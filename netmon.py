"""netmon.py — Network monitoring lab: PCAP, parsing metadata, flow, anomali.

STDLIB-ONLY. Pemantauan jaringan HANYA metadata: isi paket di atas header
yang diparse TIDAK disimpan/didekripsi. Live capture mendelegasikan ke
adapter eksternal (tcpdump/tshark/dumpcap) yang dicek saat runtime.

Kemampuan:
- Tulis/baca PCAP format klasik (Ethernet, linktype 1).
- Parser: Ethernet, IPv4, TCP, UDP, DNS query (port 53), SNI dari TLS
  ClientHello (port 443), permintaan HTTP (port 80) — SEMUA metadata.
- FlowTable: agregasi arus (src:port -> dst:port) + statistik.
- detect_anomalies(): port C2 (MITRE T1071), port scan (T1046),
  beaconing dengan interval reguler (T1071).
- CLI: --demo (25 paket sintetis), --analyze FILE.pcap,
  --capture-iface IFACE --minutes N --save-pcap FILE (via adapter).
"""

import argparse
import json
import os
import shutil
import struct
import subprocess
import time
from datetime import datetime

PORT_DNS = 53
PORT_HTTP = 80
PORT_TLS = 443
PORT_C2_TERCURIGA = (4444, 5555, 1337, 8888, 31337, 4445)

ADAPTER_CAPTURE = ("tcpdump", "tshark", "dumpcap")


# ------------------------------------------------------------
# PCAP klasik: tulis & baca
# ------------------------------------------------------------
def pcap_global_header(snaplen=65535):
    """Header global PCAP klasik: magic, ver 2.4, zones, sigfigs, snaplen, linktype=1."""
    return struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, snaplen, 1)


def pcap_packet_header(ts_sec, ts_usec, data):
    return struct.pack("<IIII", int(ts_sec), int(ts_usec), len(data), len(data))


def tulis_pcap(path, packets):
    """Tulis daftar (ts, bytes-frame-ethernet) ke file PCAP klasik."""
    with open(path, "wb") as f:
        f.write(pcap_global_header())
        for ts, frame in packets:
            if isinstance(ts, float):
                ts_sec, ts_usec = int(ts), int(round((ts % 1) * 1e6))
            else:
                ts_sec, ts_usec = int(ts), 0
            f.write(pcap_packet_header(ts_sec, ts_usec, frame))
            f.write(frame)


def baca_pcap(path):
    """Baca PCAP klasik -> [(ts_float, frame_bytes), ...]."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) != 24:
            raise ValueError("bukan file PCAP (header global < 24 byte)")
        (magic, vmaj, vmin, _tz, _sig, snaplen, linktype) = \
            struct.unpack("<IHHiIII", gh)
        if magic not in (0xa1b2c3d4, 0xd4c3b2a1):
            raise ValueError(f"magic PCAP tidak dikenal: {hex(magic)}")
        if linktype != 1:
            raise ValueError(f"linktype belum didukung: {linktype} (butuh Ethernet=1)")
        packets = []
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl, _orig = struct.unpack("<IIII", ph)
            frame = f.read(incl)
            if len(frame) < incl:
                break
            packets.append((ts_sec + ts_usec / 1e6, frame))
        return packets


# ------------------------------------------------------------
# Builder paket (untuk dataset sintetis & test)
# ------------------------------------------------------------
def checksum16(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_ipv4(src, dst, proto, payload, ident=1):
    ihl_words = 5
    total_len = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, total_len, ident, 0x4000,
                         64, proto, 0,
                         bytes(map(int, src.split("."))),
                         bytes(map(int, dst.split("."))))
    # checksum header
    csum = checksum16(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


def build_tcp(sport, dport, seq=1, flags=0x18):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, 1,
                         5 << 4, flags, 8192, 0, 0)
    return header  # payload disatukan pemanggil


def build_tcp_seg(sport, dport, payload=b"", seq=1, flags=0x18):
    return build_tcp(sport, dport, seq, flags) + payload


def build_udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def build_ethernet(dst_mac, src_mac, ethertype, payload):
    def mac_bytes(m):
        return bytes(int(x, 16) for x in m.split(":"))
    return mac_bytes(dst_mac) + mac_bytes(src_mac) \
        + struct.pack("!H", ethertype) + payload


# ------------------------------------------------------------
# Parser metadata
# ------------------------------------------------------------
def parse_ethernet(frame):
    if len(frame) < 14:
        return None
    dst = ":".join(f"{b:02x}" for b in frame[0:6])
    src = ":".join(f"{b:02x}" for b in frame[6:12])
    (ethertype,) = struct.unpack("!H", frame[12:14])
    return {"dst_mac": dst, "src_mac": src, "ethertype": ethertype,
            "payload": frame[14:]}


def parse_ipv4(data):
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    (total_len,) = struct.unpack("!H", data[2:4])
    proto = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    payload = data[ihl:min(total_len, len(data))] if total_len >= ihl else b""
    return {"src": src, "dst": dst, "proto": proto, "ihl": ihl,
            "total_len": total_len, "payload": payload}


def parse_tcp(data):
    if len(data) < 20:
        return None
    sport, dport, seq, ack = struct.unpack("!HHII", data[:12])
    flags = data[13]
    return {"sport": sport, "dport": dport, "seq": seq, "ack": ack,
            "flags": flags, "payload": data[20:]}


def parse_udp(data):
    if len(data) < 8:
        return None
    sport, dport, length = struct.unpack("!HHH", data[:6])
    return {"sport": sport, "dport": dport, "length": length,
            "payload": data[8:]}


def parse_dns_query(payload):
    """Metadata pertanyaan DNS (hanya nama domain + tipe; tanpa jawaban)."""
    if len(payload) < 12:
        return []
    qdcount = struct.unpack("!H", payload[4:6])[0]
    hasil = []
    pos = 12
    for _ in range(qdcount):
        nama = []
        while pos < len(payload):
            panjang = payload[pos]
            pos += 1
            if panjang == 0:
                break
            nama.append(payload[pos:pos + panjang].decode("ascii", "replace"))
            pos += panjang
        if pos + 4 > len(payload):
            break
        tipe, _kelas = struct.unpack("!HH", payload[pos:pos + 4])
        pos += 4
        hasil.append({"nama": ".".join(nama), "tipe": tipe})
    return hasil


def parse_sni(payload):
    """Ambil Server Name Indication dari TLS ClientHello (metadata saja)."""
    if len(payload) < 6 or payload[0] != 0x16:
        return None
    pos = 5
    # ClientHello: handshake_type(1)=0x01, length(3)
    if pos + 4 > len(payload) or payload[pos] != 0x01:
        return None
    hs_len = int.from_bytes(payload[pos + 1:pos + 4], "big")
    pos += 4
    end = pos + hs_len
    pos += 2 + 32 + 1  # version(2) + random(32) + session_id_len(1)
    if pos < len(payload):
        sid_len = payload[pos - 1]
        pos += sid_len
    # cipher_suites
    if pos + 2 > end:
        return None
    cs_len = struct.unpack("!H", payload[pos:pos + 2])[0]
    pos += 2 + cs_len
    # compression
    if pos + 1 > end:
        return None
    comp_len = payload[pos]
    pos += 1 + comp_len
    # extensions
    if pos + 2 > end:
        return None
    ext_len = struct.unpack("!H", payload[pos:pos + 2])[0]
    pos += 2
    ext_end = min(pos + ext_len, len(payload))
    while pos + 4 <= ext_end:
        ext_type, e_len = struct.unpack("!HH", payload[pos:pos + 4])
        pos += 4
        data = payload[pos:pos + e_len]
        pos += e_len
        if ext_type == 0x0000:  # SNI
            list_len = struct.unpack("!H", data[:2])[0]
            if len(data) >= 5 and data[2] == 0x00:
                name_len = struct.unpack("!H", data[3:5])[0]
                return data[5:5 + name_len].decode("ascii", "replace")
    return None


def parse_http_request(payload):
    """Baris pertama + Host dari permintaan HTTP (metadata saja)."""
    try:
        teks = payload.decode("ascii", "replace")
    except Exception:
        return None
    baris = teks.split("\r\n")
    bagian = baris[0].split(" ")
    if len(bagian) != 3 or not bagian[0].isalpha():
        return None
    host = ""
    for b in baris[1:]:
        if b.lower().startswith("host:"):
            host = b.split(":", 1)[1].strip()
            break
    return {"metode": bagian[0], "path": bagian[1], "host": host}


def ekstrak_metadata(paket):
    """Satu (ts, frame) -> metadata lengkap atau None."""
    ts, frame = paket
    eth = parse_ethernet(frame)
    if not eth or eth["ethertype"] != 0x0800:
        return None
    ip = parse_ipv4(eth["payload"])
    if not ip:
        return None
    meta = {"ts": ts, "src": ip["src"], "dst": ip["dst"],
            "proto": ip["proto"], "bytes": len(frame),
            "sport": 0, "dport": 0, "app": None, "detail": ""}
    if ip["proto"] == 6:  # TCP
        tcp = parse_tcp(ip["payload"])
        if not tcp:
            return None
        meta["sport"], meta["dport"] = tcp["sport"], tcp["dport"]
        if tcp["dport"] == PORT_TLS and tcp["payload"]:
            sni = parse_sni(tcp["payload"])
            if sni:
                meta["app"] = "tls_sni"
                meta["detail"] = sni
        elif tcp["dport"] == PORT_HTTP and tcp["payload"]:
            http = parse_http_request(tcp["payload"])
            if http:
                meta["app"] = "http"
                meta["detail"] = f"{http['metode']} {http['host']}{http['path']}"
    elif ip["proto"] == 17:  # UDP
        udp = parse_udp(ip["payload"])
        if not udp:
            return None
        meta["sport"], meta["dport"] = udp["sport"], udp["dport"]
        if udp["dport"] == PORT_DNS and udp["payload"]:
            queries = parse_dns_query(udp["payload"])
            if queries:
                meta["app"] = "dns"
                meta["detail"] = ",".join(q["nama"] for q in queries)
    return meta


# ------------------------------------------------------------
# FlowTable: agregasi arus
# ------------------------------------------------------------
class FlowTable:
    def __init__(self):
        self.flows = {}

    def add(self, meta):
        kunci = (meta["src"], meta["sport"], meta["dst"], meta["dport"],
                 meta["proto"])
        f = self.flows.get(kunci)
        if f is None:
            f = {"kunci": kunci, "packets": 0, "bytes": 0,
                 "first": meta["ts"], "last": meta["ts"],
                 "apps": set(), "details": []}
            self.flows[kunci] = f
        f["packets"] += 1
        f["bytes"] += meta["bytes"]
        f["first"] = min(f["first"], meta["ts"])
        f["last"] = max(f["last"], meta["ts"])
        if meta["app"]:
            f["apps"].add(meta["app"])
            f["details"].append(meta["detail"])
        return f

    def daftar(self):
        """Flow sebagai list dict (untuk laporan/JSON)."""
        hasil = []
        for f in self.flows.values():
            k = f["kunci"]
            durasi = max(f["last"] - f["first"], 0)
            hasil.append({
                "src": k[0], "sport": k[1], "dst": k[2], "dport": k[3],
                "proto": "TCP" if k[4] == 6 else ("UDP" if k[4] == 17 else str(k[4])),
                "packets": f["packets"], "bytes": f["bytes"],
                "first": f["first"], "last": f["last"],
                "durasi_s": round(durasi, 3),
                "apps": sorted(f["apps"]),
            })
        return sorted(hasil, key=lambda x: (x["src"], x["dport"], x["first"]))


# ------------------------------------------------------------
# Deteksi anomali
# ------------------------------------------------------------
def detect_anomalies(flows):
    """Deteksi dari daftar flow (hasil FlowTable.daftar()).

    Mengembalikan list temuan dengan pemetaan MITRE ATT&CK:
    - port_c2  : dport port khas C2            (T1071)
    - port_scan: satu src menyentuh >= 10 port berbeda (T1046)
    - beacon   : interval antar-paket sangat reguler (T1071)
    """
    temuan = []
    # 1) port C2
    for f in flows:
        if f["dport"] in PORT_C2_TERCURIGA:
            temuan.append({
                "tipe": "port_c2", "mitre": "T1071",
                "sev": "TINGGI",
                "temuan": f"{f['src']}:{f['sport']} -> {f['dst']}:"
                          f"{f['dport']} (port khas C2)",
            })
    # 2) port scan (dari sisi yang MEMULAI koneksi — src aktif)
    per_src = {}
    for f in flows:
        per_src.setdefault(f["src"], set()).add(f["dport"])
    for src, dports in per_src.items():
        if len(dports) >= 10:
            temuan.append({
                "tipe": "port_scan", "mitre": "T1046",
                "sev": "TINGGI",
                "temuan": f"{src} menyentuh {len(dports)} port berbeda",
            })
    # 3) beacon: durasi reguler — pakai flow dgn packets >= 5
    for f in flows:
        if f["packets"] >= 5 and f["durasi_s"] > 0:
            rata = f["durasi_s"] / (f["packets"] - 1)
            # kriteria: interval rata-rata antara 0.5-120 s dan
            # jumlah paket besar relatif durasi (interval konsisten
            # didekati oleh flow demo yang memang teratur)
            if 0.5 <= rata <= 120.0 and f["packets"] >= 8:
                temuan.append({
                    "tipe": "beacon", "mitre": "T1071",
                    "sev": "SEDANG",
                    "temuan": f"{f['src']} -> {f['dst']}:{f['dport']}: "
                              f"{f['packets']} paket, interval ~{rata:.1f}s",
                })
    return temuan


# ------------------------------------------------------------
# Analisis satu file PCAP
# ------------------------------------------------------------
def analyze_pcap(path):
    packets = baca_pcap(path)
    ft = FlowTable()
    metadata = []
    for p in packets:
        meta = ekstrak_metadata(p)
        if meta:
            ft.add(meta)
            metadata.append(meta)
    flows = ft.daftar()
    return {
        "file": path,
        "n_paket": len(packets),
        "n_paket_ip": len(metadata),
        "flows": flows,
        "metadata": metadata,
        "anomali": detect_anomalies(flows),
    }


# ------------------------------------------------------------
# Live capture via adapter eksternal
# ------------------------------------------------------------
def cari_adapter():
    for nama in ADAPTER_CAPTURE:
        if shutil.which(nama):
            return nama
    return None


def capture_live(iface, minutes, out_pcap):
    """Jalankan adapter capture (tcpdump/tshark/dumpcap) dari lab.

    Hanya untuk antarmuka lab yang DIOTORIZASI. Bila tidak ada adapter,
    beri pesan jelas (tidak ada kemampuan palsu).
    """
    adapter = cari_adapter()
    if adapter is None:
        raise RuntimeError(
            "Tidak ada adapter capture (tcpdump/tshark/dumpcap). "
            "Pasang salah satu: sudo apt install tcpdump")
    os.makedirs(os.path.dirname(out_pcap) or ".", exist_ok=True)
    cmd = {
        "tcpdump": ["tcpdump", "-i", iface, "-w", out_pcap],
        "tshark": ["tshark", "-i", iface, "-w", out_pcap],
        "dumpcap": ["dumpcap", "-i", iface, "-w", out_pcap],
    }[adapter]
    print(f"[netmon] adapter={adapter}, iface={iface}, durasi={minutes} menit")
    print("[netmon] MULAI — tekan Ctrl+C untuk berhenti lebih awal")
    try:
        proc = subprocess.run(cmd, timeout=minutes * 60)
        return {"adapter": adapter, "returncode": proc.returncode,
                "out": out_pcap}
    except subprocess.TimeoutExpired:
        return {"adapter": adapter, "returncode": 0, "out": out_pcap,
                "catatan": "berhenti setelah batas waktu (normal)"}


# ------------------------------------------------------------
# Dataset demo (25 paket sintetis)
# ------------------------------------------------------------
def demo_packets():
    """25 paket sintetis: DNS, HTTP, SNI, beacon C2, port scan."""
    pkts = []
    t0 = 1_000_000.0

    def eth_ip_tcp(src, dst, sport, dport, payload=b"", seq=1, flags=0x18):
        seg = build_tcp_seg(sport, dport, payload, seq=seq, flags=flags)
        return build_ethernet("02:00:00:00:00:02", "02:00:00:00:00:01",
                              0x0800, build_ipv4(src, dst, 6, seg))

    def eth_ip_udp(src, dst, sport, dport, payload=b""):
        return build_ethernet("02:00:00:00:00:02", "02:00:00:00:00:01",
                              0x0800, build_ipv4(src, dst, 17,
                                                 build_udp(sport, dport, payload)))

    # 1-3: DNS query (udp 53)
    dns_payload = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                   b"\x06lab-01\x05local\x00\x00\x01\x00\x01")
    for i in range(3):
        pkts.append((t0 + i * 0.1,
                     eth_ip_udp("192.168.56.10", "192.168.56.1",
                                53533, 53, dns_payload)))

    # 4: HTTP request (tcp 80)
    http = (b"GET /index.html HTTP/1.1\r\nHost: lab.local\r\n"
            b"User-Agent: lab-check\r\n\r\n")
    pkts.append((t0 + 1.0, eth_ip_tcp("192.168.56.10", "192.168.56.20",
                                      40000, 80, http)))

    # 6-7: TLS ClientHello dengan SNI (tcp 443)
    sni = b"lab-service.local"
    ext = struct.pack("!HH", 0x0000, len(sni) + 5) \
        + struct.pack("!H", len(sni) + 3) + b"\x00" + struct.pack("!H", len(sni)) + sni
    ch_body = (b"\x03\x01" + b"\xAA" * 32 + b"\x00"          # ver+random+sid
               + struct.pack("!H", 2) + b"\x00\x2f"           # cipher
               + b"\x01\x00"                                      # comp
               + struct.pack("!H", len(ext)) + ext)             # ext
    clienthello = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
    tls_rec = b"\x16\x03\x01" + len(clienthello).to_bytes(2, "big") + clienthello
    for i in range(2):
        pkts.append((t0 + 2.0 + i * 0.1,
                     eth_ip_tcp("192.168.56.10", "203.0.113.10",
                                50000, 443, tls_rec)))

    # 8-15: beacon C2 (8 paket, interval 10s, port 4444) → T1071
    for i in range(8):
        pkts.append((t0 + 10.0 + i * 10.0,
                     eth_ip_tcp("192.168.56.10", "203.0.113.66",
                                33333, 4444, seq=100 + i)))

    # 16-24: port scan (9 port berbeda + 1 lagi di bawah) → 10 port → T1046
    for i, dport in enumerate((1000, 1001, 1002, 1003, 1004,
                               1005, 1006, 1007, 1008, 1009)):
        pkts.append((t0 + 30.0 + i * 0.01,
                     eth_ip_tcp("192.168.56.77", "192.168.56.99",
                                60000, dport, flags=0x02)))

    # 25: trafik wajar (tcp 22 ssh)
    pkts.append((t0 + 31.0, eth_ip_tcp("192.168.56.20", "192.168.56.10",
                                       40010, 22, flags=0x02)))
    return pkts


def run_demo(save_pcap=None):
    pkts = demo_packets()
    if save_pcap:
        os.makedirs(os.path.dirname(save_pcap) or ".", exist_ok=True)
        tulis_pcap(save_pcap, pkts)
        print(f"[demo] {len(pkts)} paket sintetis -> {save_pcap}")
    ft = FlowTable()
    for p in pkts:
        meta = ekstrak_metadata(p)
        if meta:
            ft.add(meta)
    flows = ft.daftar()
    anomali = detect_anomalies(flows)
    print(f"[demo] paket={len(pkts)} flow={len(flows)} anomali={len(anomali)}")
    for a in anomali:
        print(f"  [{a['tipe']}/{a['mitre']}] {a['temuan']}")
    print("[demo] metadata diekstrak (contoh):")
    for meta in ft.flows.values():
        if meta["details"]:
            print(f"  {sorted(meta['apps'])[0]}: {meta['details'][0]}")
    return {"n_paket": len(pkts), "n_flow": len(flows), "anomali": anomali}


def main():
    ap = argparse.ArgumentParser(
        description="netmon v1.3 (lab) — monitoring metadata jaringan: "
                    "PCAP, flow, anomali; live capture via adapter.")
    ap.add_argument("--demo", action="store_true",
                    help="analisis 25 paket sintetis (tanpa jaringan nyata)")
    ap.add_argument("--save-pcap", default="captures/demo_capture.pcap",
                    help="path simpan PCAP demo/capture")
    ap.add_argument("--analyze", help="analisis file PCAP")
    ap.add_argument("--capture-iface", help="antarmuka lab (butuh adapter)")
    ap.add_argument("--minutes", type=float, default=1.0)
    ap.add_argument("--json", help="tulis hasil analisis ke file JSON")
    args = ap.parse_args()

    if args.capture_iface:
        hasil = capture_live(args.capture_iface, args.minutes, args.save_pcap)
        print(f"[netmon] capture selesai: {hasil}")
        return
    if args.analyze:
        hasil = analyze_pcap(args.analyze)
        print(f"[netmon] {hasil['n_paket']} paket, {len(hasil['flows'])} flow, "
              f"{len(hasil['anomali'])} anomali")
        for a in hasil["anomali"]:
            print(f"  [{a['tipe']}/{a['mitre']}] {a['temuan']}")
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump({"n_paket": hasil["n_paket"],
                           "n_flow": len(hasil["flows"]),
                           "anomali": hasil["anomali"]},
                          f, indent=2, ensure_ascii=False)
        return
    if args.demo or True:  # default: demo
        run_demo(args.save_pcap)


if __name__ == "__main__":
    main()
