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
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from datetime import datetime

PORT_DNS = 53
PORT_HTTP = 80
PORT_TLS = 443
PORT_C2_TERCURIGA = (4444, 5555, 1337, 8888, 31337, 4445)

# v2.0: port yang WAJAR untuk trafik sehari-hari — beacon ke port ini
# TIDAK ditandai (mengurangi false-positive pada polling/monitor biasa).
PORT_WAJAR = frozenset({53, 80, 123, 443, 22, 67, 68, 8080, 8443})

# v2.0: ambang heuristik DETEKSI — configurable, trade-off didokumentasikan:
# - beacon_cv_maks kecil → lebih sedikit FP, lebih banyak FN (jitter tak terdeteksi)
# - beacon_min_packets besar → lebih tahan noise, tapi beacon singkat lolos
AMBANG_DEFAULT = {
    "beacon_min_packets": 8,
    "beacon_rata_min": 0.5,
    "beacon_rata_maks": 120.0,
    "beacon_cv_maks": 0.25,
    "scan_min_port": 10,
}

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
            # v2.0 (bug hasil fuzz F1): incl raksasa -> MemoryError.
            # Batasi terhadap max(snaplen, 256 KiB) sebelum membaca.
            if incl > max(snaplen, 262144):
                raise ValueError(
                    f"record PCAP tidak wajar: incl_len={incl} > "
                    f"max(snaplen={snaplen}, 262144) — file korup?")
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
                 "ts_list": [],
                 "apps": set(), "details": []}
            self.flows[kunci] = f
        f["packets"] += 1
        f["bytes"] += meta["bytes"]
        f["ts_list"].append(meta["ts"])  # v2.0: untuk cv_interval (anti-FP)
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
                "cv_interval": _cv_interval(f["ts_list"]),
                "apps": sorted(f["apps"]),
            })
        return sorted(hasil, key=lambda x: (x["src"], x["dport"], x["first"]))


# ------------------------------------------------------------
# Deteksi anomali (v2.0: explainable — fakta vs kesimpulan)
# ------------------------------------------------------------
def _cv_interval(ts_list):
    """Koefisien variasi (cv) interval antar-paket.

    cv kecil -> interval sangat teratur (indikasi beacon); cv besar ->
    trafik wajar. None bila tak bisa dihitung (paket < 3 / tanpa interval).
    """
    if not ts_list or len(ts_list) < 3:
        return None
    urut = sorted(ts_list)
    interval = [b - a for a, b in zip(urut, urut[1:])]
    rata = sum(interval) / len(interval)
    if rata <= 0:
        return None
    ragam = sum((x - rata) ** 2 for x in interval) / len(interval)
    return (ragam ** 0.5) / rata


def detect_anomalies(flows, ambang=None):
    """Deteksi dari daftar flow (hasil FlowTable.daftar()) — v2.0 explainable.

    Setiap temuan memuat: tipe, mitre, sev, SKOR keyakinan (0..1), dan
    BUKTI eksplisit. Skor < 1.0 = heuristik, BUKAN kepastian: port
    mencurigakan TIDAK membuktikan aktivitas jahat.

    - port_c2  : dport port khas C2                       (T1071, SEDANG)
    - port_scan: satu src menyentuh >= scan_min_port port (T1046, TINGGI)
    - beacon   : interval TERATUR (cv <= ambang) + konteks port
                 TIDAK wajar                              (T1071, SEDANG)

    ambang: dict untuk override AMBANG_DEFAULT (trade-off didokumentasikan).
    """
    a = dict(AMBANG_DEFAULT)
    if ambang:
        a.update(ambang)
    temuan = []
    # 1) port C2 — heuristik lemah (port saja), skor rendah
    for f in flows:
        if f["dport"] in PORT_C2_TERCURIGA:
            temuan.append({
                "tipe": "port_c2", "mitre": "T1071", "sev": "SEDANG",
                "skor": 0.6,
                "bukti": [f"dport={f['dport']} termasuk daftar port khas C2",
                          "port saja TIDAK membuktikan aktivitas jahat"],
                "temuan": f"{f['src']}:{f['sport']} -> {f['dst']}:"
                          f"{f['dport']} (port khas C2)",
            })
    # 2) port scan (dari sisi yang MEMULAI koneksi — src aktif)
    per_src = {}
    for f in flows:
        per_src.setdefault(f["src"], set()).add(f["dport"])
    for src, dports in per_src.items():
        if len(dports) >= a["scan_min_port"]:
            temuan.append({
                "tipe": "port_scan", "mitre": "T1046", "sev": "TINGGI",
                "skor": 0.9,
                "bukti": [f"{src} menyentuh {len(dports)} port berbeda",
                          f"port tersentuh: {sorted(dports)[:15]}"],
                "temuan": f"{src} menyentuh {len(dports)} port berbeda",
            })
    # 3) beacon: interval teratur (cv) + konteks port — v2.0 anti-FP
    for f in flows:
        if f["packets"] < a["beacon_min_packets"] or f["durasi_s"] <= 0:
            continue
        rata = f["durasi_s"] / (f["packets"] - 1)
        if not (a["beacon_rata_min"] <= rata <= a["beacon_rata_maks"]):
            continue
        cv = f.get("cv_interval")
        if cv is None or cv > a["beacon_cv_maks"]:
            continue  # interval tidak teratur -> bukan indikasi beacon kuat
        konteks = (f["dport"] in PORT_C2_TERCURIGA
                   or f["dport"] not in PORT_WAJAR)
        if not konteks:
            continue  # polling/monitor ke port wajar -> bukan temuan
        temuan.append({
            "tipe": "beacon", "mitre": "T1071", "sev": "SEDANG",
            "skor": 0.75,
            "bukti": [f"{f['packets']} paket, interval rata-rata "
                      f"{rata:.2f}s, cv={cv:.3f} (teratur)",
                      f"dport={f['dport']} bukan port wajar sehari-hari"],
            "temuan": f"{f['src']} -> {f['dst']}:{f['dport']}: "
                      f"{f['packets']} paket, interval ~{rata:.1f}s",
        })
    return temuan


# ------------------------------------------------------------
# Evaluasi detektor dengan fixture BERLABEL (ground truth sintetis)
# ------------------------------------------------------------
def _meta_flow(src="192.168.56.10", dst="203.0.113.66", sport=33333,
               dport=4444, packets=10, interval=10.0, proto="TCP"):
    """Flow sintetis berinterval teratur (untuk evaluasi berlabel)."""
    ts_list = [1000.0 + i * interval for i in range(packets)]
    return {
        "src": src, "sport": sport, "dst": dst, "dport": dport,
        "proto": proto, "packets": packets, "bytes": packets * 200,
        "first": ts_list[0], "last": ts_list[-1],
        "durasi_s": round((packets - 1) * interval, 3),
        "cv_interval": _cv_interval(ts_list), "apps": [],
    }


def _meta_jitter(src="192.168.56.10", dst="203.0.113.99", sport=33334,
                 dport=9999, packets=11):
    """Flow beacon dengan jitter tinggi (interval 20/40s bergantian)."""
    ts_list = [1000.0]
    for i in range(packets - 1):
        ts_list.append(ts_list[-1] + (20.0 if i % 2 == 0 else 40.0))
    return {
        "src": src, "sport": sport, "dst": dst, "dport": dport,
        "proto": "TCP", "packets": packets, "bytes": packets * 200,
        "first": ts_list[0], "last": ts_list[-1],
        "durasi_s": round(ts_list[-1] - ts_list[0], 3),
        "cv_interval": _cv_interval(ts_list), "apps": [],
    }


def _meta_scan(src="192.168.56.77", dst="192.168.56.99", n_port=20):
    """Sekumpulan flow scan: satu src menyentuh banyak port berbeda."""
    return [{
        "src": src, "sport": 60000, "dst": dst, "dport": 1000 + i,
        "proto": "TCP", "packets": 1, "bytes": 60,
        "first": 1000.0 + i * 0.01, "last": 1000.0 + i * 0.01,
        "durasi_s": 0.0, "cv_interval": None, "apps": [],
    } for i in range(n_port)]


def evaluasi_detektor():
    """Evaluasi PRECISION/RECALL/FPR/FNR terhadap fixture berlabel.

    CATATAN JUJUR: fixture 100% sintetis buatan sendiri — angka ini
    mengukur perilaku detektor pada data uji ini, BUKAN akurasi dunia nyata.
    """
    fixtures = [
        # ---- BENIGN (harusnya TIDAK ada temuan) ----
        {"label": "benign_http_polling", "benign": True,
         "flows": [_meta_flow(dport=443, packets=9, interval=1.0)],
         "diharapkan": []},
        {"label": "benign_dns", "benign": True,
         "flows": [_meta_flow(dport=53, packets=12, interval=5.0,
                              proto="UDP")],
         "diharapkan": []},
        {"label": "benign_ntp", "benign": True,
         "flows": [_meta_flow(dport=123, packets=10, interval=64.0,
                              proto="UDP")],
         "diharapkan": []},
        {"label": "benign_browsing", "benign": True,
         "flows": [_meta_flow(dport=80, packets=4, interval=0.3),
                   _meta_flow(dport=443, packets=5, interval=7.0,
                              dst="203.0.113.7")],
         "diharapkan": []},
        {"label": "benign_ssh", "benign": True,
         "flows": [_meta_flow(dport=22, packets=6, interval=45.0,
                              dst="192.168.56.20")],
         "diharapkan": []},
        # ---- ANOMALI (harusnya ada temuan) ----
        {"label": "anom_beacon_c2", "benign": False,
         "flows": [_meta_flow(dport=4444, packets=10, interval=10.0)],
         "diharapkan": ["beacon", "port_c2"]},
        {"label": "anom_beacon_highport", "benign": False,
         "flows": [_meta_flow(dport=5555, packets=10, interval=30.0)],
         "diharapkan": ["beacon", "port_c2"]},
        {"label": "anom_port_scan", "benign": False,
         "flows": _meta_scan(),
         "diharapkan": ["port_scan"]},
        {"label": "anom_beacon_jitter", "benign": False,
         "flows": [_meta_jitter()],
         "diharapkan": ["beacon"]},
    ]
    tp = fp = fn = tn = 0
    rincian = []
    for fx in fixtures:
        temuan = detect_anomalies(fx["flows"])
        tipe = sorted({t["tipe"] for t in temuan})
        if fx["benign"]:
            if temuan:
                fp += 1
                hasil = "FP"
            else:
                tn += 1
                hasil = "TN"
        else:
            if set(fx["diharapkan"]) & set(tipe):
                tp += 1
                hasil = "TP"
            else:
                fn += 1
                hasil = "FN"
        rincian.append({"label": fx["label"], "hasil": hasil,
                        "temuan": tipe})
    presisi = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (tp + fn) if (tp + fn) else 0.0
    return {
        "n_fixture": len(fixtures),
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": round(presisi, 3),
        "recall": round(recall, 3),
        "fpr": round(fpr, 3), "fnr": round(fnr, 3),
        "rincian": rincian,
        "catatan": [
            "fixture sintetis berlabel buatan sendiri — BUKAN trafik nyata",
            "FN diketahui & diakui: beacon jitter tinggi (cv di atas "
            "ambang) belum terdeteksi — jangan klaim recall 1.0",
            "port mencurigakan hanyalah heuristik, bukan bukti serangan",
        ],
    }



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
        "kualitas": ukur_kualitas(packets),          # v3.0
        "korelasi_dns": korelasi_dns(metadata),      # v3.0
    }


# ------------------------------------------------------------
# v3.0 (R3) — inspeksi sertifikat, kualitas capture, korelasi DNS
# ------------------------------------------------------------
def inspeksi_sertifikat(path):
    """Fingerprint SHA-256 DER + metadata sertifikat PEM (metadata saja).

    Metadata (subject/issuer/masa berlaku) via `ssl._ssl._test_decode_cert`
    — API internal stdlib, di-GUARD: bila dekode gagal, laporkan `error`
    secara jujur (fingerprint tetap dihitung dari DER).
    """
    import base64
    import ssl
    hasil = {"file": path, "fingerprint_sha256": None,
             "subject": None, "issuer": None,
             "not_before": None, "not_after": None,
             "berlaku": None, "error": None}
    try:
        with open(path, "rb") as f:
            isi = f.read()
    except OSError as e:
        hasil["error"] = f"tidak bisa dibaca: {e}"
        return hasil
    # ambil blok PEM pertama
    if b"-----BEGIN CERTIFICATE-----" not in isi:
        hasil["error"] = "bukan file PEM (tidak ada blok CERTIFICATE)"
        return hasil
    blok = isi.split(b"-----BEGIN CERTIFICATE-----", 1)[1] \
              .split(b"-----END CERTIFICATE-----", 1)[0]
    try:
        der = base64.b64decode("".join(
            blok.decode(errors="replace").split()))
    except ValueError:
        hasil["error"] = "base64 PEM tidak valid"
        return hasil
    hasil["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
    # metadata via API internal stdlib (guarded, fallback jujur)
    try:
        meta = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        hasil["subject"] = meta.get("subject")
        hasil["issuer"] = meta.get("issuer")
        hasil["not_before"] = meta.get("notBefore")
        hasil["not_after"] = meta.get("notAfter")
        hasil["berlaku"] = not meta.get("subject") is None
    except Exception as e:  # pragma: no cover - tergantung stdlib
        hasil["error"] = f"metadata tidak terdekode: {e}"
    return hasil


def ukur_kualitas(packets, ambang_gap_s=2.0):
    """Ukur kualitas capture dari daftar (ts, frame).

    Menghitung: duplikat (frame identik berdekatan waktu), reorder
    (timestamp mundur), gap (lonjakan waktu). `estimasi_drop` adalah
    HEURISTIK dari jumlah gap — CATATAN JUJUR: ini BUKAN pengukuran
    packet-loss nyata (butuh tap independen / sekuensi transport).
    """
    n = len(packets)
    duplikat = []
    reorder = 0
    gaps = []
    terakhir = {}
    sebelumnya_ts = None
    for i, (ts, frame) in enumerate(packets):
        kunci = hashlib.sha256(frame).hexdigest()[:16]
        if kunci in terakhir:
            j, t_lama = terakhir[kunci]
            if abs(ts - t_lama) < 1.0:
                duplikat.append({"indeks": i, "duplikat_dari": j})
        terakhir[kunci] = (i, ts)
        if sebelumnya_ts is not None and ts < sebelumnya_ts:
            reorder += 1
        elif sebelumnya_ts is not None and ts - sebelumnya_ts >= ambang_gap_s:
            gaps.append({"indeks": i, "selisih_s": round(
                ts - sebelumnya_ts, 3)})
        sebelumnya_ts = ts
    return {
        "n_paket": n,
        "n_duplikat": len(duplikat),
        "duplikat": duplikat[:20],
        "n_reorder": reorder,
        "gaps": gaps[:20],
        "n_gap": len(gaps),
        "durasi_s": round(packets[-1][0] - packets[0][0], 3) if n >= 2
        else 0.0,
        "estimasi_drop": len(gaps),
        "catatan": ("estimasi_drop adalah heuristik dari gap waktu — "
                    "BUKAN pengukuran packet-loss nyata (butuh tap "
                    "independen / sekuensi transport)"),
    }


def korelasi_dns(metadata, jendela_s=60.0):
    """Korelasi kueri DNS dengan SNI/HTTP-Host berikutnya.

    Per koneksi aplikasi (tls_sni/http), dicari kueri DNS yang:
    - cocok nama (match), atau
    - nama DNS adalah subdomain-nya, atau
    - dalam jendela waktu, dan
    - apakah dari src yang sama.
    Metadata saja — isi terenkripsi tidak disentuh.
    """
    dns = [{"ts": m["ts"], "src": m["src"], "nama": n}
           for m in metadata if m.get("app") == "dns"
           for n in str(m.get("detail", "")).split(",") if n]
    app = [{"ts": m["ts"], "src": m["src"], "app": m["app"],
            "host": str(m.get("detail", "")).split(" ")[-1]}
           for m in metadata if m.get("app") in ("tls_sni", "http")]
    pasangan = []
    tanpa_dns = []
    for a in app:
        kandidat = None
        for d in dns:
            if d["ts"] > a["ts"] or a["ts"] - d["ts"] > jendela_s:
                continue
            nama = d["nama"].rstrip(".")
            host = a["host"].rstrip(".")
            if host == nama:
                kandidat = {"jenis": "match", "dns": d, }
                break
            if host.endswith("." + nama):
                kandidat = {"jenis": "subdomain", "dns": d}
                break
            kandidat = kandidat or {"jenis": "jendela", "dns": d}
        if kandidat:
            kandidat["src_sama"] = kandidat["dns"]["src"] == a["src"]
            kandidat["app"] = a
            pasangan.append(kandidat)
        else:
            tanpa_dns.append(a)
    return {
        "n_dns": len(dns),
        "n_app": len(app),
        "n_pasangan": len(pasangan),
        "pasangan": pasangan[:50],
        "n_tanpa_dns": len(tanpa_dns),
        "tanpa_dns": tanpa_dns[:50],
        "catatan": ("korelasi metadata DNS↔SNI/Host dalam jendela "
                    f"±{jendela_s:.0f}s — bukan bukti sebab-akibat"),
    }


# ------------------------------------------------------------
# Live capture via adapter eksternal
# ------------------------------------------------------------
def cari_adapter():
    for nama in ADAPTER_CAPTURE:
        if shutil.which(nama):
            return nama
    return None


def capture_live(iface, minutes, out_pcap, setuju_scope=False):
    """Jalankan adapter capture (tcpdump/tshark/dumpcap) dari lab.

    v2.0: capture live kini WAJIB dengan konfirmasi scope eksplisit
    (setuju_scope=True / CLI --confirm-scope) — tanpa itu PermissionError.
    Ini menjaga konsistensi dengan redsim yang scope-enforced: jangan
    menangkap trafik di luar lab yang diotorisasi.
    Hanya untuk antarmuka lab yang DIOTORIZASI. Bila tidak ada adapter,
    beri pesan jelas (tidak ada kemampuan palsu).
    """
    if not setuju_scope:
        raise PermissionError(
            "capture live DITOLAK tanpa --confirm-scope: konfirmasikan "
            "bahwa antarmuka adalah lab yang diotorisasi (lihat lab_scope.json)")
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
        description="netmon v3.0 (lab) — monitoring metadata jaringan: "
                    "PCAP, flow, anomali explainable, inspeksi sertifikat, "
                    "kualitas capture, korelasi DNS; live capture via "
                    "adapter (butuh --confirm-scope).")
    ap.add_argument("--demo", action="store_true",
                    help="analisis 25 paket sintetis (tanpa jaringan nyata)")
    ap.add_argument("--save-pcap", default="captures/demo_capture.pcap",
                    help="path simpan PCAP demo/capture")
    ap.add_argument("--analyze", help="analisis file PCAP")
    ap.add_argument("--inspeksi-sert", metavar="PEM",
                    help="v3.0: fingerprint SHA-256 + metadata sertifikat")
    ap.add_argument("--capture-iface", help="antarmuka lab (butuh adapter)")
    ap.add_argument("--minutes", type=float, default=1.0)
    ap.add_argument("--json", help="tulis hasil analisis ke file JSON")
    ap.add_argument("--evaluasi", action="store_true",
                    help="evaluasi detektor pada fixture berlabel "
                         "(precision/recall/FPR/FNR — sintetis)")
    ap.add_argument("--confirm-scope", action="store_true",
                    help="konfirmasi eksplisit bahwa antarmuka adalah lab "
                         "yang diotorisasi (WAJIB utk capture live)")
    args = ap.parse_args()

    if args.inspeksi_sert:
        hasil = inspeksi_sertifikat(args.inspeksi_sert)
        print(f"[sert] file          : {hasil['file']}")
        print(f"[sert] fingerprint   : {hasil['fingerprint_sha256']}")
        print(f"[sert] subject/issuer: {hasil['subject']} / "
              f"{hasil['issuer']}")
        print(f"[sert] berlaku       : {hasil['not_before']} -> "
              f"{hasil['not_after']}")
        if hasil["error"]:
            print(f"[sert] catatan jujur : {hasil['error']}")
        return 0

    if args.evaluasi:
        hasil = evaluasi_detektor()
        print(f"[evaluasi] fixture={hasil['n_fixture']} "
              f"TP={hasil['TP']} FP={hasil['FP']} "
              f"FN={hasil['FN']} TN={hasil['TN']}")
        print(f"[evaluasi] precision={hasil['precision']} "
              f"recall={hasil['recall']} "
              f"FPR={hasil['fpr']} FNR={hasil['fnr']}")
        for r in hasil["rincian"]:
            print(f"  {r['hasil']:<3} {r['label']:<22} {r['temuan']}")
        for c in hasil["catatan"]:
            print(f"  catatan: {c}")
        return 0

    if args.capture_iface:
        try:
            hasil = capture_live(args.capture_iface, args.minutes,
                                 args.save_pcap,
                                 setuju_scope=args.confirm_scope)
        except PermissionError as e:
            print(f"[netmon] {e}")
            return 3  # ditolak scope — exit code konsisten
        except RuntimeError as e:
            print(f"[netmon] {e}")
            return 4  # adapter tidak ada
        print(f"[netmon] capture selesai: {hasil}")
        return 0
    if args.analyze:
        try:
            hasil = analyze_pcap(args.analyze)
        except (ValueError, OSError) as e:
            print(f"[netmon] gagal membaca PCAP: {e}")
            return 1
        print(f"[netmon] {hasil['n_paket']} paket, {len(hasil['flows'])} flow, "
              f"{len(hasil['anomali'])} anomali")
        for a in hasil["anomali"]:
            print(f"  [{a['tipe']}/{a['mitre']}/{a['sev']}] "
                  f"skor={a['skor']} {a['temuan']}")
            for b in a["bukti"]:
                print(f"      bukti: {b}")
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump({"n_paket": hasil["n_paket"],
                           "n_flow": len(hasil["flows"]),
                           "anomali": hasil["anomali"]},
                          f, indent=2, ensure_ascii=False)
        return 0
    if args.demo or True:  # default: demo
        run_demo(args.save_pcap)
    return 0


if __name__ == "__main__":
    sys.exit(main())

