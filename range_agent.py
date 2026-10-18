#!/usr/bin/env python3
"""range_agent.py — Endpoint agent read-only (v3.0, STDLIB-ONLY).

Agent dijalankan DI PERANGKAT LAB YANG SUDAH DI-ENROLL (kunci
out-of-band dari `range_registry.py --enroll`). Siklus: sambung →
HELO → HEARTBEAT → POLL (ambil tugas) → jalankan → HASIL.

Whitelist tugas (READ-ONLY by design — TIDAK ada eksekusi perintah
arbitrer):
  proses       : inventori proses dari /proc
  pohon_proses : pohon proses via parent PID
  koneksi      : koneksi TCP dari /proc/net/tcp
                 (kolom 9 = INODE, bukan PID — keterbatasan mapping
                 koneksi->proses dijujuri; inode memungkinkan korelasi
                 manual via /proc/<pid>/fd)
  fim          : file-integrity monitoring direktori uji (hash
                 baseline vs kondisi kini)
  priv         : audit privilege sederhana (file SUID di path umum)
  health       : detak jantung + ringkasan sumber daya

CATATAN JUJUR: hanya Linux (/proc). Tidak ada persistensi/service/
autostart — uninstalasi = hapus file ini.
"""

import argparse
import hashlib
import json
import os
import secrets
import socket
import sys
import time

from range_registry import buat_mac

TUGAS_JENIS = ("proses", "pohon_proses", "koneksi", "fim", "priv",
               "health")


# ============================================================
# Kolektor (semua read-only)
# ============================================================
def kumpul_proses(batas=200):
    """Inventori proses ringkas dari /proc/[pid]/stat (Linux)."""
    hasil = []
    for pid in sorted(_pids())[:batas]:
        rec = _baca_stat(pid)
        if rec:
            hasil.append(rec)
    return hasil


def _pids():
    try:
        for nama in os.listdir("/proc"):
            if nama.isdigit():
                yield int(nama)
    except OSError:
        return


def _baca_stat(pid):
    """Parse /proc/<pid>/stat minim (nama, ppid, state) — parentesis
    dalam nama cmdline bisa mengacaukan split, jadi dicari hati-hati."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            stat = f.read()
    except OSError:
        return None
    buka = stat.find("(")
    tutup = stat.rfind(")")
    if buka < 0 or tutup < 0:
        return None
    nama = stat[buka + 1:tutup]
    sisa = stat[tutup + 1:].split()
    if len(sisa) < 2:
        return None
    return {"pid": pid, "nama": nama, "state": sisa[0],
            "ppid": int(sisa[1])}


def pohon_proses(batas=300):
    """Pohon proses (parent→children) dari kumpul_proses."""
    proses = kumpul_proses(batas)
    anak = {}
    for p in proses:
        anak.setdefault(p["ppid"], []).append(p["pid"])
    return {"n": len(proses), "anak_per induk": {
        str(k): v[:10] for k, v in sorted(anak.items())[:20]}}


def _hex_ke_ip(hexstr):
    """Balikan little-endian hex /proc/net/tcp ke IP:port."""
    try:
        ip_raw = bytes.fromhex(hexstr[:8])
        ip = ".".join(str(b) for b in ip_raw[::-1])
        port = int(hexstr[9:13], 16)
        return f"{ip}:{port}"
    except ValueError:
        return "?"


def kumpul_koneksi(batas=100):
    """Koneksi TCP dari /proc/net/tcp.

    Kolom 9 adalah INODE (bukan PID) — dijujuri di docstring & hasil.
    """
    hasil = []
    try:
        with open("/proc/net/tcp", encoding="utf-8") as f:
            baris = f.readlines()[1:]  # lewati header
    except OSError:
        return hasil
    for b in baris[:batas]:
        kol = b.split()
        if len(kol) < 4:
            continue
        hasil.append({
            "lokal": _hex_ke_ip(kol[1]),
            "remote": _hex_ke_ip(kol[2]),
            "state": kol[3],
            "inode": kol[9],  # INODE — bukan PID (keterbatasan dijujuri)
        })
    return hasil


def _hash_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for blok in iter(lambda: f.read(65536), b""):
                h.update(blok)
        return h.hexdigest()
    except OSError:
        return None


def kumpul_fim(cfg, jalankan_baseline=False):
    """File-integrity monitoring direktori uji.

    cfg = {"fim_dir": path, "fim_baseline": {path: sha256} | None}.
    Bila baseline None: kembalikan baseline BARU (belum ada perbandingan).
    Bila baseline ada: bandingkan → daftar berubah/baru/hilang.
    """
    direktori = cfg.get("fim_dir") or "."
    kini = {}
    try:
        for nama in sorted(os.listdir(direktori))[:500]:
            path = os.path.join(direktori, nama)
            if os.path.isfile(path):
                d = _hash_file(path)
                if d:
                    kini[path] = d
    except OSError:
        kini = {}
    baseline = cfg.get("fim_baseline")
    if jalankan_baseline or baseline is None:
        return {"baseline": kini, "n": len(kini), "berubah": [],
                "baru": [], "hilang": []}
    berubah = [p for p in baseline if p in kini
               and baseline[p] != kini[p]]
    baru = [p for p in kini if p not in baseline]
    hilang = [p for p in baseline if p not in kini]
    return {"baseline": kini, "n": len(kini), "berubah": berubah,
            "baru": baru, "hilang": hilang}


def kumpul_priv():
    """Audit privilege ringan: file SUID di path umum (read-only)."""
    kandidat = ["/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                "/usr/bin/mount", "/usr/bin/umount"]
    temuan = []
    for p in kandidat:
        try:
            mode = os.stat(p).st_mode
            if mode & 0o4000:  # setuid bit
                temuan.append(p)
        except OSError:
            continue
    return {"suid_ditemukan": temuan,
            "catatan": "hanya path umum; bukan audit privilege penuh"}


def kumpul_health():
    """Detak jantung agent + ringkasan sumber daya (read-only)."""
    return {"agent": "range-agent-v3", "ts": time.time(),
            "n_pid": len(list(_pids()))}


# ============================================================
# Eksekusi tugas (whitelist)
# ============================================================
def jalankan_tugas(jenis, cfg=None):
    """Jalankan SATU tugas dari whitelist — jenis lain ValueError."""
    cfg = cfg or {}
    if jenis not in TUGAS_JENIS:
        raise ValueError(f"jenis tugas tidak dikenal: {jenis}")
    if jenis == "proses":
        return kumpul_proses()
    if jenis == "pohon_proses":
        return pohon_proses()
    if jenis == "koneksi":
        return kumpul_koneksi()
    if jenis == "fim":
        return kumpul_fim(cfg)
    if jenis == "priv":
        return kumpul_priv()
    return kumpul_health()


def satu_siklus(sock, dev_id, kunci, cfg, interval=5.0):
    """Satu putaran: HEARTBEAT → POLL → (tugas?) → HASIL."""
    mac_kirim(sock, dev_id, kunci, "HEARTBEAT", {"status": "hidup"})
    resp = mac_kirim(sock, dev_id, kunci, "POLL", {})
    if not resp.get("ok"):
        return resp
    tugas = (resp.get("data") or {}).get("tugas")
    if not tugas:
        return {"ok": True, "data": {"tugas": None}}
    jenis = tugas.get("jenis")
    print(f"[agent] tugas diterima: {jenis}")
    try:
        data = jalankan_tugas(jenis, cfg)
        if jenis == "fim" and cfg.get("fim_baseline") is None:
            # baseline pertama disimpan untuk pembandingan berikutnya
            cfg["fim_baseline"] = data.get("baseline")
    except ValueError as e:
        data = {"error": str(e)}
    return mac_kirim(sock, dev_id, kunci, "HASIL", {
        "tugas_id": tugas.get("tugas_id"), "jenis": jenis,
        "data": json.dumps(data, ensure_ascii=False)[:4000]})


def mac_kirim(sock, dev_id, kunci, cmd, payload):
    """Buat pesan ber-MAC + nonce + ts; kirim; baca satu respons JSON."""
    nonce = secrets.token_hex(16)
    ts = time.time()
    mac = buat_mac(kunci, dev_id, nonce, ts, cmd, payload)
    pesan = {"jenis": "device", "id": dev_id, "nonce": nonce,
             "ts": ts, "cmd": cmd, "payload": payload, "mac": mac}
    sock.sendall(json.dumps(pesan).encode() + b"\n")
    baris = b""
    while not baris.endswith(b"\n"):
        blok = sock.recv(65536)
        if not blok:
            raise ConnectionError("controller menutup koneksi")
        baris += blok
    return json.loads(baris)


def main():
    ap = argparse.ArgumentParser(
        description="range_agent v3.0 — endpoint agent read-only "
                    "(proses/koneksi/FIM/priv/health via controller).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--id", required=True, help="device id (dev-XXXX)")
    ap.add_argument("--kunci", required=True,
                    help="kunci perangkat dari enrollment (out-of-band)")
    ap.add_argument("--fim-dir", default=".",
                    help="direktori pemantauan integritas file (test dir)")
    ap.add_argument("--interval", type=float, default=5.0)
    args = ap.parse_args()

    cfg = {"fim_dir": args.fim_dir, "fim_baseline": None}
    print(f"[agent] menyambung ke {args.host}:{args.port} "
          f"sebagai {args.id}")
    while True:
        try:
            sock = socket.create_connection((args.host, args.port),
                                            timeout=10)
            # HELLO sekali per koneksi
            resp = mac_kirim(sock, args.id, args.kunci, "HELLO", {})
            if resp.get("ok"):
                print(f"[agent] diterima controller: "
                      f"{resp.get('data', {}).get('nama', '?')}")
            else:
                print(f"[agent] DITOLAK: {resp.get('alasan')}")
                sock.close()
                return 2
            while True:
                satu_siklus(sock, args.id, args.kunci, cfg)
                time.sleep(max(0.5, args.interval))
        except (ConnectionError, OSError) as e:
            print(f"[agent] koneksi bermasalah ({e}) — coba lagi 5s")
            time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
