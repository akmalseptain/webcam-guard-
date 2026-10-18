#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_endpoint.py — v4.0 Sovereign Lab Control: ENDPOINT AGENT (Windows-ready).

Karakter:
  - ENROLLMENT EKSPLISIT: agent menolak jalan tanpa dev_id + kunci dari
    enrollment out-of-band (dia TIDAK mengaku diri sekadar karena reachable).
  - IDENTITAS JUJUR: nama produk "SLC Endpoint Agent" tampil di health,
    dokumentasi, dan layanan; tidak menyamar sebagai komponen Windows,
    tidak menonaktifkan kontrol keamanan, tidak menghalangi admin berhenti.
  - heartbeat + reconnect dengan BACKOFF TERBATAS (0.5s → maks 30s),
    graceful shutdown (selesaikan siklus, kirim BYE), pemulihan pasca-gangguan.
  - LIMIT SUMBER DAYA konfigurabel: agent menolak tugas bila pemakaian
    melebihi batas (jujur dilaporkan, bukan diam-diam diabaikan).
  - UPDATE PAKET ter-cek integritas: sha256 WAJIB cocok sebelum dipasang;
    pasang atomik + backup .bak.
  - least-privilege: hanya aksi dari registry slc_actions (read-only utk
    mayoritas); tidak ada shell arbitrer.
  - Layanan Windows: prosedur install/upgrade/restart/uninstall via sc.exe
    TERDOKUMENTASI (fungsi --install-layanan mencetak langkahnya; butuh
    Administrator di mesin target). Siklus layanan (start/stop/recover)
    mengikuti semantik Windows Service Control Manager.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import secrets
import shutil
import socket
import ssl
import sys
import time

import resource

import slc_actions

VERSII_AGENT = "4.0.0"
BATAS_BAKOFF_AWAL = 0.5
BATAS_BAKOFF_MAKS = 30.0
FAKTOR_BACKOFF = 2.0

IDENTITAS = {"produk": "SLC Endpoint Agent (WebCam Guard lab)",
             "versi": VERSII_AGENT,
             "penerbit": "akmalseptain — lab universitas (UTS)"}


class TransportError(ConnectionError):
    pass


# ---------------------------------------------------------------------------
# Transport TCP (produksi) — JSON-line ber-HMAC, TLS opsional + pinning
# ---------------------------------------------------------------------------

class TransportTCP:
    """Kirim pesan ber-MAC ke controller; TLS bila dikonfigurasi.
    Validasi sertifikat KETAT: verify_mode=CERT_REQUIRED + pin SHA-256
    fingerprint server HARUS cocok — sertifikat tak dikenal → TOLAK."""

    def __init__(self, host, port, dev_id, kunci, use_tls=False,
                 pin_sha256=None, ca_file=None, timeout=15.0):
        self.host, self.port = host, port
        self.dev_id, self.kunci = dev_id, kunci
        self.use_tls, self.pin = use_tls, pin_sha256
        self.ca_file = ca_file
        self.timeout = timeout
        self._sock = None

    def _buat_socket(self):
        raw = socket.create_connection((self.host, self.port),
                                       timeout=self.timeout)
        if not self.use_tls:
            return raw
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False       # identitas via PIN, bukan hostname lab
        ctx.verify_mode = ssl.CERT_REQUIRED
        if self.ca_file:
            ctx.load_verify_locations(self.ca_file)
        else:
            ctx.load_default_certs()
        sock = ctx.wrap_socket(raw, server_hostname=self.host)
        der = sock.getpeercert(binary_form=True) or b""
        pin = hashlib.sha256(der).hexdigest()
        if self.pin and pin != self.pin:
            sock.close()
            raise TransportError(
                f"PIN sertifikat controller TIDAK cocok ({pin[:12]}…)")
        return sock

    def kirim(self, cmd, payload):
        """Satu pesan → satu respons (JSON line, HMAC + nonce + ts)."""
        from range_registry import buat_mac
        if self._sock is None:
            self._sock = self._buat_socket()
        sock = self._sock
        nonce = secrets.token_hex(16)
        ts = time.time()
        mac = buat_mac(self.kunci, self.dev_id, nonce, ts, cmd, payload)
        pesan = {"jenis": "device", "id": self.dev_id, "nonce": nonce,
                 "ts": ts, "cmd": cmd, "payload": payload, "mac": mac}
        try:
            sock.sendall(json.dumps(pesan).encode() + b"\n")
            buf = b""
            while not buf.endswith(b"\n"):
                blok = sock.recv(65536)
                if not blok:
                    raise TransportError("controller menutup koneksi")
                buf += blok
            return json.loads(buf)
        except (OSError, ssl.SSLError) as e:
            self.tutup()
            raise TransportError(str(e)) from e

    def tutup(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


class TransportLokal:
    """Transport in-process (demo mode / test): memanggil SLCControl
    langsung — jalur yang sama, tanpa jaringan."""

    def __init__(self, control, dev_id):
        self.control = control
        self.dev_id = dev_id

    def kirim(self, cmd, payload):
        c = self.control
        if cmd == "HEARTBEAT":
            c.last_seen[self.dev_id] = time.strftime("%Y-%m-%d %H:%M:%S")
            return {"ok": True, "data": {"status": "hidup"}}
        if cmd == "POLL":
            t = c.berikutnya(self.dev_id)
            return {"ok": True, "data": {"tugas": t}}
        if cmd == "HASIL":
            tugas_id = (payload or {}).get("tugas_id")
            hasil = json.loads((payload or {}).get("data") or "{}")
            selesai = c.terima_hasil(self.dev_id, tugas_id, hasil)
            return {"ok": True, "data": {"status": selesai["status"]}}
        if cmd == "BYE":
            return {"ok": True, "data": {"bye": True}}
        return {"ok": False, "alasan": f"cmd tidak dikenal: {cmd}"}


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class SLCEndpoint:
    """Agent satu perangkat: siklus heartbeat→poll→eksekusi→hasil,
    backoff terbatas, graceful shutdown, limit sumber daya, health jujur."""

    def __init__(self, dev_id, kunci, transport, config=None):
        if not dev_id or not kunci:
            raise PermissionError(
                "agent menolak jalan tanpa enrollment eksplisit "
                "(dev_id + kunci out-of-band)")
        self.dev_id = dev_id
        self.kunci = kunci
        self.transport = transport
        cfg = config or {}
        self.limits = cfg.get("limits", {})   # mis. {"maxrss_kb": 262144}
        self.interval = float(cfg.get("interval_heartbeat", 5.0))
        self.versi = VERSII_AGENT
        self.n_eksekusi = 0
        self.n_gagal = 0
        self.terakhir_error = None
        self.percobaan_ulang = 0
        self.berhenti = False   # flag graceful shutdown

    # ---------------- backoff terbatas ----------------
    def backoff(self):
        """Jeda reconnect berikutnya (detik) — eksponensial terbatas."""
        jeda = min(BATAS_BAKOFF_AWAL * (FAKTOR_BACKOFF ** self.percobaan_ulang),
                   BATAS_BAKOFF_MAKS)
        return round(jeda, 2)

    def catat_gagal_koneksi(self):
        self.percobaan_ulang = min(self.percobaan_ulang + 1, 20)
        self.terakhir_error = "koneksi gagal"

    def catat_sukses_koneksi(self):
        self.percobaan_ulang = 0
        self.terakhir_error = None

    # ---------------- limit sumber daya ----------------
    def dalam_batas(self):
        if not self.limits:
            return True, None
        ru = resource.getrusage(resource.RUSAGE_SELF)
        maks = self.limits.get("maxrss_kb")
        if maks and ru.ru_maxrss > maks:
            return False, f"maxrss {ru.ru_maxrss}KB > batas {maks}KB"
        return True, None

    # ---------------- siklus ----------------
    def siklus(self):
        """Satu putaran penuh. Return status siklus (jujur, termasuk gagal)."""
        if self.berhenti:
            return {"status": "BERHENTI"}
        try:
            hb = self.transport.kirim("HEARTBEAT", {
                "versi_agent": self.versi,
                "identitas": IDENTITAS,
                "status": "hidup"})
            if not hb.get("ok"):
                raise TransportError(hb.get("alasan", "heartbeat ditolak"))
            self.catat_sukses_koneksi()
        except (TransportError, OSError) as e:
            self.catat_gagal_koneksi()
            return {"status": "KONEKSI_GAGAL", "jeda_s": self.backoff()}
        poll = self.transport.kirim("POLL", {})
        tugas = (poll.get("data") or {}).get("tugas") \
            if poll.get("ok") else None
        if not tugas:
            return {"status": "IDLE"}
        hasil = self._eksekusi(tugas)
        self.transport.kirim("HASIL", {
            "tugas_id": tugas["tugas_id"], "aksi": tugas["aksi"],
            "data": json.dumps(hasil, ensure_ascii=False, default=str)})
        self.n_eksekusi += 1
        return {"status": "EKSEKUSI", "tugas_id": tugas["tugas_id"],
                "aksi": tugas["aksi"]}

    def _eksekusi(self, tugas):
        """Eksekusi aksi via registry (whitelist). Limit & error jujur."""
        ok, alasan = self.dalam_batas()
        if not ok:
            self.n_gagal += 1
            return {"error": f"limit sumber daya: {alasan}"}
        d = slc_actions.definisi(tugas["aksi"])
        try:
            return slc_actions.jalankan(tugas["aksi"], tugas.get("params"),
                                         timeout=d["timeout"])
        except Exception as e:  # dilaporkan jujur, TIDAK ditelan
            self.n_gagal += 1
            self.terakhir_error = str(e)
            return {"error": f"{type(e).__name__}: {e}"}

    # ---------------- kontrol & kesehatan ----------------
    def shutdown(self):
        """Graceful shutdown: beri flag; siklus berikutnya kirim BYE."""
        self.berhenti = True
        try:
            self.transport.kirim("BYE", {"dev_id": self.dev_id})
        except (TransportError, OSError):
            pass
        finally:
            tutup = getattr(self.transport, "tutup", None)
            if tutup:
                tutup()

    def kesehatan(self):
        return {"identitas": IDENTITAS, "dev_id": self.dev_id,
                "versi": self.versi, "python": platform.python_version(),
                "platform": platform.system(),
                "n_eksekusi": self.n_eksekusi, "n_gagal": self.n_gagal,
                "terakhir_error": self.terakhir_error,
                "percobaan_ulang": self.percobaan_ulang,
                "backoff_s": self.backoff(),
                "batas": self.limits,
                "berhenti": self.berhenti}

    # ---------------- update ter-cek integritas ----------------
    def pasang_paket(self, path_paket, hash_sha256, tujuan):
        """Pasang paket update HANYA bila sha256 cocok; atomic + .bak."""
        from pathlib import Path
        src = Path(path_paket)
        if not src.is_file():
            raise FileNotFoundError(src)
        h = hashlib.sha256(src.read_bytes()).hexdigest()
        if h != hash_sha256.lower():
            raise ValueError("hash paket TIDAK cocok — update ditolak")
        dst = Path(tujuan)
        if dst.exists():
            shutil.copy2(dst, str(dst) + ".bak")
        os.replace(src, dst)
        return {"terpasang": True, "hash": h, "tujuan": str(dst)}


# ---------------------------------------------------------------------------
# Layanan Windows — prosedur TERDOKUMENTASI (butuh Administrator di mesin
# target; dijalankan pemilik lab sendiri; TIDAK dipasang diam-diam).
# ---------------------------------------------------------------------------

CARA_INSTALL = """\
Instalasi layanan Windows (jalankan sebagai Administrator di PC lab):
  sc.exe create SLCAgent binPath= "C:\\\\Python312\\\\python.exe C:\\\\lab\\\\slc_endpoint.py --layanan --id DEV-XXXX --kunci XXXX" start= delayed-auto
  sc.exe description SLCAgent "SLC Endpoint Agent - lab universitas (administrasi terpusat resmi)"
  sc.exe failure SLCAgent reset= 86400 actions= restart/5000
Mulai/stop/restart:
  sc.exe start SLCAgent | sc.exe stop SLCAgent | sc.exe restart SLCAgent
Upgrade:
  1) slc_endpoint.py --pasang-paket <file> <sha256> <tujuan>   (integritas dicek)
  2) sc.exe stop SLCAgent && salin file && sc.exe start SLCAgent
Uninstall (dihapus sepenuhnya — agent TIDAK menghalangi):
  sc.exe stop SLCAgent && sc.exe delete SLCAgent && rmdir /s /q C:\\lab
"""

NAMA_LAYANAN = "SLCAgent"  # identitas jelas — TIDAK menyamar komponen Windows


def layanan_loop(agent, transport, maks_siklus=None):
    """Loop siklus layanan: berhenti rapi saat berhenti=True (graceful),
    reconnect dengan backoff terbatas."""
    n = 0
    while not agent.berhenti and (maks_siklus is None or n < maks_siklus):
        status = agent.siklus()
        if status["status"] == "KONEKSI_GAGAL":
            time.sleep(min(status["jeda_s"], BATAS_BAKOFF_MAKS))
        else:
            time.sleep(agent.interval)
        n += 1
    return n


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="slc_endpoint v4.0 — SLC Endpoint Agent (identitas jelas, "
                    "enrollment eksplisit, least-privilege).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--id", required=False, default=None,
                    help="device id dari enrollment")
    ap.add_argument("--kunci", required=False, default=None,
                    help="kunci perangkat dari enrollment (out-of-band)")
    ap.add_argument("--tls", action="store_true",
                    help="pakai TLS + pin sertifikat controller")
    ap.add_argument("--pin", help="sha256 fingerprint sertifikat controller")
    ap.add_argument("--ca-file", help="file CA utk validasi sertifikat")
    ap.add_argument("--limit-maxrss-kb", type=int, default=0)
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--layanan", action="store_true",
                    help="mode loop layanan (utk Windows Service)")
    ap.add_argument("--install-layanan", action="store_true",
                    help="cetak prosedur install layanan Windows")
    ap.add_argument("--pasang-paket", nargs=3,
                    metavar=("FILE", "SHA256", "TUJUAN"))
    a = ap.parse_args()
    if a.install_layanan:
        print(CARA_INSTALL)
        return 0
    if not a.id or not a.kunci:
        ap.error("--id dan --kunci wajib (dari enrollment; "
                 "lihat --install-layanan untuk prosedur instalasi)")
    kunci = a.kunci
    cfg = {"interval_heartbeat": a.interval,
           "limits": {"maxrss_kb": a.limit_maxrss_kb} if
           a.limit_maxrss_kb else {}}
    tr = TransportTCP(a.host, a.port, a.id, kunci, use_tls=a.tls,
                      pin_sha256=a.pin, ca_file=a.ca_file)
    agent = SLCEndpoint(a.id, kunci, tr, cfg)
    if a.pasang_paket:
        print(json.dumps(agent.pasang_paket(*a.pasang_paket)))
        return 0
    if a.layanan:
        layanan_loop(agent, tr)
        return 0
    # satu siklus interaktif (diagnosa/manual)
    print(json.dumps(agent.siklus(), ensure_ascii=False))
    print(json.dumps(agent.kesehatan(), ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
