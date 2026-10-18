#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_server.py — v4.0 Sovereign Lab Control: SERVER TRANSPORT.

Threaded TCP (JSON-line, HMAC + nonce anti-replay via DeviceRegistry).
Aturan identitas KETAT:
  - perangkat HARUS ter-enroll, tidak dicabut, tidak lockdown,
    tidak emergency-stop; TERCAKAP DI JARINGAN ≠ DIIZINKAN.
  - cmd hanya HEARTBEAT / POLL / HASIL / BYE (whitelist; lain → ditolak).
TLS opsional: context server + validasi ketat; klien memverifikasi PIN
sha256 sertifikat (dilihat dari sisi agent — diuji nyata di test).
"""
from __future__ import annotations

import json
import socketserver
import ssl
import threading
import time

PERINTAH_DEVICE = ("HEARTBEAT", "POLL", "HASIL", "BYE")


class SLCServerHandler(socketserver.StreamRequestHandler):
    """Satu koneksi = satu perangkat. Pesan tidak valid → ditolak + audit."""

    def handle(self):
        for baris in self.rfile:
            baris = baris.strip()
            if not baris:
                continue
            try:
                msg = json.loads(baris)
            except json.JSONDecodeError:
                self._kirim({"ok": False, "alasan": "JSON tidak valid"})
                continue
            resp = self.server.control.pesan_device(
                msg, ip=self.client_address[0])
            self._kirim(resp)

    def _kirim(self, obj):
        self.wfile.write(json.dumps(obj, ensure_ascii=False,
                                    default=str).encode() + b"\n")


class SLCServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, control, host="127.0.0.1", port=0, tls_ctx=None):
        self.control = control
        self.tls_ctx = tls_ctx
        super().__init__((host, port), SLCServerHandler)

    def get_request(self):
        conn, addr = super().get_request()
        if self.tls_ctx is not None:
            try:
                conn = self.tls_ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                conn.close()
                raise
        return conn, addr


def pesan_device(control, msg, ip="127.0.0.1"):
    """Proses SATU pesan device (pure — dipakai handler & test)."""
    cmd = msg.get("cmd", "")
    if msg.get("jenis") != "device" or cmd not in PERINTAH_DEVICE:
        control.audit.append("device", "SLC_PERINTAH_DITOLAK",
                              f"cmd={cmd!r} ip={ip}")
        return {"ok": False, "alasan": f"cmd tidak dikenal: {cmd}"}
    dev_id = msg.get("id")
    rec, alasan = control.registry.verify_pesan(
        dev_id, msg.get("nonce"), msg.get("ts"), cmd,
        msg.get("payload"), msg.get("mac"))
    if rec is None:
        control.audit.append("device", "SLC_AUT_DITOLAK",
                             f"{dev_id} alasan={alasan} ip={ip}")
        return {"ok": False, "alasan": f"autentikasi gagal: {alasan}"}
    if dev_id in control._emergency:
        control.audit.append("device", "SLC_EMERGENCY_DITOLAK", str(dev_id))
        return {"ok": False, "alasan": "perangkat dalam emergency stop"}
    if cmd == "HEARTBEAT":
        control.last_seen[dev_id] = time.strftime("%Y-%m-%d %H:%M:%S")
        control.audit.append("device", "SLC_HEARTBEAT", str(dev_id))
        return {"ok": True, "data": {"status": "hidup",
                                     "server": "slc v4.0"}}
    if cmd == "POLL":
        t = control.berikutnya(dev_id)
        return {"ok": True, "data": {"tugas": t}}
    if cmd == "HASIL":
        p = msg.get("payload") or {}
        try:
            hasil = json.loads(p.get("data") or "{}")
        except json.JSONDecodeError:
            return {"ok": False, "alasan": "hasil bukan JSON valid"}
        t = control.terima_hasil(dev_id, p.get("tugas_id"), hasil)
        return {"ok": True, "data": {"status": t["status"]}}
    # BYE — graceful shutdown device
    control.audit.append("device", "SLC_BYE", str(dev_id))
    return {"ok": True, "data": {"bye": True}}


def jalankan_server(control, host="127.0.0.1", port=9443, tls_ctx=None):
    """Start server (blocking). Return tidak pernah — pakai thread utk test."""
    srv = SLCServer(control, host, port, tls_ctx=tls_ctx)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    import argparse
    from slc_control import SLCControl
    ap = argparse.ArgumentParser(description="slc_server v4.0")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--cert", help="path sertifikat TLS (PEM)")
    ap.add_argument("--key", help="path kunci privat TLS (PEM)")
    a = ap.parse_args()
    control = SLCControl()
    tls = None
    if a.cert and a.key:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(a.cert, a.key)
        print("[slc] TLS aktif — klien wajib verifikasi pin sertifikat")
    srv = SLCServer(control, a.host, a.port, tls_ctx=tls)
    print(f"[slc] server mendengarkan {a.host}:{a.port}")
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
