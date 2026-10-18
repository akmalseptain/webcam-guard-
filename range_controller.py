#!/usr/bin/env python3
"""range_controller.py — Lab controller ter-autentikasi (v3.0, STDLIB-ONLY).

Dua jenis klien:
1. PERANGKAT (dari range_registry enrollment): pesan ber-MAC HMAC
   (id/nonce/ts/cmd/payload) — divalidasi registry (anti-replay).
2. OPERATOR: username+password PBKDF2 (OperatorStore, operators.json 0600)
   dengan peran admin/operator/auditor — whitelist perintah DIEKSEKUSI.

Whitelist perintah:
- Perangkat : HELLO / HEARTBEAT / POLL / HASIL — tidak ada lagi.
- Operator  : TUGAS (admin saja) / LIHAT (semua peran, read-only).

Keamanan:
- Rate limit per-IP pada login operator (audit_core.RateLimiter) + lockout.
- Anti-enumeration: PBKDF2 dummy untuk username tak dikenal.
- Semua tugas masuk antrean FIFO per perangkat; POLL mengonsumsi
  (pop) — hasil task dibuktikan via event hash-chain.

CATATAN JUJUR: server default HANYA loopback; jalur plaintext.
"""

import argparse
import hashlib
import json
import os
import secrets
import socketserver
import sys
import threading
import time

import audit_core
import forensics
from range_registry import (DeviceRegistry, RegistryError,
                            buat_mac, now_ts)

EVENTS_FILE = "lab_events.jsonl"
AUDIT_FILE = "lab_audit.jsonl"
OPERATORS_FILE = "operators.json"
DEVICE_FILE = "devices.json"
PORT_DEFAULT = 9443
ITER_PBKDF2 = 200_000

# whitelist perintah per jenis klien
PERINTAH_DEVICE = ("HELLO", "HEARTBEAT", "POLL", "HASIL")
PERINTAH_OPERATOR = {
    "admin": ("TUGAS", "LIHAT"),
    "operator": ("LIHAT",),
    "auditor": ("LIHAT",),
}


def _hash_pbkdf2(password, iterasi=ITER_PBKDF2):
    """Hash PBKDF2 format audit_core ('pbkdf2$iter$salt$hash') dengan
    jumlah iterasi parametris (divalidasi batas 1.000–400.000 saat
    verify oleh audit_core.verify_password)."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt.encode("utf-8"), iterasi)
    return f"pbkdf2${iterasi}${salt}${dk.hex()}"


class OperatorStore:
    """Kredensial operator controller: operators.json (hash PBKDF2, 0600)."""

    def __init__(self, path=OPERATORS_FILE, audit_path=AUDIT_FILE,
                 iterasi=ITER_PBKDF2):
        self.path = path
        self.audit = audit_core.AuditLog(audit_path)
        self.iterasi = iterasi
        if os.path.exists(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    self._data = json.load(f)
            except (ValueError, OSError):
                raise RegistryError(f"operators.json rusak: {self.path}")
        else:
            self._data = {"users": {}}

    def _simpan(self):
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def add_user(self, username, password, role):
        if role not in audit_core.ROLES:
            raise ValueError(f"role tidak valid: {role}")
        if username in self._data["users"]:
            raise ValueError(f"username sudah ada: {username}")
        self._data["users"][username] = {
            "hash": _hash_pbkdf2(password, self.iterasi),
            "role": role,
        }
        self._simpan()
        self.audit.append("controller", "OPERATOR_BARU",
                          f"{username} role={role}")

    def authenticate(self, username, password, limiter=None):
        """Login operator; anti-enumeration via PBKDF2 dummy.

        Return role (str) bila berhasil, None bila ditolak.
        """
        u = self._data["users"].get(username)
        if limiter is not None and not limiter.allow(username):
            return None  # rate limit: sama lambatnya dengan ditolak
        if u is None:
            # anti-enumeration: waktu ~setara dengan pemakai nyata
            audit_core.verify_password(
                password, _hash_pbkdf2("dummy-anti-enum-lab",
                                       self.iterasi))
            return None
        if audit_core.verify_password(password, u["hash"]):
            return u["role"]
        return None


class RangeController:
    """Otak controller: validasi pesan + antrean tugas + audit."""

    def __init__(self, registry, operators, events_path=EVENTS_FILE,
                 audit_path=AUDIT_FILE):
        self.registry = registry
        self.operators = operators
        self.events = forensics.EventStore(events_path)
        self.audit = audit_core.AuditLog(audit_path)
        self._limiter = audit_core.RateLimiter(
            maks=10, jendela=60.0)  # login operator per-IP/nama
        self._antrean = {}    # dev_id -> [tugas, ...] (FIFO)
        self._hasil = []      # hasil terakhir (ringkas)

    # ---------------- operator ----------------
    def beri_tugas(self, oleh_role, dev_id, jenis, payload=None):
        """Admin saja boleh memberi tugas ke perangkat (whitelist jenis)."""
        from range_agent import TUGAS_JENIS
        if oleh_role != "admin":
            self.audit.append("controller", "TUGAS_DITOLAK",
                              f"role={oleh_role} mencoba memberi tugas "
                              f"{jenis} ke {dev_id}")
            raise PermissionError(
                f"role '{oleh_role}' tidak boleh memberi tugas")
        if jenis not in TUGAS_JENIS:
            self.audit.append("controller", "TUGAS_DITOLAK",
                              f"jenis tugas tidak dikenal: {jenis}")
            raise ValueError(f"jenis tugas tidak dikenal: {jenis}")
        rec = self.registry.cek_enrolled(dev_id)
        if rec is None:
            raise KeyError(f"perangkat tidak ter-enroll: {dev_id}")
        tugas = {"tugas_id": "t-" + secrets.token_hex(4),
                 "jenis": jenis, "payload": payload or {},
                 "diberi": now_ts()}
        self._antrean.setdefault(dev_id, []).append(tugas)
        self.audit.append("controller", "TUGAS_DIBERI",
                          f"{tugas['tugas_id']} {jenis} -> {dev_id}")
        return tugas

    # ---------------- pemrosesan pesan (pure, testable) ----------------
    def proses_pesan(self, msg, ip="127.0.0.1", sekarang=None):
        """Satu pesan (dict) → respons (dict). Tidak menyentuh socket."""
        sekarang = time.time() if sekarang is None else sekarang
        jenis = msg.get("jenis", "")
        cmd = msg.get("cmd", "")

        # ---- 1) jalur perangkat (MAC HMAC) ----
        if jenis == "device":
            if cmd not in PERINTAH_DEVICE:
                self.audit.append("device", "PERINTAH_DITOLAK",
                                  f"cmd={cmd} di luar whitelist")
                return {"ok": False, "alasan": f"cmd tidak dikenal: {cmd}"}
            rec, alasan = self.registry.verify_pesan(
                msg.get("id"), msg.get("nonce"), msg.get("ts"),
                cmd, msg.get("payload", {}), msg.get("mac"),
                sekarang=sekarang)
            if rec is None:
                self.audit.append("device", "DEVICE_DITOLAK",
                                  f"{msg.get('id')}: {alasan}")
                return {"ok": False, "alasan": alasan}
            if cmd == "HELLO":
                self.audit.append("device", "DEVICE_HELLO",
                                  f"{msg['id']} ({rec['nama']}) tersambung")
                return {"ok": True, "data": {"nama": rec["nama"],
                                             "peran": rec["peran"]}}
            if cmd == "HEARTBEAT":
                return {"ok": True, "data": {"diterima": True}}
            if cmd == "POLL":
                antrean = self._antrean.get(msg["id"], [])
                tugas = antrean.pop(0) if antrean else None  # FIFO konsumsi
                return {"ok": True, "data": {"tugas": tugas}}
            if cmd == "HASIL":
                hasil = msg.get("payload", {})
                self._hasil.append({"id": msg["id"],
                                    "tugas_id": hasil.get("tugas_id"),
                                    "jenis": hasil.get("jenis")})
                self.events.append(forensics.normalize(
                    "process",
                    f"hasil tugas {hasil.get('jenis')} "
                    f"({hasil.get('tugas_id')})",
                    str(hasil.get("data"))[:300],
                    host=rec["nama"]))
                self.audit.append("device", "HASIL_DITERIMA",
                                  f"{msg['id']} {hasil.get('tugas_id')}")
                return {"ok": True, "data": {"tercatat": True}}

        # ---- 2) jalur operator (username+password PBKDF2) ----
        if jenis == "operator":
            role = self.operators.authenticate(
                msg.get("username"), msg.get("password", ""),
                limiter=self._limiter)
            if role is None:
                self.audit.append("operator", "LOGIN_GAGAL",
                                  f"user={msg.get('username')} ip={ip}")
                return {"ok": False, "alasan": "login ditolak"}
            if cmd not in PERINTAH_OPERATOR.get(role, ()):
                self.audit.append("operator", "TUGAS_DITOLAK",
                                  f"role={role} cmd={cmd} di luar izin")
                return {"ok": False,
                        "alasan": f"role '{role}' tidak berizin cmd {cmd}"}
            if cmd == "TUGAS":
                try:
                    t = self.beri_tugas(role, msg.get("dev_id"),
                                        msg.get("jenis_tugas"),
                                        msg.get("payload"))
                except (PermissionError, ValueError, KeyError) as e:
                    return {"ok": False, "alasan": str(e)}
                return {"ok": True, "data": {"tugas_id": t["tugas_id"]}}
            if cmd == "LIHAT":
                return {"ok": True, "data": {
                    "devices": self.registry.daftar(),
                    "n_antrean": {k: len(v)
                                  for k, v in self._antrean.items()},
                    "n_hasil": len(self._hasil)}}

        return {"ok": False, "alasan": "jenis klien tidak dikenal"}


class _Handler(socketserver.StreamRequestHandler):
    """Satu klien per koneksi; baris JSON masuk → JSON keluar."""

    def handle(self):
        ctrl = self.server.ctrl
        for baris in self.rfile:
            try:
                msg = json.loads(baris)
            except ValueError:
                self.wfile.write(json.dumps(
                    {"ok": False, "alasan": "JSON tidak valid"}).encode()
                    + b"\n")
                continue
            resp = ctrl.proses_pesan(msg, ip=self.client_address[0])
            self.wfile.write(json.dumps(resp, ensure_ascii=False).encode()
                             + b"\n")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def jalankan_server(ctrl, host="127.0.0.1", port=PORT_DEFAULT):
    """Jalankan server; return (server, port_aktual) — port 0 = pilih bebas."""
    srv = _Server((host, port), _Handler)
    srv.ctrl = ctrl
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


def main():
    ap = argparse.ArgumentParser(
        description="range_controller v3.0 — lab controller ter-autentikasi "
                    "(device registry + operator RBAC persisten + audit).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=PORT_DEFAULT)
    ap.add_argument("--device-file", default=DEVICE_FILE)
    ap.add_argument("--operators-file", default=OPERATORS_FILE)
    ap.add_argument("--events", default=EVENTS_FILE)
    ap.add_argument("--audit", default=AUDIT_FILE)
    ap.add_argument("--init-admin", metavar="PASSWORD",
                    help="buat admin operator awal (sekali saja)")
    args = ap.parse_args()

    operators = OperatorStore(args.operators_file, args.audit)
    if args.init_admin:
        operators.add_user("admin", args.init_admin, "admin")
        print("[controller] admin dibuat (operators.json).")
        return 0

    if "admin" not in operators._data["users"]:
        print("[controller] BELUM ada admin. Jalankan dulu:")
        print("  python3 range_controller.py --init-admin <password>")
        return 2

    registry = DeviceRegistry(args.device_file, args.audit)
    ctrl = RangeController(registry, operators, args.events, args.audit)
    srv, port = jalankan_server(ctrl, args.host, args.port)
    print(f"[controller] JALAN di {args.host}:{port}")
    print(f"[controller] {len(registry.devices)} perangkat, "
          f"lockdown={registry.lockdown}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
        print("[controller] berhenti.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
