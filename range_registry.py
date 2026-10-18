#!/usr/bin/env python3
"""range_registry.py — Enrollment & kontrol perangkat lab (v3.0, STDLIB-ONLY).

Enrollment menghasilkan identitas perangkat:
- `dev-XXXXXXXX` + kunci rahasia 256-bit (`secrets.token_hex(32)`).
- Kunci ditampilkan SEKALI saat enroll (out-of-band); fingerprint
  SHA-256 kunci tersimpan di `devices.json` (0600).
- Kontrol: revoke per perangkat + lockdown global (semua ditolak).
- Anti-replay: setiap pesan perangkat membawa nonce sekali-pakai +
  timestamp; nonce yang sudah terlihat DITOLAK dalam jendela waktu.

CATATAN JUJUR:
- Jalur transport controller saat ini TCP plaintext loopback — TLS/mTLS
  antar-2-host adalah kerja manual owner (lihat docs/RANGE-SECURITY-v3.0.md).
- `last_seen` TIDAK dipersist (in-memory) — bukan klaim tracking.
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from datetime import datetime

import audit_core

FILE_DEFAULT = "devices.json"
PERAN_DEVICE = ("operator", "auditor")
JENDELA_NONCE = 60.0  # detik; pesan dengan |now-ts| > jendela DITOLAK


class RegistryError(Exception):
    """Kesalahan registry (file rusak, perangkat tidak ada, dst)."""


def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fingerprint_kunci(kunci):
    return hashlib.sha256(kunci.encode()).hexdigest()


def buat_mac(kunci, dev_id, nonce, ts, cmd, payload):
    """HMAC-SHA256 kanonik atas pesan perangkat (hex)."""
    kanonik = json.dumps({"id": dev_id, "nonce": nonce, "ts": ts,
                          "cmd": cmd, "payload": payload},
                         sort_keys=True, ensure_ascii=False)
    return hmac.new(kunci.encode(), kanonik.encode(),
                    hashlib.sha256).hexdigest()


def verifikasi_mac(kunci, dev_id, nonce, ts, cmd, payload, mac):
    return hmac.compare_digest(
        buat_mac(kunci, dev_id, nonce, ts, cmd, payload), mac or "")


class DeviceRegistry:
    """Inventaris perangkat ter-enroll + kontrol akses (devices.json 0600)."""

    def __init__(self, path=FILE_DEFAULT, audit_path="lab_audit.jsonl"):
        self.path = path
        self.audit = audit_core.AuditLog(audit_path)
        self.devices = {}
        self.lockdown = False
        self._nonce_terlihat = {}   # nonce -> waktu terlihat (detik epoch)
        self._muat()

    # ---------------- persistensi ----------------
    def _muat(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data.get("devices"), dict):
                raise ValueError("devices bukan dict")
            self.devices = data["devices"]
            self.lockdown = bool(data.get("lockdown", False))
        except (ValueError, OSError) as e:
            raise RegistryError(f"devices.json rusak: {self.path} ({e})")

    def simpan(self):
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(d, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"versi": 1, "lockdown": self.lockdown,
                       "devices": self.devices}, f, ensure_ascii=False,
                      indent=2)
        # pastikan izin 0600 juga bila file sudah ada sebelumnya
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # ---------------- lifecycle perangkat ----------------
    def enroll(self, nama, peran="operator", aktor="admin"):
        """Enroll perangkat baru → kunci DITAMPILKAN SEKALI (out-of-band)."""
        if peran not in PERAN_DEVICE:
            raise ValueError(f"peran tidak valid: {peran}")
        dev_id = "dev-" + secrets.token_hex(4)
        kunci = secrets.token_hex(32)  # 256-bit
        rec = {
            "nama": str(nama),
            "peran": peran,
            "kunci": kunci,
            "fingerprint": hashlib.sha256(kunci.encode()).hexdigest(),
            "enrolled_at": now_ts(),
            "revoked": False,
            "last_seen": None,
        }
        self.devices[dev_id] = rec
        self.simpan()
        self.audit.append(aktor, "DEVICE_ENROLL",
                          f"{dev_id} ({nama}) peran={peran}")
        return {"id": dev_id, "kunci": kunci, "fingerprint": rec["fingerprint"]}

    def revoke(self, dev_id, aktor="admin"):
        """Revokasi darurat per perangkat."""
        rec = self.devices.get(dev_id)
        if rec is None:
            raise KeyError(f"perangkat tidak ada: {dev_id}")
        rec["revoked"] = True
        self.simpan()
        self.audit.append(aktor, "DEVICE_REVOKE", f"{dev_id} ({rec['nama']})")

    def set_lockdown(self, aktif, aktor="admin"):
        """Lockdown global: semua perangkat ditolak (switch darurat)."""
        self.lockdown = bool(aktif)
        self.simpan()
        self.audit.append(aktor, "RANGE_LOCKDOWN",
                          f"aktif={self.lockdown}")

    def daftar(self):
        """Salinan inventaris (tanpa kunci) untuk tampilan."""
        return [{"id": k, "nama": r["nama"], "peran": r["peran"],
                 "revoked": r["revoked"],
                 "enrolled_at": r["enrolled_at"]}
                for k, r in sorted(self.devices.items())]

    def cek_enrolled(self, dev_id):
        """Rec perangkat aktif, atau None bila tidak ada/revoked."""
        rec = self.devices.get(dev_id)
        if rec is None or rec.get("revoked"):
            return None
        return rec

    # ---------------- verifikasi pesan + anti-replay ----------------
    def verify_pesan(self, dev_id, nonce, ts, cmd, payload, mac,
                     sekarang=None):
        """Verifikasi autentisitas + kesegaran pesan perangkat.

        Return (rec, alasan): rec = record bila OK, alasan = str bila
        DITOLAK. Urutan cek: lockdown → enrolled → jendela waktu →
        nonce sekali-pakai → MAC.
        """
        sekarang = time.time() if sekarang is None else sekarang
        if self.lockdown:
            return None, "lockdown aktif — semua perangkat ditolak"
        rec = self.cek_enrolled(dev_id)
        if rec is None:
            return None, f"perangkat {dev_id} tidak ter-enroll/revoked"
        try:
            umur = abs(sekarang - float(ts))
        except (TypeError, ValueError):
            return None, "timestamp tidak valid"
        if umur > JENDELA_NONCE:
            return None, f"timestamp di luar jendela ±{JENDELA_NONCE:.0f}s"
        if not nonce:
            return None, "nonce kosong"
        if nonce in self._nonce_terlihat:
            return None, "nonce sudah dipakai (replay)"
        if not verifikasi_mac(rec["kunci"], dev_id, nonce, ts, cmd,
                              payload, mac):
            return None, "MAC tidak cocok"
        self._nonce_terlihat[nonce] = sekarang
        rec["last_seen"] = now_ts()  # in-memory saja (jujur: tak dipersist)
        self._bersihkan_nonce(sekarang)
        return rec, ""

    def _bersihkan_nonce(self, now):
        for n, t in list(self._nonce_terlihat.items()):
            if now - t > JENDELA_NONCE:
                del self._nonce_terlihat[n]


def main():
    ap = argparse.ArgumentParser(
        description="range_registry v3.0 — enrollment & kontrol perangkat lab "
                    "(identitas HMAC-SHA256, revoke, lockdown darurat).")
    ap.add_argument("--file", default=FILE_DEFAULT)
    ap.add_argument("--audit", default="lab_audit.jsonl")
    ap.add_argument("--enroll", metavar="NAMA",
                    help="enroll perangkat baru (kunci ditampilkan SEKALI)")
    ap.add_argument("--peran", default="operator", choices=PERAN_DEVICE)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--revoke", metavar="DEV_ID")
    ap.add_argument("--lockdown", action="store_true")
    ap.add_argument("--buka-lockdown", action="store_true")
    args = ap.parse_args()

    reg = DeviceRegistry(args.file, args.audit)
    if args.enroll:
        info = reg.enroll(args.enroll, args.peran)
        print(f"[registry] ENROLL OK: {info['id']} ({args.enroll})")
        print(f"  kunci perangkat (SIMPAN SEKARANG — tidak dicetak ulang):")
        print(f"    {info['kunci']}")
        print(f"  fingerprint SHA-256: {info['fingerprint']}")
        return 0
    if args.revoke:
        reg.revoke(args.revoke)
        print(f"[registry] REVOKE OK: {args.revoke}")
        return 0
    if args.lockdown:
        reg.set_lockdown(True)
        print("[registry] LOCKDOWN AKTIF — semua perangkat ditolak")
        return 0
    if args.buka_lockdown:
        reg.set_lockdown(False)
        print("[registry] lockdown dibuka")
        return 0
    # default: list
    print(f"[registry] lockdown={reg.lockdown}, "
          f"{len(reg.devices)} perangkat:")
    for d in reg.daftar():
        print(f"  {d['id']} {d['nama']:<16} {d['peran']:<8} "
              f"{'aktif' if not d['revoked'] else 'REVOKED'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
