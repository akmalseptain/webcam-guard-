"""mirror_auth.py — Autentikasi, peran, persetujuan eksplisit, dan audit sesi mirroring.

Modul ini STDLIB-ONLY (bisa diuji tanpa OpenCV/mss).
Konsep:
- Kode pairing 8-hex (XXXX-XXXX) dibuat per sesi oleh pengirim; ditampilkan
  ke pengguna dan harus diketik manual oleh penonton (out-of-band).
- Token = HMAC-SHA256(kode, "kode:role") — server memverifikasi tiap koneksi.
- Role "admin" bisa mencabut penonton lain; "viewer" hanya bisa keluar sendiri.
- ConsentGate: mirroring TIDAK BISA dimulai sebelum pengguna mengetik SETUJU.
- Semua kejadian tercatat ke sessions.csv (audit trail).
"""

import csv
import hashlib
import hmac
import os
import secrets
from datetime import datetime

SESSIONS_LOG = "sessions.csv"
ROLES = ("admin", "viewer")


def buat_kode_pairing():
    """Kode pairing per sesi, format 'XXXX-XXXX' (4+4 hex)."""
    a = secrets.token_hex(2).upper()
    b = secrets.token_hex(2).upper()
    return f"{a}-{b}"


def buat_token(kode, role):
    """Token HMAC untuk (kode pairing, role)."""
    if role not in ROLES:
        raise ValueError(f"role tidak valid: {role}")
    bahan = f"{kode}:{role}".encode("utf-8")
    return hmac.new(bahan, bahan, hashlib.sha256).hexdigest()


def verifikasi_token(kode, role, token):
    """True bila token cocok untuk (kode, role). Constant-time compare."""
    if role not in ROLES or not token:
        return False
    return hmac.compare_digest(buat_token(kode, role), token)


def audit_log(event, role, detail=""):
    """Catat kejadian sesi ke sessions.csv."""
    baru = not os.path.exists(SESSIONS_LOG)
    with open(SESSIONS_LOG, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if baru:
            w.writerow(["timestamp", "event", "role", "detail"])
        w.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    event, role, detail])


class ConsentGate:
    """Gerbang persetujuan eksplisit — tidak bisa dilewati program.

    Pengguna HARUS mengetik kata persetujuan (default 'SETUJU') di terminal.
    Tidak ada jalur otomatis; tanpa ini, sesi tidak boleh berstatus AKTIF.
    """

    def __init__(self, kata="SETUJU"):
        self.kata = kata.upper()
        self.waktu_setuju = None

    def minta(self, jawaban):
        """Proses jawaban pengguna; True bila disetujui."""
        if jawaban.strip().upper() == self.kata:
            self.waktu_setuju = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return True
        return False

    @property
    def disetujui(self):
        return self.waktu_setuju is not None


class Sesi:
    """State machine sesi: idle -> aktif -> jeda -> berhenti (satu arah)."""
    IDLE, AKTIF, JEDA, BERHENTI = "idle", "aktif", "jeda", "berhenti"
    TRANSISI = {
        (IDLE, AKTIF): "mulai",
        (AKTIF, JEDA): "jeda",
        (JEDA, AKTIF): "lanjut",
        (AKTIF, BERHENTI): "stop",
        (JEDA, BERHENTI): "stop",
        (IDLE, BERHENTI): "batal",
    }

    def __init__(self):
        self.state = self.IDLE
        self.penonton = {}  # id -> role

    def _transisi(self, target):
        kunci = (self.state, target)
        if kunci not in self.TRANSISI:
            raise RuntimeError(f"transisi ilegal: {self.state} -> {target}")
        self.state = target
        return self.TRANSISI[kunci]

    def mulai(self):
        return self._transisi(self.AKTIF)

    def jeda(self):
        return self._transisi(self.JEDA)

    def lanjut(self):
        return self._transisi(self.AKTIF)

    def stop(self):
        return self._transisi(self.BERHENTI)

    def tambah_penonton(self, penonton_id, role):
        if role not in ROLES:
            raise ValueError(f"role tidak valid: {role}")
        if self.state not in (self.AKTIF, self.JEDA):
            raise RuntimeError("penonton hanya bisa masuk saat sesi aktif/jeda")
        self.penonton[penonton_id] = role

    def keluar(self, penonton_id):
        """Penonton keluar sendiri — boleh untuk semua role."""
        return self.penonton.pop(penonton_id, None) is not None

    def cabut(self, penonton_id, oleh_role):
        """Admin boleh mencabut penonton lain; viewer TIDAK."""
        if oleh_role != "admin":
            raise PermissionError("hanya admin yang bisa mencabut penonton lain")
        if penonton_id not in self.penonton:
            raise KeyError(f"penonton tidak ada: {penonton_id}")
        del self.penonton[penonton_id]
