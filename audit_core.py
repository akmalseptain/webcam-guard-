"""audit_core.py — Inti keamanan lab: RBAC, password hashing, rate limiter, audit log.

Modul STDLIB-ONLY (hashlib/hmac stdlib; PBKDF2 via hashlib.pbkdf2_hmac).
Konsep:
- RBAC tiga peran: admin / operator / auditor. Matriks izin eksplisit.
- Password TIDAK pernah disimpan polos: PBKDF2-HMAC-SHA256 + salt acak.
- RateLimiter: batasi percobaan login per-pengguna (anti brute-force).
- AuditLog: hash-chain (setiap baris berisi hash baris sebelumnya) —
  perubahan/ penghapusan baris akan terdeteksi oleh verify().
Semua operasi istimewa di lab wajib melewati modul ini.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime

PBKDF2_ITER = 200_000

ROLES = ("admin", "operator", "auditor")

# Matriks izin: permission -> peran yang boleh.
IZIN = {
    "kelola_pengguna": ("admin",),
    "jalankan_skenario": ("admin", "operator"),
    "jalankan_capture": ("admin", "operator"),
    "jalankan_credcheck": ("admin", "operator"),
    "lihat_laporan": ("admin", "operator", "auditor"),
    "verifikasi_integritas": ("admin", "auditor"),
}


# ------------------------------------------------------------
# Password hashing (PBKDF2)
# ------------------------------------------------------------
def hash_password(password, salt=None):
    """Kembalikan string 'pbkdf2$iter$salt$hash' (tidak ada password polos)."""
    if not isinstance(password, str) or not password:
        raise ValueError("password kosong/tidak valid")
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt.encode("utf-8"), PBKDF2_ITER)
    return f"pbkdf2${PBKDF2_ITER}${salt}${dk.hex()}"


def verify_password(password, stored):
    """Cek password terhadap string hash; constant-time per bandingkan."""
    try:
        skema, iterasi, salt, digest = stored.split("$", 3)
        if skema != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 salt.encode("utf-8"), int(iterasi))
        return hmac.compare_digest(dk.hex(), digest)
    except (ValueError, AttributeError):
        return False


# ------------------------------------------------------------
# Rate limiter (sliding window per kunci)
# ------------------------------------------------------------
class RateLimiter:
    """Batasi aksi per kunci: maksimum `maks` kali dalam `jendela` detik."""

    def __init__(self, maks=5, jendela=60.0):
        self.maks = maks
        self.jendela = jendela
        self._riwayat = {}  # kunci -> [timestamps]

    def allow(self, kunci, now=None):
        now = time.monotonic() if now is None else now
        riwayat = [t for t in self._riwayat.get(kunci, [])
                   if now - t < self.jendela]
        if len(riwayat) >= self.maks:
            self._riwayat[kunci] = riwayat
            return False
        riwayat.append(now)
        self._riwayat[kunci] = riwayat
        return True


# ------------------------------------------------------------
# Audit log dengan hash-chain (tamper-evident)
# ------------------------------------------------------------
class AuditLog:
    """Log operasi istimewa; setiap baris terikat hash baris sebelumnya.

    Format JSONL: {"ts","aktor","aksi","detail","prev","hash"}
    verify() memeriksa ulang seluruh rantai dan melaporkan baris pertama
    yang tidak konsisten (bila ada), atau None bila utuh.
    """

    def __init__(self, path="lab_audit.jsonl"):
        self.path = path

    def _hash_baris(self, ts, aktor, aksi, detail, prev):
        bahan = f"{prev}|{ts}|{aktor}|{aksi}|{detail}".encode("utf-8")
        return hashlib.sha256(bahan).hexdigest()

    def append(self, aktor, aksi, detail=""):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prev = "GENESIS"
        entries = self.entries()
        if entries:
            prev = entries[-1]["hash"]
        h = self._hash_baris(ts, aktor, aksi, detail, prev)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": ts, "aktor": aktor, "aksi": aksi,
                                "detail": detail, "prev": prev, "hash": h},
                               ensure_ascii=False) + "\n")

    def entries(self):
        if not os.path.exists(self.path):
            return []
        hasil = []
        with open(self.path, encoding="utf-8") as f:
            for baris in f:
                baris = baris.strip()
                if baris:
                    hasil.append(json.loads(baris))
        return hasil

    def verify(self):
        """None bila rantai utuh; selain itu indeks baris bermasalah."""
        prev = "GENESIS"
        for i, e in enumerate(self.entries()):
            if e.get("prev") != prev:
                return i
            h = self._hash_baris(e["ts"], e["aktor"], e["aksi"],
                                 e.get("detail", ""), prev)
            if h != e.get("hash"):
                return i
            prev = e["hash"]
        return None

    def tamper(self, indeks, aksi_baru):
        """HANYA untuk test: ubah satu baris untuk membuktikan verify() bekerja."""
        entries = self.entries()
        entries[indeks]["aksi"] = aksi_baru
        with open(self.path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")


# ------------------------------------------------------------
# RBAC
# ------------------------------------------------------------
class RBAC:
    """Registry pengguna lab: username -> {role, hash_password}."""

    def __init__(self):
        self._pengguna = {}

    def add_user(self, username, password, role):
        if role not in ROLES:
            raise ValueError(f"role tidak valid: {role}")
        if username in self._pengguna:
            raise ValueError(f"username sudah ada: {username}")
        self._pengguna[username] = {
            "role": role,
            "hash": hash_password(password),
        }

    def authenticate(self, username, password):
        """Kembalikan role bila sah; None bila gagal."""
        u = self._pengguna.get(username)
        if u is None:
            return None
        if verify_password(password, u["hash"]):
            return u["role"]
        return None

    def authorize(self, role, permission):
        """True bila role memiliki permission."""
        return role in IZIN.get(permission, ())

    def n_pengguna(self):
        return len(self._pengguna)
