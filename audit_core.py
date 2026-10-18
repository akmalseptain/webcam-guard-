"""audit_core.py — Inti keamanan lab: RBAC, password hashing, rate limiter,
audit log hash-chain (v2.0).

STDLIB-ONLY (hashlib/hmac/fcntl stdlib; PBKDF2 via hashlib.pbkdf2_hmac).

v2.0 — perubahan dari v1.3 (semua dimotivasi audit independen A-01/A-05/A-15):
- flock lintas-proses (POSIX) pada append → menulis bersamaan dari banyak
  proses TIDAK lagi merusak rantai (diuji tests/test_audit_fixes.py).
- append O(1): hanya membaca baris terakhir (tail 8 KiB), bukan seluruh
  file → tidak lagi O(n^2) (A-07).
- field `seq` monotonik per baris (membantu deteksi re-order/duplikasi).
- checkpoint()/verify_terhadap_anchor(): anchor eksternal (file terpisah,
  ditulis atomik) → penghapusan baris EKOR kini terdeteksi (A-15).
  CATATAN PENTING: tanpa anchor, verify() TIDAK bisa mendeteksi
  penghapusan baris terakhir (blind spot yang diakui dan didokumentasikan).
- verify_password menolak iterasi di luar [PBKDF2_ITER_MIN, PBKDF2_ITER_MAKS]
  → hash parameter disusun sendiri oleh penyerang tidak bisa memaksa
  server berhemat-DoS (A-05).
- RateLimiter.hitung()/reset() tambahan.
- RBAC.authenticate(username, password, limiter=None): dukungan lockout
  per-username + anti user-enumeration (pemakai tak dikenal tetap
  menjalankan PBKDF2 dummy agar waktu respons ~sama).
- verify() toleran baris malformed (bukan dict / field hilang / JSON rusak)
  → melaporkan indeks baris bermasalah, bukan crash (bug hasil fuzz F2).

Format baris (JSONL, kompatibel v1.3 + field baru):
  {"ts","aktor","aksi","detail","prev","seq","hash"}
Formula hash TIDAK berubah dari v1.3: sha256("{prev}|{ts}|{aktor}|{aksi}|{detail}").

Jaminan & batasan (jujur):
- Terdeteksi: modifikasi isi baris, re-order, duplikasi (via prev/seq/hash),
  penghapusan baris TENGAH, truncation ekor (HANYA dengan anchor), dan
  baris malformed.
- TIDAK terdeteksi: penghapusan baris terakhir TANPA anchor; penyerang yang
  menguasai host bisa merekayasa file+anchor bersama (butuh anchoring
  eksternal — di luar scope v2.0, lihat docs/V2.0-SECURITY.md).
- Kunci file memakai fcntl.flock → didukung POSIX (Linux/macOS). Di Windows
  fallback TANPA kunci lintas-proses (dijelaskan saat runtime, tidak
  diklaim aman).
"""

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime

try:
    import fcntl
    _FCNTL_ADA = True
except ImportError:  # Windows: fallback tanpa kunci lintas-proses
    _FCNTL_ADA = False

PBKDF2_ITER = 200_000
# v2.0: rentang iterasi yang DIVALIDASI saat verify (anti-DoS parameter).
PBKDF2_ITER_MIN = 1_000
PBKDF2_ITER_MAKS = 400_000

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
# Kunci file lintas proses (POSIX)
# ------------------------------------------------------------
@contextmanager
def _kunci_file(path):
    """Kunci eksklusif lintas-proses untuk `path` (file sidecar `path.lock`).

    Di Windows fallback tanpa kunci (perilaku aman-secara-pesan: tetap
    jalan tapi TANPA jaminan konkurensi lintas proses).
    """
    lock_path = f"{path}.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if _FCNTL_ADA:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        if _FCNTL_ADA:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _entry_terakhir(path, tail=8192):
    """Baris JSON terakhir tanpa membaca seluruh file (append O(1)).

    Membaca `tail` byte terakhir; bila hasil potongannya bukan JSON valid
    (baris > tail atau mulai file terpotong), fallback membaca penuh.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size == 0:
        return None
    with open(path, "rb") as f:
        if size <= tail:
            data = f.read()
        else:
            f.seek(max(0, size - tail))
            data = f.read()
    kandidat = [b for b in data.split(b"\n") if b.strip()]
    if kandidat:
        try:
            e = json.loads(kandidat[-1].decode("utf-8"))
            if isinstance(e, dict):
                return e
        except (ValueError, UnicodeDecodeError):
            pass
    # fallback (jarang): baris terakhir > tail atau file korup — baca penuh
    try:
        with open(path, encoding="utf-8") as f:
            terakhir = None
            for baris in f:
                baris = baris.strip()
                if not baris:
                    continue
                try:
                    e = json.loads(baris)
                    if isinstance(e, dict):
                        terakhir = e
                except ValueError:
                    continue
            return terakhir
    except OSError:
        return None


def _sha256_file(path):
    """SHA-256 file (dibaca per-chunk; untuk anchor/manifest)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for potong in iter(lambda: f.read(65536), b""):
                h.update(potong)
        return h.hexdigest()
    except OSError:
        return ""


def tulis_anchor_atomik(path, data):
    """Tulis file anchor SECARA ATOMIK (tempfile + os.replace).

    Tulisan yang terputus di tengah TIDAK merusak anchor lama
    (file temp dibuang, file asli tetap utuh sampai replace).
    """
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".anchor-tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


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
    """Cek password terhadap string hash; constant-time per bandingkan.

    v2.0: iterasi dari string tersimpan DIVALIDASI terhadap
    [PBKDF2_ITER_MIN, PBKDF2_ITER_MAKS] SEBELUM komputasi mahal —
    hash parameternya dilemahkan/diperbesar oleh siapa pun ditolak cepat.
    """
    try:
        skema, iterasi, salt, digest = stored.split("$", 3)
        if skema != "pbkdf2":
            return False
        n = int(iterasi)
        if not (PBKDF2_ITER_MIN <= n <= PBKDF2_ITER_MAKS):
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 salt.encode("utf-8"), n)
        return hmac.compare_digest(dk.hex(), digest)
    except (ValueError, AttributeError, TypeError):
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

    def _dalam_jendela(self, kunci, now):
        return [t for t in self._riwayat.get(kunci, [])
                if now - t < self.jendela]

    def allow(self, kunci, now=None):
        now = time.monotonic() if now is None else now
        riwayat = self._dalam_jendela(kunci, now)
        if len(riwayat) >= self.maks:
            self._riwayat[kunci] = riwayat
            return False
        riwayat.append(now)
        self._riwayat[kunci] = riwayat
        return True

    def hitung(self, kunci, now=None):
        """Berapa upaya sudah tercatat dalam jendela (tanpa menambah)."""
        now = time.monotonic() if now is None else now
        return len(self._dalam_jendela(kunci, now))

    def reset(self, kunci):
        """Hapus riwayat kunci (mis. setelah keberhasilan login)."""
        self._riwayat.pop(kunci, None)


# ------------------------------------------------------------
# Audit log dengan hash-chain (tamper-evident) + seq + anchor
# ------------------------------------------------------------
class AuditLog:
    """Log operasi istimewa; setiap baris terikat hash baris sebelumnya.

    Format JSONL: {"ts","aktor","aksi","detail","prev","seq","hash"}
    verify() memeriksa ulang seluruh rantai dan melaporkan indeks baris
    pertama yang tidak konsisten (bila ada), atau None bila utuh.
    """

    def __init__(self, path="lab_audit.jsonl", anchor_path=None):
        self.path = path
        self.anchor_path = anchor_path or f"{path}.anchor.json"

    def _hash_baris(self, ts, aktor, aksi, detail, prev):
        bahan = f"{prev}|{ts}|{aktor}|{aksi}|{detail}".encode("utf-8")
        return hashlib.sha256(bahan).hexdigest()

    def _seq_baru(self, terakhir):
        """Seq baris berikutnya (kompatibel file v1.3 tanpa seq)."""
        if terakhir is None:
            return 1
        if isinstance(terakhir.get("seq"), int):
            return terakhir["seq"] + 1
        # file lama tanpa seq: hitung dari seluruh isi (sekali per baris
        # baru — biaya hanya untuk file legacy; setelah itu seq berjalan).
        return len(self.entries()) + 1

    def append(self, aktor, aksi, detail=""):
        """Tambah satu baris audit. Aman lintas proses (flock), O(1)."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with _kunci_file(self.path):
            terakhir = _entry_terakhir(self.path)
            prev = terakhir.get("hash") if terakhir else "GENESIS"
            seq = self._seq_baru(terakhir)
            h = self._hash_baris(ts, aktor, aksi, detail, prev)
            baris = {"ts": ts, "aktor": aktor, "aksi": aksi,
                     "detail": detail, "prev": prev, "seq": seq, "hash": h}
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(baris, ensure_ascii=False) + "\n")
        return baris

    def entries(self):
        """Semua baris valid (baris kosong dilewati)."""
        if not os.path.exists(self.path):
            return []
        hasil = []
        with open(self.path, encoding="utf-8") as f:
            for baris in f:
                baris = baris.strip()
                if not baris:
                    continue
                try:
                    hasil.append(json.loads(baris))
                except ValueError:
                    continue  # baris korup: dilewati di sini; verify() melapor
        return hasil

    def _baris_mentah(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as f:
            return [b.strip() for b in f if b.strip()]

    def verify(self):
        """None bila rantai utuh; selain itu indeks baris bermasalah.

        v2.0 toleran terhadap baris malformed (JSON rusak / bukan dict /
        field hilang): dilaporkan sebagai indeks bermasalah, bukan crash.
        """
        prev = "GENESIS"
        for i, mentah in enumerate(self._baris_mentah()):
            try:
                e = json.loads(mentah)
            except ValueError:
                return i
            if not isinstance(e, dict):
                return i
            if e.get("prev") != prev:
                return i
            try:
                h = self._hash_baris(e["ts"], e["aktor"], e["aksi"],
                                     e.get("detail", ""), prev)
            except (KeyError, TypeError):
                return i
            if h != e.get("hash"):
                return i
            prev = e["hash"]
        return None

    # ---------------- anchor (checkpoint eksternal) ----------------
    def checkpoint(self, anchor_path=None):
        """Catat checkpoint tepercaya ke file anchor TERPISAH (atomik).

        Anchor berisi: versi, jumlah baris (n), seq & hash baris terakhir,
        timestamp, dan SHA-256 seluruh file saat checkpoint.
        """
        anchor_path = anchor_path or self.anchor_path
        with _kunci_file(self.path):
            entries = self.entries()
            n = len(entries)
            terakhir = entries[-1] if entries else None
            data = {
                "versi": 1,
                "n": n,
                "anchor_seq": terakhir.get("seq") if terakhir else None,
                "anchor_hash": terakhir.get("hash") if terakhir else "GENESIS",
                "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "file_sha256": _sha256_file(self.path) if n else "",
            }
        tulis_anchor_atomik(anchor_path, data)
        return data

    def verify_terhadap_anchor(self, anchor_path=None):
        """Verifikasi rantai TERHADAP anchor tepercaya (bukan sekadar utuh).

        Return {"utuh": bool, "masalah": str|None, "n": int, "anchor": dict|None}.
        Kasus masalah (eksplisit):
        - "anchor tidak ditemukan"        : file anchor belum ada / rusak
        - "rantai rusak di baris N"       : verify() biasa menemukan rusak
        - "TERPANGKAS: N < anchor n"      : baris ekor dihapus setelah checkpoint
        - "baris pada posisi anchor berubah/dihapus"
        """
        anchor_path = anchor_path or self.anchor_path
        hasil = {"utuh": False, "masalah": "anchor tidak ditemukan",
                 "n": 0, "anchor": None}
        if not os.path.exists(anchor_path):
            hasil["n"] = len(self.entries())
            return hasil
        try:
            with open(anchor_path, encoding="utf-8") as f:
                anchor = json.load(f)
        except (ValueError, OSError):
            hasil["masalah"] = "anchor tidak ditemukan (rusak/tak terbaca)"
            hasil["n"] = len(self.entries())
            return hasil
        if not isinstance(anchor, dict):
            hasil["masalah"] = "anchor tidak ditemukan (format salah)"
            hasil["n"] = len(self.entries())
            return hasil
        hasil["anchor"] = anchor

        idx = self.verify()
        if idx is not None:
            hasil["masalah"] = f"rantai rusak di baris {idx}"
            hasil["n"] = len(self.entries())
            return hasil

        entries = self.entries()
        hasil["n"] = len(entries)
        try:
            n_anchor = int(anchor.get("n", 0))
        except (ValueError, TypeError):
            n_anchor = 0
        if len(entries) < n_anchor:
            hasil["masalah"] = f"TERPANGKAS: {len(entries)} < {n_anchor}"
            return hasil
        if n_anchor == 0:
            hasil["utuh"] = True
            hasil["masalah"] = None
            return hasil
        e = entries[n_anchor - 1]
        if e.get("hash") != anchor.get("anchor_hash"):
            hasil["masalah"] = "baris pada posisi anchor berubah/dihapus"
            return hasil
        aseq = anchor.get("anchor_seq")
        if aseq is not None and e.get("seq") is not None \
                and e.get("seq") != aseq:
            hasil["masalah"] = "baris pada posisi anchor berubah/dihapus"
            return hasil
        hasil["utuh"] = True
        hasil["masalah"] = None
        return hasil

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
    """Registry pengguna lab: username -> {role, hash_password}.

    v2.0: authenticate() mendukung limiter per-username (lockout) dan
    anti user-enumeration (waktu respons pemakai tak dikenal dibuat
    setara dengan pemakai salah-sandi via PBKDF2 dummy).
    """

    def __init__(self):
        self._pengguna = {}
        self._dummy_hash = None

    def _hash_dummy(self):
        if self._dummy_hash is None:
            # Dibuat SEKALI per proses (PBKDF2 mahal; bukan per-login).
            self._dummy_hash = hash_password("dummy-timing-pad")
        return self._dummy_hash

    def add_user(self, username, password, role):
        if role not in ROLES:
            raise ValueError(f"role tidak valid: {role}")
        if username in self._pengguna:
            raise ValueError(f"username sudah ada: {username}")
        self._pengguna[username] = {
            "role": role,
            "hash": hash_password(password),
        }

    def authenticate(self, username, password, limiter=None):
        """Kembalikan role bila sah; None bila gagal/terkunci.

        limiter: audit_core.RateLimiter opsional — kunci = username;
        setelah `maks` upaya gagal dalam jendela, upaya berikutnya
        (BENAR sekalipun) ditolak sampai jendela bergulir.
        """
        u = self._pengguna.get(username)
        if limiter is not None and not limiter.allow(username):
            return None
        if u is None:
            # anti-enumeration: waktu ~setara dengan pemakai nyata
            verify_password(password, self._hash_dummy())
            return None
        if verify_password(password, u["hash"]):
            return u["role"]
        return None

    def authorize(self, role, permission):
        """True bila role memiliki permission."""
        return role in IZIN.get(permission, ())

    def n_pengguna(self):
        return len(self._pengguna)
