"""credcheck.py — Asesmen keamanan kredensial LAB (100% SINTETIS).

TIDAK menyentuh kredensial nyata: kredensial uji dibuang-buat
(disposable), aplikasi uji memang sengaja dibuat rentan, dan semua
bukti DIMATIKAN (masked) — nilai rahasia asli tidak pernah muncul.

Kemampuan:
- generate kredensial sintetis sekali-pakai (username/password/token).
- Deteksi pola secret + heuristik entropi pada teks konfigurasi/log uji.
- VulnTestApp: aplikasi uji sengaja rentan (IDOR, session expiration,
  batas otorisasi) — semua disengaja untuk pembelajaran.
- run_assessment(): bukti ter-mask, klasifikasi severity, rekomendasi,
  dan verifikasi 'no_secret_leak' bahwa tidak ada nilai rahasia
  yang bocor dalam laporan.

v2.0: mask() memakai kebijakan "ketat" secara DEFAULT — potongan awal/akhir
nilai rahasia tidak lagi ditampilkan (prefix/suffix bisa membantu tebakan);
hanya panjang + asterisk. Mode "ringan" (tampilan lama) masih tersedia
untuk kompatibilitas.
"""

import argparse
import json
import math
import re
import secrets
import string
import time
from collections import Counter

# ------------------------------------------------------------
# Kredensial sintetis sekali-pakai
# ------------------------------------------------------------
def generate_credentials(n=3):
    """Buat n set kredensial sintetis (tidak dipakai di sistem nyata)."""
    hasil = []
    for i in range(n):
        pwd = ("Lab-" + secrets.token_urlsafe(12))
        token = secrets.token_hex(16)
        hasil.append({
            "username": f"labuser-{i:02d}",
            "password": pwd,
            "token": token,
        })
    return hasil


def mask(nilai, kebijakan="ketat"):
    """Matikan nilai rahasia sebelum masuk bukti/laporan.

    kebijakan="ketat" (DEFAULT v2.0): TIDAK ada potongan awal/akhir
    yang bisa dipakai menebak/mengurai nilai — hanya asterisk + panjang.
    kebijakan="ringan": kompatibel tampilan lama (2 char awal + akhir).
    """
    s = str(nilai)
    if len(s) <= 4:
        return "*" * len(s)
    if kebijakan == "ringan":
        return s[:2] + "…" + s[-2:]
    # ketat (default)
    return "*" * min(len(s), 8) + f" (len={len(s)})"


# ------------------------------------------------------------
# Deteksi pola secret (6 pola) + entropi
# ------------------------------------------------------------
POLA_SECRET = [
    ("password_assignment", re.compile(r"(?i)(?:db_)?password\s*[=:]\s*['\"]?(\S{6,})")),
    ("api_key", re.compile(r"(?i)api[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})")),
    ("bearer_token", re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-.=]{16,})")),
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{12,16})\b")),
    ("private_key_header", re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)")),
    ("session_cookie", re.compile(r"(?i)(?:session|jwt)[_\-]?(?:id|token)?\s*[=:]\s*['\"]?([A-Za-z0-9_\-.]{20,})")),
]


def shannon_entropy(s):
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan_text(teks, label=""):
    """Cari secret dalam teks uji; bukti dimask. Heuristik entropi utk string panjang."""
    temuan = []
    for nama, pola in POLA_SECRET:
        for m in pola.finditer(teks):
            nilai = m.group(1) if m.lastindex else m.group(0)
            nilai = nilai.strip("'\"")
            temuan.append({
                "pola": nama, "sev": "KRITIS",
                "bukti": mask(nilai),
                "lokasi": label,
                "rekomendasi": "pindah ke vault/variabel lingkungan; "
                               "rotasi nilai; tambah .gitignore",
            })
    # heuristik entropi: string panjang acak tanpa konteks
    for m in re.finditer(r"['\"]([A-Za-z0-9+/=_\-]{24,})['\"]", teks):
        nilai = m.group(1)
        if shannon_entropy(nilai) > 4.5:
            temuan.append({
                "pola": "high_entropy_string", "sev": "TINGGI",
                "bukti": mask(nilai),
                "lokasi": label,
                "rekomendasi": "string acak panjang di file teks — "
                               "periksa apakah kunci/sandi",
            })
    return temuan


# ------------------------------------------------------------
# Aplikasi uji yang SENGAJA rentan
# ------------------------------------------------------------
class VulnTestApp:
    """Aplikasi uji kecil dengan 3 kelemahan SENGAJA:
    1. IDOR: dokumen bisa dibaca tanpa cek kepemilikan.
    2. Session tidak berakhir setelah logout / TTL lewat.
    3. Otorisasi: role 'guest' bisa memanggil aksi admin.
    """

    def __init__(self, kreds, session_ttl=0.1):
        self.users = {k["username"]: k["password"] for k in kreds}
        self.docs = {f"doc-{i}": f"milik-{u}" for i, u in
                     enumerate(self.users.keys())}
        self.sessions = {}
        self.session_ttl = session_ttl

    def login(self, username, password):
        if self.users.get(username) == password:
            sid = secrets.token_hex(8)
            self.sessions[sid] = {"user": username, "t": time.monotonic()}
            return sid
        return None

    def get_document(self, sid, doc_id):
        # KELEMAHAN SENGAJA (IDOR): tidak ada cek self.docs[doc_id]
        # milik session user — dokumen siapa pun bisa dibaca.
        if sid not in self.sessions:
            return None
        return self.docs.get(doc_id)

    def is_session_valid(self, sid):
        s = self.sessions.get(sid)
        if s is None:
            return False
        return (time.monotonic() - s["t"]) <= self.session_ttl

    def aksi_admin(self, sid):
        # KELEMAHAN SENGAJA: tidak ada cek role — sesi valid mana pun
        # (termasuk guest) bisa menjalankan aksi admin.
        return "OK" if sid in self.sessions else "DENIED"


# ------------------------------------------------------------
# Asesmen lengkap
# ------------------------------------------------------------
def run_assessment():
    """Jalankan asesmen; kembalikan laporan (tanpa nilai rahasia asli)."""
    kreds = generate_credentials(3)

    # Teks uji sengaja berisi secret sintetis (menyerupai file config nyata)
    config_teks = (
        "# konfigurasi lab-app (SINTETIS)\n"
        f"db_password = '{kreds[0]['password']}'\n"
        f"api_key = 'ak_live_{kreds[1]['token'][:16]}'\n"
        f"session_token = '{kreds[2]['token']}'\n"
        "Authorization: Bearer eyJhbGciOiJTE5.eyJzdWIiOiJsYWIifQ.SYNTH\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
    )
    log_teks = (
        f"[auth] login labuser-00 password={kreds[0]['password']} "
        "status=OK\n"  # KELEMAHAN SENGAJA: password tercatat di log
    )

    temuan_config = scan_text(config_teks, "config_lab.txt")
    temuan_log = scan_text(log_teks, "app_debug.log")

    app = VulnTestApp(kreds, session_ttl=0.1)
    sid = app.login(kreds[0]["username"], kreds[0]["password"])

    # Uji IDOR: user pertama membaca dokumen milik user lain
    idor = app.get_document(sid, "doc-2")  # milik labuser-02, bukan labuser-00
    idor_status = "VULNERABLE" if idor else "OK"
    if idor_status == "VULNERABLE":
        temuan_config.append({
            "pola": "idor_access_control", "sev": "KRITIS",
            "bukti": f"doc-02 dibaca tanpa cek kepemilikan (dibaca: {idor})",
            "lokasi": "VulnTestApp.get_document",
            "rekomendasi": "cek kepemilikan dokumen per-request "
                           "(deny by default)",
        })

    # Uji session expiration
    time.sleep(0.15)
    session_status = "VULNERABLE" if app.is_session_valid(sid) else "OK"
    if session_status == "VULNERABLE":
        temuan_config.append({
            "pola": "session_no_expiry", "sev": "TINGGI",
            "bukti": "session masih valid setelah TTL",
            "lokasi": "VulnTestApp.is_session_valid",
            "rekomendasi": "hapus session saat logout & TTL ketat",
        })

    # Uji batas otorisasi (guest memanggil aksi admin)
    sid2 = app.login(kreds[1]["username"], kreds[1]["password"])
    hasil_admin = app.aksi_admin(sid2)
    authz_status = "VULNERABLE" if hasil_admin == "OK" else "OK"
    if authz_status == "VULNERABLE":
        temuan_config.append({
            "pola": "missing_authz_check", "sev": "KRITIS",
            "bukti": "aksi admin dijalankan tanpa cek role",
            "lokasi": "VulnTestApp.aksi_admin",
            "rekomendasi": "terapkan RBAC + cek role di setiap aksi istimewa",
        })

    semua_temuan = temuan_config + temuan_log

    # Verifikasi jujur: TIDAK ADA nilai rahasia sintetis yang muncul polos
    laporan_teks = json.dumps(semua_temuan, ensure_ascii=False)
    bocor = [k["username"] for k in kreds
             if k["password"] in laporan_teks or k["token"] in laporan_teks]
    no_leak = not bocor

    per_sev = Counter(t["sev"] for t in semua_temuan)
    return {
        "modul": "credcheck",
        "target": "aplikasi uji sintetis (VulnTestApp) — bukan sistem nyata",
        "n_kreds_sintetis": len(kreds),
        "temuan": semua_temuan,
        "ringkasan": {
            "total": len(semua_temuan),
            "per_severity": dict(per_sev),
            "idor": idor_status,
            "session_expiration": session_status,
            "authz_boundary": authz_status,
            "no_secret_leak_verified": no_leak,
        },
        "catatan": "Semua kredensial adalah SINTETIS dan dibuang setelah "
                   "asesmen; bukti dimask (kebijakan ketat: tanpa potongan "
                   "awal/akhir). Tidak ada kredensial nyata yang disentuh.",
    }


def main():
    ap = argparse.ArgumentParser(
        description="credcheck v2.0 (lab) — asesmen keamanan kredensial "
                    "100% sintetis (IDOR, session, authz, secret scanning).")
    ap.add_argument("--out", default="cred_report.json")
    args = ap.parse_args()

    laporan = run_assessment()
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(laporan, f, indent=2, ensure_ascii=False)

    r = laporan["ringkasan"]
    print("=" * 62)
    print(" CRED CHECK — Laporan Asesmen (100% sintetis)")
    print("=" * 62)
    print(f"  Temuan total     : {r['total']}  {r['per_severity']}")
    print(f"  IDOR             : {r['idor']}")
    print(f"  Session expiry   : {r['session_expiration']}")
    print(f"  Authz boundary   : {r['authz_boundary']}")
    print(f"  No-secret-leak   : {r['no_secret_leak_verified']}")
    print("  Detail per temuan:")
    for t in laporan["temuan"]:
        print(f"    [{t['sev']}] {t['pola']} @ {t['lokasi']} "
              f"— bukti: {t['bukti']}")
        print(f"           -> {t['rekomendasi']}")
    print("=" * 62)
    print(f"  Laporan JSON: {args.out}")
    print("  Catatan: bukti dimask; nilai rahasia tidak pernah ditulis polos.")


if __name__ == "__main__":
    main()
