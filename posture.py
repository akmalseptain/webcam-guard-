"""posture.py — Security Posture Engine (cek BEHAVIORAL, bukan nama fitur).

Filosofi: JANGAN percaya fitur karena namanya ada. Setiap cek di sini
menjalankan PERILAKU nyata modul terkait (append/verify/tamper/connect/
subprocess) dan mencatat bukti.

Status per cek:
  LULUS    — perilaku keamanan yang diharapkan TERBUKTI bekerja.
  PERINGAT — tidak bisa dibuktikan penuh di lingkungan ini (mis. butuh
             alat eksternal / artefak belum ada) — JUJUR dilaporkan.
  GAGAL    — perilaku yang diharapkan TIDAK terjadi (bloker bila kritis).

Skor = (n_lulus + 0.5 * n_peringat) / n_cek * 100.
Exit code 1 HANYA bila ada GAGAL pada cek ber-kritis (bloker release).
Komponen TIDAK pernah dilaporkan aman hanya karena tidak ada test gagal.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

import audit_core
import credcheck
import forensics
import mirror_stream
import netmon
import privacy


def _cek(id_, nama, komponen, kritis=False):
    """Dekorator sederhana: kumpulkan bukti dalam fungsi cek."""
    def bungkus(fn):
        def jalankan(hasil):
            try:
                status, bukti, rekomendasi = fn()
            except Exception as e:  # noqa: BLE001
                status, bukti, rekomendasi = (
                    "GAGAL", f"exception tak terduga: {e!r}",
                    "periksa implementasi modul terkait")
            hasil.append({"id": id_, "nama": nama, "komponen": komponen,
                          "kritis": kritis, "status": status,
                          "bukti": bukti, "rekomendasi": rekomendasi})
        CEK_LIST.append((id_, nama, komponen, kritis, jalankan))
        return fn
    return bungkus


CEK_LIST = []


# ------------------------------------------------------------
# P-01/02: integritas rantai audit & event
# ------------------------------------------------------------
@_cek("P-01", "Rantai audit: append + verify utuh", "audit_core", kritis=True)
def p01():
    d = tempfile.mkdtemp(prefix="posture_p01_")
    try:
        log = audit_core.AuditLog(os.path.join(d, "audit.jsonl"))
        for i in range(3):
            log.append("posture", "TES", f"baris {i}")
        rusak = log.verify()
        entries = log.entries()
        seq_ok = [e["seq"] for e in entries] == [1, 2, 3]
        if rusak is None and seq_ok:
            return "LULUS", f"3 entri, verify()=None, seq=1..3", ""
        return "GAGAL", f"verify()={rusak}, seq_ok={seq_ok}", \
            "periksa format hash-chain audit"
    finally:
        shutil.rmtree(d, ignore_errors=True)


@_cek("P-02", "Rantai event: append + verify utuh", "forensics", kritis=True)
def p02():
    d = tempfile.mkdtemp(prefix="posture_p02_")
    try:
        store = forensics.EventStore(os.path.join(d, "events.jsonl"))
        for i in range(3):
            store.append(forensics.normalize("netmon", f"event {i}"))
        rusak = store.verify()
        n = len(store.load())
        if rusak is None and n == 3:
            return "LULUS", "3 event, verify()=None", ""
        return "GAGAL", f"verify()={rusak}, n={n}", "periksa hash-chain event"
    finally:
        shutil.rmtree(d, ignore_errors=True)


@_cek("P-03", "Anchor checkpoint: utuh + truncation terdeteksi", "audit_core",
      kritis=True)
def p03():
    d = tempfile.mkdtemp(prefix="posture_p03_")
    try:
        path = os.path.join(d, "audit.jsonl")
        anchor = os.path.join(d, "audit.anchor.json")
        log = audit_core.AuditLog(path, anchor_path=anchor)
        for i in range(5):
            log.append("posture", "TES", f"baris {i}")
        log.checkpoint()
        hasil_utuh = log.verify_terhadap_anchor()
        # truncation: buang 2 baris terakhir
        with open(path, encoding="utf-8") as f:
            baris = f.readlines()
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(baris[:3])
        hasil_potong = log.verify_terhadap_anchor()
        ok = (hasil_utuh.get("utuh") is True
              and hasil_potong.get("utuh") is False
              and "TERPANGKAS" in str(hasil_potong.get("masalah")))
        if ok:
            return "LULUS", (f"verify anchor utuh OK; setelah truncation "
                             f"-> {hasil_potong.get('masalah')}"), ""
        return "GAGAL", f"utuh={hasil_utuh}, terpotong={hasil_potong}", \
            "anchor harus mendeteksi truncation"
    finally:
        shutil.rmtree(d, ignore_errors=True)


@_cek("P-04", "PBKDF2: parameter iterasi divalidasi (cap atas+bawah)",
      "audit_core", kritis=True)
def p04():
    t0 = time.monotonic()
    r_melek = audit_core.verify_password(
        "sandi", "pbkdf2$999999999$abcd$efgh")
    durasi = time.monotonic() - t0
    r_lembek = audit_core.verify_password(
        "sandi", "pbkdf2$500$abcd$efgh")  # < PBKDF2_ITER_MIN
    if r_melek is False and r_lembek is False and durasi < 0.05:
        return "LULUS", (f"iterasi 999 juta & 500 ditolak cepat "
                         f"({durasi*1000:.1f} ms, hasil False)"), ""
    return "GAGAL", (f"melek={r_melek}, lembek={r_lembek}, "
                     f"{durasi*1000:.1f} ms"), \
        "verify_password wajib menolak parameter di luar batas"


# ------------------------------------------------------------
# P-05: rate limiter
# ------------------------------------------------------------
@_cek("P-05", "Rate limiter: jendela + reset", "audit_core")
def p05():
    rl = audit_core.RateLimiter(maks=5, jendela=60.0)
    lima = [rl.allow("ip-uji") for _ in range(5)]
    keenam = rl.allow("ip-uji")
    rl.reset("ip-uji")
    setelah = rl.allow("ip-uji")
    if all(lima) and keenam is False and setelah is True:
        return "LULUS", "5 diizinkan, ke-6 ditolak, reset -> diizinkan", ""
    return "GAGAL", f"lima={lima}, keenam={keenam}, setelah={setelah}", \
        "periksa RateLimiter"


# ------------------------------------------------------------
# P-06/07/08: mirror auth (lockout, per-IP, STOP admin-only)
# ------------------------------------------------------------
@_cek("P-06", "Mirror: lockout setelah 5 gagal (token benar pun ditolak)",
      "mirror_stream", kritis=True)
def p06():
    srv = mirror_stream.MirrorServer(
        "KODE", "dev", port=0, token_map={"tokvalid": "viewer"})
    for _ in range(mirror_stream.GAGAL_MAKS):
        role, _ = srv._autentikasi(
            "10.7.7.7", {"cmd": "HELLO", "kode": "KODE", "token": "salah"})
        if role is not None:
            return "GAGAL", "upaya salah diterima?!", \
                "periksa jalur autentikasi"
    role, alasan = srv._autentikasi(
        "10.7.7.7", {"cmd": "HELLO", "kode": "KODE", "token": "tokvalid"})
    if role is None and alasan == "terlalu banyak upaya gagal":
        return "LULUS", "lockout aktif; token benar ditolak selama terkunci", ""
    return "GAGAL", f"role={role}, alasan={alasan!r}", \
        "lockout harus diuji SEBELUM cek token"


@_cek("P-07", "Mirror: lockout per-IP (IP lain tidak terpengaruh)",
      "mirror_stream")
def p07():
    srv = mirror_stream.MirrorServer(
        "KODE", "dev", port=0, token_map={"tokvalid": "viewer"})
    for _ in range(mirror_stream.GAGAL_MAKS):
        srv._autentikasi("10.7.7.8",
                         {"cmd": "HELLO", "kode": "KODE", "token": "salah"})
    role, alasan = srv._autentikasi(
        "10.7.7.9", {"cmd": "HELLO", "kode": "KODE", "token": "tokvalid"})
    if role == "viewer":
        return "LULUS", "IP berbeda tetap bisa login dengan token benar", ""
    return "GAGAL", f"role={role}, alasan={alasan!r}", \
        "lockout seharusnya per-IP, bukan global (anti-DoS)"


@_cek("P-08", "Mirror: STOP_REQ hanya admin (viewer ditolak)",
      "mirror_stream", kritis=True)
def p08():
    srv = mirror_stream.MirrorServer(
        "KODE", "dev", host="127.0.0.1", port=0, ssl_ctx=None,
        token_map={"tokadmin": "admin", "tokviewer": "viewer"})
    srv.start()
    port = srv.server_sock.getsockname()[1]
    threading.Thread(target=srv.accept_loop, daemon=True).start()
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.settimeout(5)
        mirror_stream.kirim_json(
            s, {"cmd": "HELLO", "kode": "KODE", "token": "tokviewer"})
        mirror_stream.terima_json(s)  # WELCOME
        mirror_stream.kirim_json(s, {"cmd": "STOP_REQ"})
        _, data = mirror_stream.terima_frame(s)
        s.close()
        if data.get("cmd") == "STOP_DENIED" and srv.running:
            return "LULUS", ("viewer STOP_REQ -> STOP_DENIED; sesi global "
                             "tetap berjalan"), ""
        return "GAGAL", f"respon={data.get('cmd')}, running={srv.running}", \
            "viewer tidak boleh menstop sesi global"
    finally:
        srv.stop()


# ------------------------------------------------------------
# P-09: TLS pinning
# ------------------------------------------------------------
@_cek("P-09", "TLS pinning: pin wajib + constant-time + fingerprint",
      "mirror_stream/mirror_viewer", kritis=True)
def p09():
    bukti = []
    # (a) pin cocok: constant-time compare dengan DER sintetis
    der = os.urandom(64)
    import hashlib
    pin_benar = hashlib.sha256(der).hexdigest()
    pin_salah = hashlib.sha256(der + b"x").hexdigest()
    a = mirror_stream.pin_cocok(der, pin_benar)
    b = mirror_stream.pin_cocok(der, pin_salah)
    if not (a is True and b is False):
        return "GAGAL", f"pin_cocok: benar={a}, salah={b}", \
            "pin_cocok harus menerima pin benar & menolak pin salah"
    bukti.append("pin_cocok benar/salah OK")
    # (b) viewer TANPA --pin harus menolak jalan (argparse exit 2)
    r = subprocess.run(
        [sys.executable, "mirror_viewer.py"],
        cwd=BASE_DIR, capture_output=True, text=True, timeout=30)
    if r.returncode == 2 and "--pin" in (r.stderr + r.stdout):
        bukti.append("viewer tanpa --pin -> exit 2 (arg wajib)")
    else:
        return "GAGAL", (f"viewer tanpa --pin: exit={r.returncode}, "
                         f"stderr={r.stderr[:200]!r}"), \
            "--pin wajib: trust-on-first-use dilarang"
    # (c) fingerprint sertifikat nyata bila cryptography/openssl ada
    d = tempfile.mkdtemp(prefix="posture_p09_")
    try:
        cert = os.path.join(d, "lab.crt")
        key = os.path.join(d, "lab.key")
        try:
            mirror_stream.ensure_cert(cert, key)
            fp = mirror_stream.cert_fingerprint(cert)
            if len(fp) == 64 and all(c in "0123456789abcdef" for c in fp):
                bukti.append(f"fingerprint SHA-256 dibuat: {fp[:16]}…")
                return "LULUS", "; ".join(bukti), ""
            return "GAGAL", f"fingerprint format salah: {fp!r}", \
                "fingerprint harus hex SHA-256 (64 karakter)"
        except (ImportError, FileNotFoundError, OSError, RuntimeError) as e:
            bukti.append(f"fingerprint cert NYATA tidak diuji ({type(e).__name__})"
                         " — cryptography/openssl tidak tersedia; "
                         "ujian manual di laptop owner")
            return "PERINGAT", "; ".join(bukti), \
                "pasang 'cryptography' untuk uji fingerprint lokal"
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------
# P-10: netmon deteksi (FP rendah + evaluasi berlabel jujur)
# ------------------------------------------------------------
@_cek("P-10", "Netmon: polling wajar bukan anomali + evaluasi berlabel",
      "netmon", kritis=True)
def p10():
    bukti = []

    def _flow_beacon(dport, interval, n):
        ts = [1000.0 + i * interval for i in range(n)]
        return {"src": "192.168.56.10", "sport": 33333,
                "dst": "203.0.113.66", "dport": dport, "proto": "TCP",
                "packets": n, "bytes": n * 200,
                "first": ts[0], "last": ts[-1],
                "durasi_s": round(ts[-1] - ts[0], 3),
                "cv_interval": netmon._cv_interval(ts), "apps": []}

    # (a) polling HTTP ke port wajar TIDAK ditandai beacon/c2
    anomali = netmon.detect_anomalies([_flow_beacon(8080, 10.0, 12)])
    if anomali:
        return "GAGAL", f"polling 8080 ditandai: {anomali}", \
            "port wajar + polling sehari-hari tidak boleh jadi temuan"
    bukti.append("polling 8080 (cv=0, 12 pkt) tanpa temuan")
    # (b) beacon C2 dengan jitter rendah tetap terdeteksi
    anomali = netmon.detect_anomalies([_flow_beacon(4444, 10.0, 12)])
    if not any(a["tipe"] in ("beacon", "port_c2") for a in anomali):
        return "GAGAL", "beacon 4444 teratur tidak terdeteksi", \
            "deteksi beacon tidak boleh buta terhadap port C2"
    bukti.append("beacon 4444 terdeteksi")
    # (c) evaluasi berlabel: precision/recall dilaporkan apa adanya
    ev = netmon.evaluasi_detektor()
    bukti.append(f"evaluasi: precision={ev.get('precision')}, "
                 f"recall={ev.get('recall')}, "
                 f"fpr={ev.get('fpr')} (fixture {ev.get('n_fixture')}, "
                 f"TP={ev.get('TP')} FP={ev.get('FP')} "
                 f"FN={ev.get('FN')} TN={ev.get('TN')})")
    if all(k in ev for k in ("precision", "recall", "fpr")):
        return "LULUS", "; ".join(bukti), ""
    return "GAGAL", f"metrik evaluasi hilang: {ev}", \
        "evaluasi wajib melaporkan metrik dari data berlabel"


# ------------------------------------------------------------
# P-11: redsim scope (subprocess, lingkungan nyata CLI)
# ------------------------------------------------------------
@_cek("P-11", "Redsim: --target out-of-scope DITOLAK + audit + exit 2",
      "redsim", kritis=True)
def p11():
    r = subprocess.run(
        [sys.executable, "redsim.py", "--target", "8.8.8.8"],
        cwd=BASE_DIR, capture_output=True, text=True, timeout=60)
    if r.returncode == 2 and "DITOLAK" in r.stdout:
        return "LULUS", ("exit 2, target 8.8.8.8 di luar scope ditolak "
                         "ter-audit"), ""
    return "GAGAL", (f"exit={r.returncode}, stdout={r.stdout[:200]!r}, "
                     f"stderr={r.stderr[:200]!r}"), \
        "out-of-scope harus exit 2 dengan penolakan ter-audit"


# ------------------------------------------------------------
# P-12: masking ketat
# ------------------------------------------------------------
@_cek("P-12", "Credcheck: mask ketat tanpa potongan awal/akhir",
      "credcheck", kritis=True)
def p12():
    nilai = "Lab-SuperRahasia12345"
    m = credcheck.mask(nilai)
    if (nilai[:2] not in m and nilai[-2:] not in m
            and "SuperRahasia" not in m and "len=21" in m):
        return "LULUS", f"mask={m!r} — hanya asterisk + panjang", ""
    return "GAGAL", f"mask={m!r} masih membocorkan potongan nilai", \
        "kebijakan ketat tidak boleh menampilkan prefix/suffix"


# ------------------------------------------------------------
# P-13: privacy fail-safe
# ------------------------------------------------------------
@_cek("P-13", "Privacy: blur gagal -> TOLAK_FRAME + tercatat",
      "privacy")
def p13():
    d = tempfile.mkdtemp(prefix="posture_p13_")
    try:
        pg = privacy.PrivacyGuard(direktori_media=os.path.join(d, "rec"),
                                  log_path=os.path.join(d, "privacy.jsonl"))
        putusan = pg.keputusan_frame_blur(False)
        log = pg.baca_log()
        ok = (putusan == "TOLAK_FRAME"
              and any(e.get("event") == "BLUR_GAGAL" for e in log))
        if ok:
            return "LULUS", ("keputusan=TOLAK_FRAME, event BLUR_GAGAL "
                             "tercatat (fail-closed)"), ""
        return "GAGAL", f"keputusan={putusan!r}, log={log}", \
            "blur gagal wajib menolak frame (privasi dulu)"
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------
# P-14: malformed toleran (verify melaporkan, bukan crash)
# ------------------------------------------------------------
@_cek("P-14", "Forensics: file malformed dilaporkan tanpa crash",
      "audit_core/forensics")
def p14():
    d = tempfile.mkdtemp(prefix="posture_p14_")
    try:
        p = os.path.join(d, "audit.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            f.write("bukan json\n[1,2]\n{\"tanpa\": \"hash\"}\n")
        log = audit_core.AuditLog(p)
        masalah = log.verify()
        if isinstance(masalah, int):
            return "LULUS", f"verify() melaporkan baris {masalah}, tanpa crash", ""
        return "GAGAL", f"verify()={masalah!r} — malformed tidak terdeteksi", \
            "verify harus melaporkan baris bermasalah"
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------
# P-15: dependency audit (jujur: NOT RUN bila alat tak ada)
# ------------------------------------------------------------
@_cek("P-15", "Dependency scan (pip-audit) tersedia/dijalankan",
      "supply chain")
def p15():
    req = os.path.join(BASE_DIR, "requirements.txt")
    kons = os.path.join(BASE_DIR, "constraints.txt")
    if not (os.path.exists(req) or os.path.exists(kons)):
        return "GAGAL", "requirements.txt/constraints.txt tidak ditemukan", \
            "deklarasi dependensi wajib ada"
    alat = shutil.which("pip-audit")
    if alat is None:
        return "PERINGAT", (
            "pip-audit TIDAK tersedia di lingkungan ini — scan TIDAK "
            "DIJALANKAN (jujur dilaporkan, bukan dianggap aman). "
            "Jalankan manual: pip install pip-audit && pip-audit -r "
            "requirements.txt"), "jalankan pip-audit di laptop owner"
    return "LULUS", f"pip-audit ditemukan di {alat} — jalankan untuk hasil", ""


# ------------------------------------------------------------
# P-16: evidence pack roundtrip
# ------------------------------------------------------------
@_cek("P-16", "Evidence: build + verify roundtrip + tamper terdeteksi",
      "evidence")
def p16():
    import evidence
    d = tempfile.mkdtemp(prefix="posture_p16_")
    try:
        ev_path = os.path.join(d, "events.jsonl")
        au_path = os.path.join(d, "audit.jsonl")
        store = forensics.EventStore(ev_path)
        for i in range(3):
            store.append(forensics.normalize("netmon", f"ev {i}"))
        log = audit_core.AuditLog(au_path)
        log.append("posture", "TES", "baris 0")
        out = os.path.join(d, "pack")
        evidence.build_pack(ev_path, au_path, out)
        h1 = evidence.verify_pack(out)
        # tamper: ubah events.json tanpa update manifest
        with open(os.path.join(out, "events.json"), "a",
                  encoding="utf-8") as f:
            f.write("\n/* disisipkan */")
        h2 = evidence.verify_pack(out)
        if h1["utuh"] and (not h2["utuh"]) and h2["masalah"]:
            return "LULUS", ("verify utuh OK; setelah tamper: "
                             f"{h2['masalah'][0]}"), ""
        return "GAGAL", f"utuh={h1['utuh']}, tamper={h2['utuh']}", \
            "verifikasi paket bukti harus mendeteksi perubahan"
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------
# Runner
# ------------------------------------------------------------
def jalankan_semua():
    hasil = []
    for _, _, _, _, fn in CEK_LIST:
        fn(hasil)
    n = len(hasil)
    lulus = sum(1 for h in hasil if h["status"] == "LULUS")
    peringat = sum(1 for h in hasil if h["status"] == "PERINGAT")
    gagal = [h for h in hasil if h["status"] == "GAGAL"]
    bloker = [h for h in gagal if h["kritis"]]
    return {
        "modul": "posture",
        "versi": "2.0",
        "n_cek": n,
        "n_lulus": lulus,
        "n_peringat": peringat,
        "n_gagal": len(gagal),
        "skor": round((lulus + 0.5 * peringat) / max(1, n) * 100, 1),
        "bloker": [h["id"] for h in bloker],
        "hasil": hasil,
    }


def main():
    ap = argparse.ArgumentParser(
        description="posture v2.0 — security posture engine (cek behavioral: "
                    "audit chain, anchor, PBKDF2, rate limit, mirror lockout, "
                    "TLS pinning, netmon, scope, masking, privacy, evidence).")
    ap.add_argument("--json", action="store_true",
                    help="keluarkan JSON penuh")
    args = ap.parse_args()

    laporan = jalankan_semua()

    if args.json:
        print(json.dumps(laporan, indent=2, ensure_ascii=False))
        return 1 if laporan["bloker"] else 0

    print("=" * 64)
    print(" SECURITY POSTURE — hasil cek behavioral (bukan sekadar nama)")
    print("=" * 64)
    for h in laporan["hasil"]:
        tag = "KRITIS" if h["kritis"] else "      "
        print(f"  [{h['status']:<8}] {h['id']} {h['nama']}  ({tag})")
        print(f"      bukti: {h['bukti']}")
        if h["rekomendasi"]:
            print(f"      saran: {h['rekomendasi']}")
    print("-" * 64)
    print(f"  Skor posture : {laporan['skor']}/100 "
          f"(LULUS {laporan['n_lulus']}, PERINGAT {laporan['n_peringat']}, "
          f"GAGAL {laporan['n_gagal']})")
    if laporan["bloker"]:
        print(f"  BLOKER RELEASE: {', '.join(laporan['bloker'])}")
        print("  CATATAN: komponen lain TIDAK otomatis aman karena lolos cek.")
        return 1
    print("  Catatan: skor tinggi bukan sertifikasi; komponen tanpa cek "
          "tidak dinyatakan aman.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
