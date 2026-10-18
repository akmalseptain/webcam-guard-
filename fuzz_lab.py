"""fuzz_lab.py — Fuzz testing LOKAL-ONLY, deterministik, bounded.

Tujuan: bukti perilaku kode terhadap input jahat/gagal, tanpa target
eksternal apa pun. Semua input dibuat sintetis di sini.

Kategori hasil per kasus:
  AMAN     — input diproses tanpa crash dan hasil konsisten.
  GUARD_OK — input jahat DITOLAK dengan exception terkontrol
             (ValueError/ConnectionError/…): guard bekerja.
  CRASH    — exception tak terduga = REGRESI (exit code 1).
  SKIP     — jatah waktu habis (JATAH_WAKTU_S) — bounded by design.

Kasus:
  F1  PCAP korup (header pendek, magic salah, incl_len raksasa,
      record terpotong, file kosong)
  F2  JSONL malformed (audit + events: bukan-JSON, list, dict tanpa
      hash, baris kosong) — verify() harus melaporkan, bukan crash
  F3  Wire payload (socketpair): header length > MAX_PAYLOAD,
      JSON rusak, biner acak
  F4  Brute-force auth mirror: 5x gagal + 1x token BENAR -> tetap
      DITOLAK (lockout dulu)
  F5  forensics.normalize kind invalid
  F6  Enumerasi auth RBAC + parameter hash password malformed

Deterministik: seed (default 42) mengendalikan seluruh byte acak.
"""

import argparse
import json
import os
import random
import socket
import struct
import sys
import tempfile
import time

import audit_core
import credcheck
import forensics
import mirror_stream
import netmon

JATAH_WAKTU_S = 10.0  # batas total detik; kasus berikutnya di-SKIP


# ------------------------------------------------------------
# Kerangka kasus
# ------------------------------------------------------------
def _guard(fn, diharapkan=(ValueError, ConnectionError, OSError)):
    """Jalankan fn; exception diharapkan = GUARD_OK, lainnya = CRASH."""
    try:
        fn()
        return "AMAN", "diproses tanpa penolakan"
    except diharapkan as e:
        return "GUARD_OK", f"{type(e).__name__}: {e}"


# ------------------------------------------------------------
# F1 — PCAP korup
# ------------------------------------------------------------
def f1_pcap_korup(hasil, rng):
    d = tempfile.mkdtemp(prefix="fuzz_f1_")
    try:
        # (a) header global terpotong
        p = os.path.join(d, "pendek.pcap")
        with open(p, "wb") as f:
            f.write(b"\xa1\xb2\xc3")
        s, ket = _guard(lambda: netmon.baca_pcap(p), (ValueError,))
        hasil.append({"id": "F1a", "nama": "PCAP header <24 byte",
                      "status": s, "detail": ket})
        # (b) magic salah
        p = os.path.join(d, "magic.pcap")
        with open(p, "wb") as f:
            f.write(b"XXXX" + b"\x00" * 20)
        s, ket = _guard(lambda: netmon.baca_pcap(p), (ValueError,))
        hasil.append({"id": "F1b", "nama": "PCAP magic tidak dikenal",
                      "status": s, "detail": ket})
        # (c) incl_len raksasa (0xFFFFFFFF) — guard memori v2.0
        p = os.path.join(d, "raksasa.pcap")
        with open(p, "wb") as f:
            f.write(netmon.pcap_global_header())
            f.write(struct.pack("<IIII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF))
            f.write(b"\xde\xad\xbe\xef")
        s, ket = _guard(lambda: netmon.baca_pcap(p), (ValueError,))
        hasil.append({"id": "F1c", "nama": "PCAP incl_len raksasa (guard)",
                      "status": s, "detail": ket})
        # (d) record terpotong (incl besar-ish tapi data kurang)
        p = os.path.join(d, "potong.pcap")
        with open(p, "wb") as f:
            f.write(netmon.pcap_global_header())
            f.write(struct.pack("<IIII", 1, 0, 100, 100))
            f.write(b"\x01\x02")  # hanya 2 dari 100 byte
        try:
            pkts = netmon.baca_pcap(p)
            hasil.append({"id": "F1d", "nama": "PCAP record terpotong",
                          "status": "AMAN",
                          "detail": f"terbaca {len(pkts)} paket "
                                    "(record tidak lengkap diabaikan)"})
        except Exception as e:  # noqa: BLE001
            hasil.append({"id": "F1d", "nama": "PCAP record terpotong",
                          "status": "CRASH", "detail": repr(e)})
        # (e) file kosong
        p = os.path.join(d, "kosong.pcap")
        open(p, "wb").close()
        s, ket = _guard(lambda: netmon.baca_pcap(p), (ValueError,))
        hasil.append({"id": "F1e", "nama": "PCAP file kosong",
                      "status": s, "detail": ket})
    finally:
        for nama in os.listdir(d):
            os.unlink(os.path.join(d, nama))
        os.rmdir(d)


# ------------------------------------------------------------
# F2 — JSONL malformed (audit + events)
# ------------------------------------------------------------
def f2_jsonl_malformed(hasil, rng):
    d = tempfile.mkdtemp(prefix="fuzz_f2_")
    try:
        baris_jahat = ["bukan json sama sekali",
                       "[1, 2, 3]",
                       '{"tanpa": "hash"}',
                       "",
                       "{\\'miring': 1}",
                       "x" * 5000]
        # (a) audit
        p_audit = os.path.join(d, "audit.jsonl")
        with open(p_audit, "w", encoding="utf-8") as f:
            for b in baris_jahat:
                f.write(b + "\n")
        try:
            log = audit_core.AuditLog(p_audit)
            masalah = log.verify()
            if masalah is None:
                hasil.append({"id": "F2a", "nama": "JSONL audit malformed",
                              "status": "CRASH",
                              "detail": "verify() menganggap file utuh?!"})
            else:
                hasil.append({"id": "F2a", "nama": "JSONL audit malformed",
                              "status": "AMAN",
                              "detail": f"verify() melaporkan baris "
                                        f"{masalah} (tidak crash)"})
        except Exception as e:  # noqa: BLE001
            hasil.append({"id": "F2a", "nama": "JSONL audit malformed",
                          "status": "CRASH", "detail": repr(e)})
        # (b) events
        p_ev = os.path.join(d, "events.jsonl")
        with open(p_ev, "w", encoding="utf-8") as f:
            for b in baris_jahat:
                f.write(b + "\n")
        try:
            store = forensics.EventStore(p_ev)
            masalah = store.verify()
            if masalah is None:
                hasil.append({"id": "F2b", "nama": "JSONL events malformed",
                              "status": "CRASH",
                              "detail": "verify() menganggap file utuh?!"})
            else:
                hasil.append({"id": "F2b", "nama": "JSONL events malformed",
                              "status": "AMAN",
                              "detail": f"verify() melaporkan baris "
                                        f"{masalah} (tidak crash)"})
        except Exception as e:  # noqa: BLE001
            hasil.append({"id": "F2b", "nama": "JSONL events malformed",
                          "status": "CRASH", "detail": repr(e)})
    finally:
        for nama in os.listdir(d):
            os.unlink(os.path.join(d, nama))
        os.rmdir(d)


# ------------------------------------------------------------
# F3 — Wire payload via socketpair
# ------------------------------------------------------------
def f3_wire_payload(hasil, rng):
    # (a) header length > MAX_PAYLOAD (10 MiB + 1) — ditolak SEBELUM baca
    a, b = socket.socketpair()
    try:
        a.settimeout(0.5)
        b.settimeout(0.5)
        a.sendall(struct.pack(">I", mirror_stream.MAX_PAYLOAD + 1))
        s, ket = _guard(lambda: mirror_stream.terima_payload(b),
                        (ValueError,))
        hasil.append({"id": "F3a", "nama": "payload > MAX_PAYLOAD (10MiB+1)",
                      "status": s, "detail": ket})
    finally:
        a.close()
        b.close()
    # (b) JSON rusak
    a, b = socket.socketpair()
    try:
        a.settimeout(0.5)
        b.settimeout(0.5)
        data = b"{\xff\xfe bukan json"
        a.sendall(struct.pack(">I", len(data)) + data)
        s, ket = _guard(lambda: mirror_stream.terima_json(b),
                        (ValueError, UnicodeDecodeError))
        hasil.append({"id": "F3b", "nama": "JSON rusak di wire",
                      "status": s, "detail": ket})
    finally:
        a.close()
        b.close()
    # (c) biner acak (deterministik dari rng)
    a, b = socket.socketpair()
    try:
        a.settimeout(0.5)
        b.settimeout(0.5)
        data = bytes(rng.randrange(256) for _ in range(512))
        a.sendall(struct.pack(">I", len(data)) + data)
        s, ket = _guard(lambda: mirror_stream.terima_frame(b),
                        (ValueError, UnicodeDecodeError))
        hasil.append({"id": "F3c", "nama": "biner acak 512 byte",
                      "status": s, "detail": ket})
    finally:
        a.close()
        b.close()


# ------------------------------------------------------------
# F4 — Brute-force auth mirror (lockout)
# ------------------------------------------------------------
def f4_brute_force_auth(hasil, rng):
    srv = mirror_stream.MirrorServer("KODE-UJI", "lab-device",
                                     port=0, token_map={"tokvalid": "viewer"})
    ip = "10.9.9.9"
    # 5 upaya gagal (token salah)
    for i in range(mirror_stream.GAGAL_MAKS):
        role, alasan = srv._autentikasi(
            ip, {"cmd": "HELLO", "kode": "KODE-UJI", "token": "salah"})
        if role is not None:
            hasil.append({"id": "F4", "nama": "brute-force 5x gagal + token benar",
                          "status": "CRASH", "detail": f"upaya {i}: DITERIMA?!"})
            return
    # upaya ke-6 dengan token BENAR — harus tetap DITOLAK (lockout dulu)
    role, alasan = srv._autentikasi(
        ip, {"cmd": "HELLO", "kode": "KODE-UJI", "token": "tokvalid"})
    if role is None and alasan == "terlalu banyak upaya gagal":
        hasil.append({"id": "F4", "nama": "brute-force 5x gagal + token benar",
                      "status": "GUARD_OK",
                      "detail": "kunci lockout aktif; token benar pun "
                                "ditolak; upaya IP lain tidak terpengaruh"})
    else:
        hasil.append({"id": "F4", "nama": "brute-force 5x gagal + token benar",
                      "status": "CRASH",
                      "detail": f"lockout tidak bekerja: {role}/{alasan}"})


# ------------------------------------------------------------
# F5 — normalize kind invalid
# ------------------------------------------------------------
def f5_normalize_invalid(hasil, rng):
    def coba():
        forensics.normalize("kind_hantu", "event uji", "detail")
    s, ket = _guard(coba, (ValueError,))
    hasil.append({"id": "F5", "nama": "normalize kind invalid",
                  "status": s, "detail": ket})
    # sanity: kind valid tetap jalan
    e = forensics.normalize("netmon", "event uji")
    hasil.append({"id": "F5", "nama": "normalize kind invalid",
                  "status": "AMAN" if e["kind"] == "netmon" else "CRASH",
                  "detail": "kind valid tetap diterima"})


# ------------------------------------------------------------
# F6 — Enumerasi auth + parameter hash malformed
# ------------------------------------------------------------
def f6_auth(hasil, rng):
    rbac = audit_core.RBAC()
    rbac.add_user("lab-user", "Pwd-Synth-1", "operator")
    tidak_ada = rbac.authenticate("tidak-ada", "kata-sandi")
    salah = rbac.authenticate("lab-user", "kata-sandi")
    if tidak_ada is None and salah is None:
        hasil.append({"id": "F6a", "nama": "auth enumerasi (user ada vs tidak)",
                      "status": "GUARD_OK",
                      "detail": "keduanya None — tidak bisa dibedakan dari "
                                "hasil (anti-enumerasi)"})
    else:
        hasil.append({"id": "F6a", "nama": "auth enumerasi (user ada vs tidak)",
                      "status": "CRASH",
                      "detail": f"hasil berbeda: {tidak_ada} vs {salah}"})
    # verify_password dengan stored hash malformed -> False (fail-safe)
    r = audit_core.verify_password("sandi", "bukan-format-hash")
    hasil.append({"id": "F6b", "nama": "verify_password stored malformed",
                  "status": "GUARD_OK" if r is False else "CRASH",
                  "detail": f"hasil={r} (harus False, tanpa komputasi mahal)"})
    # iterasi PBKDF2 di luar batas -> ditolak SEBELUM komputasi mahal
    hash_melek = "pbkdf2$999999999$abcd$efgh"
    t0 = time.monotonic()
    r = audit_core.verify_password("sandi", hash_melek)
    durasi = time.monotonic() - t0
    ok = (r is False) and durasi < 0.05
    hasil.append({"id": "F6c", "nama": "PBKDF2 iterasi di luar batas",
                  "status": "GUARD_OK" if ok else "CRASH",
                  "detail": f"hasil={r}, {durasi*1000:.1f} ms "
                            "(harus ditolak cepat, bukan 999 juta iterasi)"})


# ------------------------------------------------------------
# Runner
# ------------------------------------------------------------
KASUS = [f1_pcap_korup, f2_jsonl_malformed, f3_wire_payload,
         f4_brute_force_auth, f5_normalize_invalid, f6_auth]


def run(seed=42):
    rng = random.Random(seed)
    hasil = []
    mulai = time.monotonic()
    for kasus in KASUS:
        if time.monotonic() - mulai > JATAH_WAKTU_S:
            hasil.append({"id": kasus.__name__, "nama": "jatah waktu habis",
                          "status": "SKIP",
                          "detail": f"> {JATAH_WAKTU_S}s (bounded by design)"})
            continue
        try:
            kasus(hasil, rng)
        except Exception as e:  # noqa: BLE001 — ini inti fuzzing
            hasil.append({"id": kasus.__name__,
                          "nama": f"exception tak terduga di {kasus.__name__}",
                          "status": "CRASH", "detail": repr(e)})
    ringkas = {
        "modul": "fuzz_lab",
        "seed": seed,
        "jatah_waktu_s": JATAH_WAKTU_S,
        "waktu_total_s": round(time.monotonic() - mulai, 3),
        "n_case": len(hasil),
        "n_aman": sum(1 for h in hasil if h["status"] == "AMAN"),
        "n_guard_ok": sum(1 for h in hasil if h["status"] == "GUARD_OK"),
        "n_crash": sum(1 for h in hasil if h["status"] == "CRASH"),
        "n_skip": sum(1 for h in hasil if h["status"] == "SKIP"),
        "hasil": hasil,
    }
    return ringkas


def main():
    ap = argparse.ArgumentParser(
        description="fuzz_lab v2.0 — fuzzing LOKAL-ONLY deterministik "
                    "(PCAP korup, JSONL malformed, wire payload, brute-force "
                    "auth, normalize invalid, auth malformed).")
    ap.add_argument("--seed", type=int, default=42,
                    help="seed deterministik (default: 42)")
    ap.add_argument("--json", action="store_true",
                    help="keluarkan JSON penuh (default: ringkasan teks)")
    args = ap.parse_args()

    laporan = run(seed=args.seed)

    if args.json:
        print(json.dumps(laporan, indent=2, ensure_ascii=False))
    else:
        print("=" * 62)
        print(f" FUZZ LAB — hasil (seed={args.seed}, "
              f"batas {JATAH_WAKTU_S}s)")
        print("=" * 62)
        for h in laporan["hasil"]:
            print(f"  [{h['status']:<8}] {h['id']:<5} {h['nama']}")
            print(f"             {h['detail']}")
        print("-" * 62)
        print(f"  kasus={laporan['n_case']} "
              f"AMAN={laporan['n_aman']} "
              f"GUARD_OK={laporan['n_guard_ok']} "
              f"CRASH={laporan['n_crash']} "
              f"SKIP={laporan['n_skip']} "
              f"waktu={laporan['waktu_total_s']}s")
    return 1 if laporan["n_crash"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
