"""test_audit_fixes.py — Regresi v2.0: race, seq, anchor, PBKDF2 cap,
rate limiter, anti-enumeration, toleransi baris malformed (bug fuzz),
dan deteksi beacon netmon (cv + port wajar).

Setiap test di sini MENGIKAT satu temuan audit independen (A-01..A-08,
A-15) atau bug hasil fuzz (F1/F2) supaya masalah yang sama tidak
kembali diam-diam.
"""
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_core
import forensics
import netmon


# ------------------------------------------------------------
# A-01: race condition append lintas-proses (kini flock)
# ------------------------------------------------------------
class TestRaceCondition(unittest.TestCase):
    """A-01: tanpa flock lintas-proses, append paralel merusak rantai.

    Catatan jujur: penguncian memakai fcntl.flock — POSIX-only. Di Windows
    audit_core memakai fallback TANPA kunci lintas-proses (terdokumentasi),
    jadi jaminan race-free ini tidak diuji di Windows (di-skip, bukan
    diklaim lulus).
    """

    _skip_flock = unittest.skipIf(
        os.name != "posix",
        "POSIX-only: jaminan race-free bergantung fcntl.flock")

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "audit.jsonl")

    def tearDown(self):
        self.dir.cleanup()

    @_skip_flock
    def test_race_audit_2_proses(self):
        # DULU: 2 proses x append -> rantai rusak. KINI: flock -> utuh.
        log1 = audit_core.AuditLog(self.path)
        log2 = audit_core.AuditLog(self.path)
        t1 = threading.Thread(
            target=lambda: [log1.append("p1", f"A{i}") for i in range(30)])
        t2 = threading.Thread(
            target=lambda: [log2.append("p2", f"B{i}") for i in range(30)])
        t1.start(); t2.start(); t1.join(); t2.join()
        log = audit_core.AuditLog(self.path)
        self.assertEqual(len(log.entries()), 60)
        self.assertIsNone(log.verify())
        seqs = sorted(e["seq"] for e in log.entries())
        self.assertEqual(seqs, list(range(1, 61)))  # seq kontinu 1..60

    @_skip_flock
    def test_race_event_2_proses(self):
        path = os.path.join(self.dir.name, "events.jsonl")
        s1 = forensics.EventStore(path)
        s2 = forensics.EventStore(path)

        def isi(store, nama):
            for i in range(30):
                store.append(forensics.normalize("netmon", f"{nama}{i}"))

        t1 = threading.Thread(target=isi, args=(s1, "a"))
        t2 = threading.Thread(target=isi, args=(s2, "b"))
        t1.start(); t2.start(); t1.join(); t2.join()
        store = forensics.EventStore(path)
        self.assertEqual(len(store.load()), 60)
        self.assertIsNone(store.verify())
        seqs = sorted(e["seq"] for e in store.load())
        self.assertEqual(seqs, list(range(1, 61)))


# ------------------------------------------------------------
# A-07: append O(n^2) -> tail-read (sekalian cek seq monotonik)
# ------------------------------------------------------------
class TestAppendEfisien(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "audit.jsonl")

    def tearDown(self):
        self.dir.cleanup()

    def test_append_500_baris_utuh_dan_seq_kontinu(self):
        log = audit_core.AuditLog(self.path)
        for i in range(500):
            log.append("admin", f"AKSI-{i}", "beban")
        self.assertEqual(len(log.entries()), 500)
        self.assertIsNone(log.verify())
        self.assertEqual([e["seq"] for e in log.entries()],
                         list(range(1, 501)))

    def test_seq_file_legacy_v13_dilanjutkan(self):
        # file v1.3 (tanpa seq) tetap kompatibel: seq baru = n+1
        prev = "GENESIS"
        with open(self.path, "w", encoding="utf-8") as f:
            for i in range(2):
                ts = f"2026-01-01 00:00:0{i}"
                h = hashlib.sha256(
                    f"{prev}|{ts}|admin|AKSI-{i}|x".encode()).hexdigest()
                f.write(json.dumps({"ts": ts, "aktor": "admin",
                                    "aksi": f"AKSI-{i}", "detail": "x",
                                    "prev": prev, "hash": h},
                                   ensure_ascii=False) + "\n")
                prev = h
        log = audit_core.AuditLog(self.path)
        self.assertIsNone(log.verify())  # format lama tetap valid
        e = log.append("admin", "BARU")
        self.assertEqual(e["seq"], 3)


# ------------------------------------------------------------
# A-05: verify_password DoS via iterasi tersimpan -> rentang min/maks
# ------------------------------------------------------------
class TestPBKDF2Cap(unittest.TestCase):
    def test_iterasi_di_atas_cap_ditolak_cepat(self):
        # 5 juta iterasi dulu -> 0,64 dtk per verify (DoS). Kini: False.
        self.assertFalse(audit_core.verify_password(
            "x", "pbkdf2$5000000$" + "a" * 32 + "0" * 64))

    def test_iterasi_di_bawah_min_ditolak(self):
        self.assertFalse(audit_core.verify_password(
            "x", "pbkdf2$100$" + "a" * 32 + "0" * 64))

    def test_iterasi_valid_dalam_rentang_diterima(self):
        dk = hashlib.pbkdf2_hmac("sha256", b"rahasia", b"00" * 16, 1000)
        stored = f"pbkdf2$1000${'00' * 16}${dk.hex()}"
        self.assertTrue(audit_core.verify_password("rahasia", stored))
        self.assertFalse(audit_core.verify_password("salah", stored))

    def test_hash_default_dalam_rentang(self):
        h = audit_core.hash_password("sandi")
        self.assertTrue(audit_core.verify_password("sandi", h))


# ------------------------------------------------------------
# RateLimiter.hitung()/reset() (dipakai MirrorServer lockout)
# ------------------------------------------------------------
class TestRateLimiterHitung(unittest.TestCase):
    def test_hitung_dan_reset(self):
        rl = audit_core.RateLimiter(maks=3, jendela=60)
        for _ in range(3):
            rl.allow("ip1", now=1.0)
        self.assertEqual(rl.hitung("ip1", now=1.5), 3)
        rl.reset("ip1")
        self.assertEqual(rl.hitung("ip1", now=1.5), 0)
        self.assertTrue(rl.allow("ip1", now=1.5))


# ------------------------------------------------------------
# A-02 (bagian RBAC): lockout + anti user-enumeration
# ------------------------------------------------------------
class TestAuthenticateHardening(unittest.TestCase):
    def setUp(self):
        self.rbac = audit_core.RBAC()
        self.rbac.add_user("op1", "sandi-op", "operator")

    def test_limiter_mengunci_username(self):
        rl = audit_core.RateLimiter(maks=5, jendela=60)
        for _ in range(5):
            self.assertIsNone(
                self.rbac.authenticate("op1", "salah", limiter=rl))
        # password BENAR tapi terkunci -> tetap None
        self.assertIsNone(
            self.rbac.authenticate("op1", "sandi-op", limiter=rl))

    def test_antienumerasi_tidak_raise_dan_tetap_none(self):
        # pemakai tak dikenal: jalankan PBKDF2 dummy (waktu ~sama),
        # hasil tetap None — TIDAK membocorkan keberadaan username.
        self.assertIsNone(self.rbac.authenticate("hantu", "apa"))
        self.assertIsNone(self.rbac.authenticate("hantu", "apa",
                                                 limiter=audit_core.RateLimiter()))


# ------------------------------------------------------------
# A-15: anchor/checkpoint (deteksi truncation ekor)
# ------------------------------------------------------------
class TestAnchorAudit(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "audit.jsonl")
        self.log = audit_core.AuditLog(self.path)
        for i in range(5):
            self.log.append("admin", f"A{i}")

    def tearDown(self):
        self.dir.cleanup()

    def _potong(self, n_tersisa):
        entries = self.log.entries()[:n_tersisa]
        with open(self.path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")

    def test_checkpoint_lalu_utuh(self):
        self.log.checkpoint()
        hasil = self.log.verify_terhadap_anchor()
        self.assertTrue(hasil["utuh"])
        self.assertIsNone(hasil["masalah"])

    def test_truncation_ekor_terdeteksi_dengan_anchor(self):
        self.log.checkpoint()          # n=5
        self._potong(3)                # hapus 2 baris ekor
        hasil = self.log.verify_terhadap_anchor()
        self.assertFalse(hasil["utuh"])
        self.assertIn("TERPANGKAS", hasil["masalah"])
        self.assertIn("3 < 5", hasil["masalah"])

    def test_tanpa_anchor_truncation_buta_didokumentasikan(self):
        # Blind spot yang DIAKUI: tanpa anchor, verify() biasa tidak
        # mendeteksi penghapusan baris ekor (inilah kenapa anchor wajib).
        self._potong(3)
        self.assertIsNone(self.log.verify())
        hasil = self.log.verify_terhadap_anchor()
        self.assertFalse(hasil["utuh"])
        self.assertEqual(hasil["masalah"], "anchor tidak ditemukan")

    def test_anchor_baris_posisi_diubah(self):
        anchor = self.log.checkpoint()
        # Penyerang mengganti baris di posisi anchor dengan hash lain
        # tapi menjaga rantai visual — seq/hash harus tetap cocok anchor.
        entries = self.log.entries()
        entries[4]["hash"] = "f" * 64
        with open(self.path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        idx = self.log.verify()
        hasil = self.log.verify_terhadap_anchor()
        self.assertFalse(hasil["utuh"])
        self.assertTrue(hasil["masalah"].startswith("rantai rusak")
                        or "berubah/dihapus" in hasil["masalah"])

    def test_reorder_terdeteksi(self):
        entries = self.log.entries()
        with open(self.path, "w", encoding="utf-8") as f:
            for e in reversed(entries):
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        self.assertIsNotNone(self.log.verify())

    def test_duplikasi_baris_terdeteksi(self):
        entries = self.log.entries()
        entries.append(dict(entries[-1]))
        with open(self.path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        self.assertIsNotNone(self.log.verify())


# ------------------------------------------------------------
# Bug fuzz F2: baris JSONL malformed (non-dict / JSON rusak)
# ------------------------------------------------------------
class TestVerifyToleranMalformed(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "audit.jsonl")
        self.log = audit_core.AuditLog(self.path)
        self.log.append("admin", "A1")
        self.log.append("admin", "A2")

    def tearDown(self):
        self.dir.cleanup()

    def _tambah_baris(self, baris):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(baris + "\n")

    def test_baris_array_tidak_crash(self):
        # dulu: AttributeError di verify(); kini: indeks baris masalah
        self._tambah_baris("[1, 2, 3]")
        self.assertEqual(self.log.verify(), 2)

    def test_baris_json_rusak_tidak_crash(self):
        self._tambah_baris("{bukan-json")
        self.assertEqual(self.log.verify(), 2)

    def test_baris_dict_tanpa_field_hash(self):
        self._tambah_baris(json.dumps({"ts": "x", "aktor": "y"}))
        idx = self.log.verify()
        self.assertEqual(idx, 2)

    def test_event_baris_array_tidak_crash(self):
        p = os.path.join(self.dir.name, "ev.jsonl")
        store = forensics.EventStore(p)
        store.append(forensics.normalize("netmon", "e1"))
        with open(p, "a", encoding="utf-8") as f:
            f.write('["bukan", "dict"]\n')
        self.assertEqual(store.verify(), 1)


# ------------------------------------------------------------
# A-04: beacon netmon — cv interval + port wajar (anti-FP)
# ------------------------------------------------------------
class TestBeaconNetmon(unittest.TestCase):
    def test_cv_interval_teratur_nol(self):
        ts = [float(i * 10) for i in range(11)]  # 11 titik kumulatif
        self.assertAlmostEqual(netmon._cv_interval(ts), 0.0, places=6)

    def test_cv_interval_jitter_tinggi(self):
        ts = [0.0]
        for i in range(10):
            ts.append(ts[-1] + (20.0 if i % 2 == 0 else 40.0))
        self.assertGreater(netmon._cv_interval(ts), 0.25)

    def test_polling_port_wajar_tidak_ditandai(self):
        # dulu: 9 paket polling 8080 -> FP "beacon"; kini: TIDAK
        flow = netmon._meta_flow(dport=8080, packets=9, interval=1.0)
        tipe = {t["tipe"] for t in netmon.detect_anomalies([flow])}
        self.assertNotIn("beacon", tipe)

    def test_beacon_port_c2_terdeteksi(self):
        flow = netmon._meta_flow(dport=4444, packets=10, interval=10.0)
        tipe = {t["tipe"] for t in netmon.detect_anomalies([flow])}
        self.assertIn("beacon", tipe)
        self.assertIn("port_c2", tipe)

    def test_ambang_configurable(self):
        # beacon jitter (cv ~0.33): di atas ambang default 0.25 → lolos;
        # dengan ambang longgar 0.5 → terdeteksi (trade-off eksplisit)
        flow = netmon._meta_jitter()
        self.assertNotIn("beacon",
                         {t["tipe"] for t in netmon.detect_anomalies([flow])})
        longgar = netmon.detect_anomalies(
            [flow], ambang={"beacon_cv_maks": 0.5})
        self.assertIn("beacon", {t["tipe"] for t in longgar})

    def test_temuan_punya_skor_dan_bukti(self):
        flow = netmon._meta_flow(dport=4444, packets=10, interval=10.0)
        t = netmon.detect_anomalies([flow])[0]
        self.assertIn("skor", t)
        self.assertIn("bukti", t)
        self.assertLessEqual(t["skor"], 1.0)


if __name__ == "__main__":
    unittest.main()
