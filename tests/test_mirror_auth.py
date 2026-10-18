"""test_mirror_auth.py — Unit test untuk autentikasi, persetujuan, sesi, audit.

Stdlib-only; tidak butuh OpenCV. Jalankan dari root repo:
  python -m unittest discover -s tests
"""
import csv
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mirror_auth


class TestKodePairing(unittest.TestCase):
    def test_format_kode(self):
        kode = mirror_auth.buat_kode_pairing()
        self.assertEqual(len(kode), 9)
        a, b = kode.split("-")
        self.assertEqual(len(a), 4)
        self.assertEqual(len(b), 4)
        int(a, 16)  # harus hex valid
        int(b, 16)


class TestToken(unittest.TestCase):
    def test_buat_token_deterministik(self):
        t1 = mirror_auth.buat_token("AAAA-BBBB", "admin")
        t2 = mirror_auth.buat_token("AAAA-BBBB", "admin")
        self.assertEqual(t1, t2)
        self.assertEqual(len(t1), 64)  # hex sha256

    def test_verifikasi_valid(self):
        kode = mirror_auth.buat_kode_pairing()
        token = mirror_auth.buat_token(kode, "viewer")
        self.assertTrue(mirror_auth.verifikasi_token(kode, "viewer", token))

    def test_verifikasi_token_salah(self):
        kode = mirror_auth.buat_kode_pairing()
        self.assertFalse(mirror_auth.verifikasi_token(kode, "admin", "f" * 64))

    def test_verifikasi_role_salah(self):
        kode = mirror_auth.buat_kode_pairing()
        token = mirror_auth.buat_token(kode, "admin")
        self.assertFalse(mirror_auth.verifikasi_token(kode, "viewer", token))

    def test_verifikasi_token_kosong(self):
        kode = mirror_auth.buat_kode_pairing()
        self.assertFalse(mirror_auth.verifikasi_token(kode, "admin", ""))

    def test_role_tidak_valid_raise(self):
        with self.assertRaises(ValueError):
            mirror_auth.buat_token("AAAA-BBBB", "root")


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.asli = mirror_auth.SESSIONS_LOG
        mirror_auth.SESSIONS_LOG = os.path.join(self.dir.name, "sessions.csv")

    def tearDown(self):
        mirror_auth.SESSIONS_LOG = self.asli
        self.dir.cleanup()

    def _baca(self):
        with open(mirror_auth.SESSIONS_LOG, encoding="utf-8") as f:
            return list(csv.reader(f))

    def test_header_dibuat(self):
        mirror_auth.audit_log("MULAI", "pengirim", "tes")
        baris = self._baca()
        self.assertEqual(baris[0], ["timestamp", "event", "role", "detail"])
        self.assertEqual(len(baris), 2)
        self.assertEqual(baris[1][1], "MULAI")

    def test_baris_baru_tertambah(self):
        mirror_auth.audit_log("MULAI", "pengirim", "a")
        mirror_auth.audit_log("STOP", "pengirim", "b")
        baris = self._baca()
        self.assertEqual(len(baris), 3)
        self.assertEqual([b[1] for b in baris[1:]], ["MULAI", "STOP"])


class TestConsentGate(unittest.TestCase):
    def test_setuju(self):
        gate = mirror_auth.ConsentGate()
        self.assertTrue(gate.minta("SETUJU"))
        self.assertTrue(gate.disetujui)

    def test_tolak_jawaban_salah(self):
        gate = mirror_auth.ConsentGate()
        self.assertFalse(gate.minta("ya"))
        self.assertFalse(gate.disetujui)

    def test_case_insensitive(self):
        gate = mirror_auth.ConsentGate()
        self.assertTrue(gate.minta("  setuju "))

    def test_disetujui_false_awal(self):
        gate = mirror_auth.ConsentGate()
        self.assertFalse(gate.disetujui)
        self.assertIsNone(gate.waktu_setuju)


class TestSesi(unittest.TestCase):
    def test_mulai_dari_idle(self):
        s = mirror_auth.Sesi()
        self.assertEqual(s.mulai(), "mulai")
        self.assertEqual(s.state, mirror_auth.Sesi.AKTIF)

    def test_jeda_lalu_lanjut(self):
        s = mirror_auth.Sesi()
        s.mulai()
        self.assertEqual(s.jeda(), "jeda")
        self.assertEqual(s.lanjut(), "lanjut")
        self.assertEqual(s.state, mirror_auth.Sesi.AKTIF)

    def test_transisi_ilegal_raise(self):
        s = mirror_auth.Sesi()
        with self.assertRaises(RuntimeError):
            s.jeda()  # idle -> jeda tidak boleh

    def test_tidak_bisa_mulai_setelah_berhenti(self):
        s = mirror_auth.Sesi()
        s.mulai()
        s.stop()
        with self.assertRaises(RuntimeError):
            s.mulai()

    def test_tambah_penonton(self):
        s = mirror_auth.Sesi()
        s.mulai()
        s.tambah_penonton("viewer@1.2.3.4:99", "viewer")
        self.assertIn("viewer@1.2.3.4:99", s.penonton)

    def test_penonton_role_salah_raise(self):
        s = mirror_auth.Sesi()
        s.mulai()
        with self.assertRaises(ValueError):
            s.tambah_penonton("x", "root")

    def test_keluar_penonton(self):
        s = mirror_auth.Sesi()
        s.mulai()
        s.tambah_penonton("v1", "viewer")
        self.assertTrue(s.keluar("v1"))
        self.assertFalse(s.keluar("v1"))  # sudah keluar

    def test_cabut_oleh_admin(self):
        s = mirror_auth.Sesi()
        s.mulai()
        s.tambah_penonton("v1", "viewer")
        s.cabut("v1", "admin")
        self.assertNotIn("v1", s.penonton)

    def test_cabut_oleh_viewer_raise(self):
        s = mirror_auth.Sesi()
        s.mulai()
        s.tambah_penonton("v1", "viewer")
        with self.assertRaises(PermissionError):
            s.cabut("v1", "viewer")


if __name__ == "__main__":
    unittest.main()
