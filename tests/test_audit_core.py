"""test_audit_core.py — Unit test RBAC, PBKDF2, rate limiter, audit hash-chain."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_core


class TestPasswordHash(unittest.TestCase):
    def test_format_hash(self):
        h = audit_core.hash_password("rahasia-lab")
        self.assertTrue(h.startswith("pbkdf2$"))
        skema, iterasi, salt, digest = h.split("$", 3)
        self.assertEqual(skema, "pbkdf2")
        self.assertEqual(int(iterasi), audit_core.PBKDF2_ITER)
        self.assertEqual(len(salt), 32)   # hex 16 byte
        self.assertEqual(len(digest), 64)

    def test_password_benar_diverifikasi(self):
        h = audit_core.hash_password("rahasia-lab")
        self.assertTrue(audit_core.verify_password("rahasia-lab", h))

    def test_password_salah_ditolak(self):
        h = audit_core.hash_password("rahasia-lab")
        self.assertFalse(audit_core.verify_password("salah", h))

    def test_salt_acak_berbeda(self):
        self.assertNotEqual(audit_core.hash_password("sama"),
                            audit_core.hash_password("sama"))

    def test_password_kosong_raise(self):
        with self.assertRaises(ValueError):
            audit_core.hash_password("")

    def test_verify_format_rusak(self):
        self.assertFalse(audit_core.verify_password("x", "bukan-format"))


class TestRateLimiter(unittest.TestCase):
    def test_bawah_batas_diizinkan(self):
        rl = audit_core.RateLimiter(maks=3, jendela=60)
        self.assertTrue(all(rl.allow("u1", now=1.0) for _ in range(3)))

    def test_atas_batas_ditolak(self):
        rl = audit_core.RateLimiter(maks=3, jendela=60)
        for _ in range(3):
            rl.allow("u1", now=1.0)
        self.assertFalse(rl.allow("u1", now=1.5))

    def test_jendela_bergulir_reset(self):
        rl = audit_core.RateLimiter(maks=2, jendela=10)
        rl.allow("u1", now=1.0)
        rl.allow("u1", now=2.0)
        self.assertFalse(rl.allow("u1", now=3.0))
        self.assertTrue(rl.allow("u1", now=12.0))  # jendela lewat

    def test_kunci_berbedaIndependen(self):
        rl = audit_core.RateLimiter(maks=1, jendela=60)
        self.assertTrue(rl.allow("a", now=1.0))
        self.assertTrue(rl.allow("b", now=1.0))


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "audit.jsonl")
        self.log = audit_core.AuditLog(self.path)

    def tearDown(self):
        self.dir.cleanup()

    def test_append_dan_entries(self):
        self.log.append("admin", "MULAI", "tes")
        self.log.append("operator", "STOP", "tes2")
        e = self.log.entries()
        self.assertEqual(len(e), 2)
        self.assertEqual(e[0]["aktor"], "admin")
        self.assertEqual(e[1]["prev"], e[0]["hash"])

    def test_verify_utuh(self):
        self.log.append("admin", "A", "1")
        self.log.append("admin", "B", "2")
        self.assertIsNone(self.log.verify())

    def test_tamper_terdeteksi(self):
        self.log.append("admin", "A", "1")
        self.log.append("operator", "B", "2")
        self.log.tamper(0, "DIBUANG")
        idx = self.log.verify()
        self.assertIsNotNone(idx)
        self.assertEqual(idx, 0)  # hash baris-0 tidak cocok lagi setelah diubah

    def test_hapus_baris_terdeteksi(self):
        self.log.append("admin", "A", "1")
        self.log.append("admin", "B", "2")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("")  # hapus semua
        self.assertEqual(len(self.log.entries()), 0)
        self.assertIsNone(self.log.verify())  # rantai kosong = utuh

    def test_file_baru_kosong(self):
        self.assertEqual(audit_core.AuditLog(
            os.path.join(self.dir.name, "tidak-ada.jsonl")).entries(), [])


class TestRBAC(unittest.TestCase):
    def setUp(self):
        self.rbac = audit_core.RBAC()
        self.rbac.add_user("admin1", "sandi-admin", "admin")
        self.rbac.add_user("op1", "sandi-op", "operator")
        self.rbac.add_user("aud1", "sandi-aud", "auditor")

    def test_role_tidak_valid_raise(self):
        with self.assertRaises(ValueError):
            self.rbac.add_user("x", "y", "root")

    def test_username_duplikat_raise(self):
        with self.assertRaises(ValueError):
            self.rbac.add_user("admin1", "z", "auditor")

    def test_authenticate_valid(self):
        self.assertEqual(self.rbac.authenticate("op1", "sandi-op"),
                         "operator")

    def test_authenticate_password_salah(self):
        self.assertIsNone(self.rbac.authenticate("op1", "salah"))

    def test_authenticate_user_tidak_ada(self):
        self.assertIsNone(self.rbac.authenticate("hantu", "x"))

    def test_authorize_matriks(self):
        self.assertTrue(self.rbac.authorize("admin", "kelola_pengguna"))
        self.assertFalse(self.rbac.authorize("operator", "kelola_pengguna"))
        self.assertTrue(self.rbac.authorize("auditor", "verifikasi_integritas"))
        self.assertFalse(self.rbac.authorize("auditor", "jalankan_skenario"))

    def test_n_pengguna(self):
        self.assertEqual(self.rbac.n_pengguna(), 3)


if __name__ == "__main__":
    unittest.main()
