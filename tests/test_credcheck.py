"""test_credcheck.py — Unit test kredensial sintetis, masking, secret scanning, VulnTestApp."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import credcheck


class TestGenerateCredentials(unittest.TestCase):
    def test_jumlah_dan_isi(self):
        kreds = credcheck.generate_credentials(4)
        self.assertEqual(len(kreds), 4)
        for k in kreds:
            self.assertTrue(k["username"])
            self.assertGreaterEqual(len(k["password"]), 10)
            self.assertEqual(len(k["token"]), 32)

    def test_unik_antar_kreds(self):
        kreds = credcheck.generate_credentials(5)
        pwd = [k["password"] for k in kreds]
        self.assertEqual(len(set(pwd)), 5)


class TestMask(unittest.TestCase):
    """v2.0: kebijakan 'ketat' (DEFAULT) tidak menampilkan potongan
    awal/akhir yang bisa membantu tebakan; 'ringan' kompatibel v1.3."""

    def test_mask_ketat_tanpa_potongan(self):
        m = credcheck.mask("Lab-SuperRahasia12345")
        self.assertNotIn("SuperRahasia", m)
        self.assertFalse(m.startswith("La"))
        self.assertFalse(m.endswith("45"))

    def test_mask_ketat_format(self):
        # panjang disertutupi jujur, isi tidak
        self.assertEqual(credcheck.mask("Lab-SuperRahasia12345"),
                         "******** (len=21)")

    def test_mask_ketat_panjang_berbeda_dibedakan(self):
        self.assertIn("len=8", credcheck.mask("abcdefgh"))
        self.assertIn("len=9", credcheck.mask("abcdefghi"))

    def test_mask_ringan_kompatibel(self):
        self.assertEqual(
            credcheck.mask("Lab-SuperRahasia12345", kebijakan="ringan"),
            "La…45")

    def test_mask_pendek(self):
        self.assertEqual(credcheck.mask("abc"), "***")
        self.assertEqual(credcheck.mask("abc", kebijakan="ringan"), "***")

    def test_scan_text_bukti_ketat_default(self):
        nilai = "Lab-xyz-123456789"
        t = f"password = '{nilai}'"
        temuan = credcheck.scan_text(t, "config")
        self.assertTrue(temuan)
        for x in temuan:
            # tidak ada 2 karakter pertama/terakhir nilai yang muncul
            self.assertNotIn(nilai[:2], x["bukti"])
            self.assertNotIn(nilai[-2:], x["bukti"])


class TestEntropy(unittest.TestCase):
    def test_string_acak_entropi_tinggi(self):
        self.assertGreater(
            credcheck.shannon_entropy("a8Kj2mQ9xLp3zR7v"), 3.5)

    def test_string_berulang_entropi_rendah(self):
        self.assertLess(credcheck.shannon_entropy("aaaaaaaa"), 0.1)


class TestScanText(unittest.TestCase):
    def test_deteksi_password(self):
        t = "db_password = 'Lab-xyz-123456789'"
        temuan = credcheck.scan_text(t, "config")
        self.assertTrue(any(t2["pola"] == "password_assignment"
                            for t2 in temuan))

    def test_deteksi_api_key_dan_aws(self):
        t = ("api_key = 'ak_live_abcdef1234567890'\n"
             "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
             "Authorization: Bearer abcdef12345678901234\n"
             "-----BEGIN RSA PRIVATE KEY-----\n")
        pola = {x["pola"] for x in credcheck.scan_text(t, "config")}
        self.assertIn("api_key", pola)
        self.assertIn("aws_access_key", pola)
        self.assertIn("bearer_token", pola)
        self.assertIn("private_key_header", pola)

    def test_deteksi_string_entropi_tinggi(self):
        t = "kunci = 'a8Kj2mQ9xLp3zR7vB4nC6dXw'"
        temuan = credcheck.scan_text(t, "config")
        self.assertTrue(any(x["pola"] == "high_entropy_string"
                            for x in temuan))

    def test_bukti_dimask(self):
        nilai = "Lab-xyz-123456789"
        t = f"password = '{nilai}'"
        temuan = credcheck.scan_text(t, "config")
        for x in temuan:
            self.assertNotIn(nilai, x["bukti"])

    def test_teks_bersih_tanpa_temuan(self):
        t = "# hanya komentar\ntimeout = 30\n"
        self.assertEqual(credcheck.scan_text(t, "config"), [])


class TestVulnTestApp(unittest.TestCase):
    def setUp(self):
        self.kreds = credcheck.generate_credentials(3)
        self.app = credcheck.VulnTestApp(self.kreds, session_ttl=0.05)

    def test_login_valid(self):
        sid = self.app.login(self.kreds[0]["username"], self.kreds[0]["password"])
        self.assertIsNotNone(sid)

    def test_login_salah_ditolak(self):
        self.assertIsNone(self.app.login(self.kreds[0]["username"], "salah"))

    def test_idor_terbukti(self):
        sid = self.app.login(self.kreds[0]["username"], self.kreds[0]["password"])
        # doc-2 milik user lain, tapi app rentan IDOR mengizinkan
        hasil = self.app.get_document(sid, "doc-2")
        self.assertIsNotNone(hasil)
        self.assertNotEqual(hasil, f"milik-{self.kreds[0]['username']}")

    def test_session_ttl_expired(self):
        import time
        sid = self.app.login(self.kreds[0]["username"], self.kreds[0]["password"])
        self.assertTrue(self.app.is_session_valid(sid))
        time.sleep(0.08)
        self.assertFalse(self.app.is_session_valid(sid))

    def test_authz_tanpa_role(self):
        sid = self.app.login(self.kreds[1]["username"], self.kreds[1]["password"])
        # kelemahan sengaja: aksi admin tanpa cek role tetap 'OK'
        self.assertEqual(self.app.aksi_admin(sid), "OK")


class TestRunAssessment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.laporan = credcheck.run_assessment()

    def test_ada_temuan_dan_severity(self):
        self.assertGreaterEqual(self.laporan["ringkasan"]["total"], 5)
        self.assertIn("KRITIS", self.laporan["ringkasan"]["per_severity"])

    def test_idor_ditandai_vulnerable(self):
        self.assertEqual(self.laporan["ringkasan"]["idor"], "VULNERABLE")

    def test_authz_ditandai_vulnerable(self):
        self.assertEqual(self.laporan["ringkasan"]["authz_boundary"], "VULNERABLE")

    def test_tidak_ada_nilai_rahasia_dalam_laporan(self):
        self.assertTrue(self.laporan["ringkasan"]["no_secret_leak_verified"])

    def test_semua_bukti_dimask(self):
        import json
        teks = json.dumps(self.laporan, ensure_ascii=False)
        for k in credcheck.generate_credentials(2):  # sampel ekstra
            self.assertNotIn(k["password"], teks)
        for t in self.laporan["temuan"]:
            self.assertNotIn("Lab-", t.get("bukti", ""))


if __name__ == "__main__":
    unittest.main()
