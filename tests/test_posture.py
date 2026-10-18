"""test_posture.py — Unit test security posture engine + integritas anchor."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_core
import mirror_stream
import posture


class TestPostureRun(unittest.TestCase):
    """Jalankan SELURUH cek posture sekali; verifikasi struktur & skor."""

    @classmethod
    def setUpClass(cls):
        cls.laporan = posture.jalankan_semua()

    def test_16_cek_jalan(self):
        self.assertEqual(self.laporan["n_cek"], 16)
        id_cek = {h["id"] for h in self.laporan["hasil"]}
        self.assertEqual(len(id_cek), 16)  # tidak ada id ganda

    def test_status_valid_dan_bukti_ada(self):
        for h in self.laporan["hasil"]:
            self.assertIn(h["status"], ("LULUS", "PERINGAT", "GAGAL"))
            self.assertTrue(h["bukti"], f"bukti kosong di {h['id']}")

    def test_skor_formula(self):
        l = self.laporan["n_lulus"]
        p = self.laporan["n_peringat"]
        n = self.laporan["n_cek"]
        self.assertEqual(self.laporan["skor"],
                         round((l + 0.5 * p) / n * 100, 1))

    def test_gagal_tidak_ada_di_lingkungan_lab(self):
        """Bila ini GAGAL di lab → REGRESI nyata, bukan test yang salah
        (kecuali lingkungan hilangkan modul: itu dijelaskan di bukti)."""
        gagal = [h["id"] for h in self.laporan["hasil"]
                 if h["status"] == "GAGAL"]
        self.assertEqual(gagal, [],
                         f"posture GAGAL: {[(h['id'], h['bukti']) for h in self.laporan['hasil'] if h['status'] == 'GAGAL']}")

    def test_json_serializable(self):
        teks = json.dumps(self.laporan, ensure_ascii=False)
        self.assertIn("posture", teks)

    def test_peringat_itu_jujur(self):
        """PERINGAT wajib menjelaskan kenapa TIDAK bisa dibuktikan penuh
        (mis. alat eksternal absen) — bukan klaim aman."""
        for h in self.laporan["hasil"]:
            if h["status"] == "PERINGAT":
                self.assertTrue(
                    any(k in h["bukti"].lower()
                        for k in ("tidak", "manual", "not run")),
                    f"PERINGAT {h['id']} tidak jujur: {h['bukti']}")


class TestAnchorIntegritas(unittest.TestCase):
    """Cek behavioral yang dipakai posture P-03 — diuji langsung."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "audit.jsonl")
        self.anchor = os.path.join(self.dir.name, "audit.anchor.json")

    def tearDown(self):
        self.dir.cleanup()

    def _isi(self, n=5):
        log = audit_core.AuditLog(self.path, anchor_path=self.anchor)
        for i in range(n):
            log.append("posture", "TES", f"baris {i}")
        log.checkpoint()
        return log

    def test_utuh(self):
        log = self._isi()
        hasil = log.verify_terhadap_anchor()
        self.assertTrue(hasil["utuh"])
        self.assertIsNone(hasil["masalah"])

    def test_tamper_terdeteksi_via_anchor(self):
        log = self._isi()
        log.tamper(0, "AKSI-DIRUSAK")
        hasil = log.verify_terhadap_anchor()
        self.assertFalse(hasil["utuh"])
        self.assertIn("rusak", hasil["masalah"])

    def test_truncation_terdeteksi(self):
        log = self._isi(n=5)
        with open(self.path, encoding="utf-8") as f:
            baris = f.readlines()
        with open(self.path, "w", encoding="utf-8") as f:
            f.writelines(baris[:3])
        hasil = log.verify_terhadap_anchor()
        self.assertFalse(hasil["utuh"])
        self.assertIn("TERPANGKAS", hasil["masalah"])

    def test_anchor_tidak_ada_dilaporkan(self):
        log = self._isi()
        os.unlink(self.anchor)
        hasil = log.verify_terhadap_anchor()
        self.assertFalse(hasil["utuh"])
        self.assertIn("anchor", hasil["masalah"].lower())


class TestMirrorLockoutBehavioral(unittest.TestCase):
    """Cek behavioral yang dipakai posture P-06/P-07 — diuji langsung."""

    def test_lockout_dan_per_ip(self):
        srv = mirror_stream.MirrorServer(
            "KODE", "dev", port=0, token_map={"tokvalid": "viewer"})
        for _ in range(mirror_stream.GAGAL_MAKS):
            srv._autentikasi("10.1.1.1",
                             {"cmd": "HELLO", "kode": "KODE",
                              "token": "salah"})
        role, alasan = srv._autentikasi(
            "10.1.1.1", {"cmd": "HELLO", "kode": "KODE",
                         "token": "tokvalid"})
        self.assertIsNone(role)
        self.assertEqual(alasan, "terlalu banyak upaya gagal")
        # IP lain tidak terpengaruh (anti-DoS)
        role2, _ = srv._autentikasi(
            "10.1.1.2", {"cmd": "HELLO", "kode": "KODE",
                         "token": "tokvalid"})
        self.assertEqual(role2, "viewer")


if __name__ == "__main__":
    unittest.main()
