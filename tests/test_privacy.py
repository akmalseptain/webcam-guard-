"""test_privacy.py — Unit test PrivacyGuard: jejak, retensi, izin, fail-safe."""
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import privacy


class PrivacyBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.media = os.path.join(self.dir.name, "rec")
        os.makedirs(self.media, exist_ok=True)
        self.log = os.path.join(self.dir.name, "privacy.jsonl")

    def tearDown(self):
        self.dir.cleanup()

    def _buat_file(self, nama, ukuran=1024, umur_hari=0.0):
        p = os.path.join(self.media, nama)
        with open(p, "wb") as f:
            f.write(b"x" * ukuran)
        if umur_hari:
            lama = time.time() - umur_hari * 86400.0
            os.utime(p, (lama, lama))
        return p


class TestJejakPrivasi(PrivacyBase):
    def test_catat_dan_baca(self):
        pg = privacy.PrivacyGuard(direktori_media=self.media,
                                  log_path=self.log)
        pg.catat("MULAI_REKAM", "sesi lab")
        pg.catat("STOP_REKAM", "selesai")
        log = pg.baca_log()
        self.assertEqual(len(log), 2)
        self.assertEqual(log[0]["event"], "MULAI_REKAM")
        self.assertEqual(log[1]["detail"], "selesai")

    def test_log_malformed_dilewati(self):
        pg = privacy.PrivacyGuard(direktori_media=self.media,
                                  log_path=self.log)
        with open(self.log, "w", encoding="utf-8") as f:
            f.write("bukan json\n")
            f.write(json.dumps({"ts": "t", "event": "VALID",
                                "detail": ""}) + "\n")
        log = pg.baca_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["event"], "VALID")

    def test_log_tidak_ada(self):
        pg = privacy.PrivacyGuard(direktori_media=self.media,
                                  log_path=self.log)
        self.assertEqual(pg.baca_log(), [])


class TestRetensi(PrivacyBase):
    def test_ringkasan_kosong(self):
        pg = privacy.PrivacyGuard(direktori_media=self.media,
                                  log_path=self.log)
        r = pg.ringkasan()
        self.assertEqual(r["n_file"], 0)
        self.assertFalse(r["melebihi_kuota"])

    def test_hanya_file_media_dihitung(self):
        self._buat_file("rekaman.mp4")
        self._buat_file("catatan.txt")  # bukan media — diabaikan
        pg = privacy.PrivacyGuard(direktori_media=self.media,
                                  log_path=self.log)
        self.assertEqual(pg.ringkasan()["n_file"], 1)

    def test_retensi_umur_direncanakan(self):
        tua = self._buat_file("tua.mp4", umur_hari=10)
        baru = self._buat_file("baru.mp4", umur_hari=0)
        pg = privacy.PrivacyGuard(direktori_media=self.media,
                                  log_path=self.log, maks_umur_hari=7)
        hasil = pg.bersihkan(jalankan=False)
        self.assertEqual(hasil["direncanakan"], [tua])
        self.assertEqual(hasil["terhapus"], [])
        # dry-run TIDAK menghapus
        self.assertTrue(os.path.exists(tua))
        self.assertTrue(os.path.exists(baru))

    def test_retensi_umur_dijalankan(self):
        tua = self._buat_file("tua.mp4", umur_hari=10)
        self._buat_file("baru.mp4", umur_hari=0)
        pg = privacy.PrivacyGuard(direktori_media=self.media,
                                  log_path=self.log, maks_umur_hari=7)
        hasil = pg.bersihkan(jalankan=True)
        self.assertFalse(os.path.exists(tua))
        self.assertTrue(any(e["event"] == "RETENSI_DIJALANKAN"
                            for e in pg.baca_log()))

    def test_kuota_hapus_terlama_dulu(self):
        # kuota kecil: hapus TERLAMA dulu, BERHENTI begitu kuota terpenuhi
        a = self._buat_file("a.mp4", ukuran=4096, umur_hari=5)
        b = self._buat_file("b.mp4", ukuran=4096, umur_hari=1)
        pg = privacy.PrivacyGuard(direktori_media=self.media,
                                  log_path=self.log,
                                  maks_umur_hari=30, maks_total_mb=0.004)
        hasil = pg.bersihkan(jalankan=True)
        # total 0.0078 MB > 0.004 -> hapus a (terlama) -> 0.0039 <= kuota
        self.assertEqual(hasil["direncanakan"], [a])
        self.assertEqual(hasil["terhapus"], [a])
        self.assertFalse(os.path.exists(a))
        self.assertTrue(os.path.exists(b))  # b tidak ikut terhapus

    def test_kuota_habis_semua_bila_sangat_kecil(self):
        a = self._buat_file("a.mp4", ukuran=4096, umur_hari=5)
        b = self._buat_file("b.mp4", ukuran=4096, umur_hari=1)
        pg = privacy.PrivacyGuard(direktori_media=self.media,
                                  log_path=self.log,
                                  maks_umur_hari=30, maks_total_mb=0.002)
        hasil = pg.bersihkan(jalankan=True)
        self.assertEqual(hasil["terhapus"], [a, b])  # terlama dulu
        self.assertFalse(os.path.exists(a))
        self.assertFalse(os.path.exists(b))


class TestIzinDanFailSafe(PrivacyBase):
    def test_perketatizin_posix(self):
        p = self._buat_file("rahasia.mp4")
        pg = privacy.PrivacyGuard(direktori_media=self.media,
                                  log_path=self.log)
        hasil = pg.perketatizin()
        self.assertTrue(hasil[0][1])
        if os.name == "posix":
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)

    def test_fail_safe_blur_gagal(self):
        pg = privacy.PrivacyGuard(direktori_media=self.media,
                                  log_path=self.log)
        self.assertEqual(pg.keputusan_frame_blur(True), "LANJUTKAN")
        self.assertEqual(pg.keputusan_frame_blur(False), "TOLAK_FRAME")
        self.assertTrue(any(e["event"] == "BLUR_GAGAL"
                            for e in pg.baca_log()))


if __name__ == "__main__":
    unittest.main()
