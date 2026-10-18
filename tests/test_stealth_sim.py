"""test_stealth_sim.py — Unit test detektor defensif stealth_sim."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stealth_sim

AKAR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET = os.path.join(AKAR, "stealth_dataset.json")


class TestProses(unittest.TestCase):
    def test_proses_mencurigakan_terdeteksi(self):
        temuan = stealth_sim.analisa_proses(
            [{"nama": "silent_hook.exe", "path": "C:\\x\\silent_hook.exe"}])
        self.assertEqual(len(temuan), 1)
        self.assertEqual(temuan[0]["sev"], "TINGGI")

    def test_proses_bersih_lolos(self):
        temuan = stealth_sim.analisa_proses(
            [{"nama": "chrome.exe",
              "path": "C:\\Program Files\\Chrome\\chrome.exe"}])
        self.assertEqual(temuan, [])


class TestKoneksi(unittest.TestCase):
    def test_port_tercuriga_terdeteksi(self):
        temuan = stealth_sim.analisa_koneksi(
            [{"proses": "x.exe", "ip_remote": "203.0.113.7",
              "port_remote": 4444, "status": "ESTABLISHED"}])
        self.assertEqual(len(temuan), 1)
        self.assertEqual(temuan[0]["sev"], "TINGGI")

    def test_koneksi_wajar_lolos(self):
        temuan = stealth_sim.analisa_koneksi(
            [{"proses": "chrome.exe", "ip_remote": "1.2.3.4",
              "port_remote": 443, "status": "ESTABLISHED"}])
        self.assertEqual(temuan, [])


class TestPersistensi(unittest.TestCase):
    def test_pola_startup_terdeteksi(self):
        temuan = stealth_sim.analisa_persistensi(
            [{"nama": "silent_hook.exe",
              "lokasi": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}])
        self.assertEqual(len(temuan), 1)
        self.assertEqual(temuan[0]["sev"], "TINGGI")


class TestIzin(unittest.TestCase):
    def test_izin_berlebihan_terdeteksi(self):
        temuan = stealth_sim.analisa_izin(
            [{"aplikasi": "bad_app", "izin": ["kamera", "mikrofon",
                                              "layar", "aksesibilitas"]}])
        self.assertEqual(len(temuan), 1)
        self.assertEqual(temuan[0]["sev"], "TINGGI")

    def test_izin_satu_lolos(self):
        temuan = stealth_sim.analisa_izin(
            [{"aplikasi": "vscode", "izin": ["layar"]}])
        self.assertEqual(temuan, [])


class TestDatasetLengkap(unittest.TestCase):
    def test_dataset_dimuat_lengkap(self):
        data = stealth_sim.muat_dataset(DATASET)
        self.assertEqual(len(data["proses"]), 10)
        self.assertEqual(len(data["koneksi"]), 4)
        self.assertEqual(len(data["persistensi"]), 3)
        self.assertEqual(len(data["izin"]), 3)

    def test_pindai_dataset_menghasilkan_temuan(self):
        data = stealth_sim.muat_dataset(DATASET)
        hasil = stealth_sim.pindai_dataset(data)
        total = sum(len(v) for v in hasil.values())
        self.assertGreaterEqual(total, 8)  # dataset memang berisi indikator
        self.assertTrue(all(
            t["sev"] in ("TINGGI", "SEDANG", "RENDAH")
            for v in hasil.values() for t in v))


if __name__ == "__main__":
    unittest.main()
