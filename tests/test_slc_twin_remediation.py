#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test slc_twin + slc_remediation v4.0."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from slc_twin import TwinError, TwinModel  # noqa: E402
from slc_remediation import (Remediasi, RemediasiError,  # noqa: E402
                              RemediationEngine, laporan_teks)


class TestTwin(unittest.TestCase):
    def setUp(self):
        self.m = TwinModel("Lab Uji")
        self.m.tambah_endpoint("dev-1", "LAB-PC-01", grup=["lab-a"])
        self.m.tambah_layanan("svc-demo", "dev-1", "MirrorDemo")
        self.m.tambah_layanan("svc-api", "dev-1", "APIInternal")

    def test_endpoint_duplikat_ditolak(self):
        with self.assertRaises(TwinError):
            self.m.tambah_endpoint("dev-1", "duplikat")

    def test_layanan_dev_tak_ada_ditolak(self):
        with self.assertRaises(TwinError):
            self.m.tambah_layanan("svc-x", "dev-99", "X")

    def test_dependensi_terverifikasi_wajib_bukti(self):
        with self.assertRaises(TwinError):
            self.m.tambah_dependensi("svc-api", "svc-demo",
                                     terverifikasi=True, bukti=None)

    def test_status_dan_kesehatan_jujur(self):
        s = self.m.status()
        self.assertEqual(s["n_layanan"], 2)
        self.assertEqual(s["endpoints"][0]["sehat"], None)
        self.assertIn("TIDAK DIKETAHUI", s["endpoints"][0]["sehat_catatan"])

    def test_temuan_confidence_range(self):
        with self.assertRaises(TwinError):
            self.m.tambah_temuan("f1", "x", 1.5, ["bukti"])
        self.m.tambah_temuan("f1", "port C2 aktif", 0.8, ["netmon flow"])
        self.assertEqual(self.m.status()["temuan"][0]["confidence"], 0.8)

    def test_what_if_matikan_layanan(self):
        self.m.tambah_dependensi("svc-api", "svc-demo",
                                 terverifikasi=True,
                                 bukti="telemetri koneksi teramati")
        self.m.tambah_dependensi("dev-1", "svc-demo")  # asumsi (tanpa bukti)
        r = self.m.what_if("matikan_layanan", "svc-demo")
        self.assertTrue(r["model_saja"])
        self.assertEqual(len(r["dampak_terverifikasi"]), 1)
        self.assertIn("bukti", r["dampak_terverifikasi"][0])
        self.assertEqual(len(r["asumsi"]), 1)
        self.assertIn("ASUMSI", r["asumsi"][0])
        self.assertIn("peringatan", r)
        self.assertTrue(r["usulan_uji_validasi"])

    def test_what_if_target_tak_ada(self):
        with self.assertRaises(TwinError):
            self.m.what_if("matikan_layanan", "svc-ngawur")

    def test_what_if_tercatat_sejarah(self):
        self.m.what_if("matikan_layanan", "svc-demo")
        self.assertIn("SIMULASI", self.m.sejarah[-1]["perubahan"])

    def test_sejarah_konfigurasi(self):
        self.m.catat_perubahan("svc-demo", "status=BERHENTI", oleh="test")
        self.assertEqual(len(self.m.sejarah), 1)


class TestRemediasi(unittest.TestCase):
    def buat(self, **kw):
        d = {"temuan_id": "f-1", "deskripsi": "port C2 demo aktif",
             "bukti": ["netmon flow 4444"], "usulan": "blokir via scope",
             "diff": "- 4444 → tolak", "zona": "konfigurasi_aplikasi"}
        d.update(kw)
        return Remediasi(**d)

    def engine(self, lulus=True, apply_ok=True, verif_ok=True,
               ada_rollback=True):
        state = {"di_rollback": False}
        return RemediationEngine(
            tester=lambda r: {"lulus": lulus, "n": 12},
            applier=lambda r: apply_ok,
            verifier=lambda r: (verif_ok, "cek pasca") if verif_ok
            else (False, "postcondition gagal"),
            rollback=lambda cp: state.update(di_rollback=True) or
            {"dipulihkan": True},
            checkpoint=lambda r: {"backup": "cfg-lama"}), state

    def test_langkah_dasar_dan_klasifikasi(self):
        r = self.buat()
        r.klasifikasi_risiko()
        self.assertEqual(r.state, "DIKLASIFIKASI")

    def test_temuan_tanpa_bukti_ditolak(self):
        with self.assertRaises(RemediasiError):
            self.buat(bukti=[])

    def test_zona_larangan_tanpa_recovery_plan_ditolak(self):
        r = self.buat(zona="firewall")
        with self.assertRaises(RemediasiError):
            r.klasifikasi_risiko()
        r2 = self.buat(zona="firewall", recovery_plan="pulihkan via bak")
        r2.klasifikasi_risiko()  # dengan rencana pemulihan → boleh lanjut

    def test_alur_sukses_penuh(self):
        r = self.buat()
        r.klasifikasi_risiko()
        eng, _ = self.engine()
        eng.inspeksi_diff(r)
        eng.jalankan_tes(r)
        self.assertTrue(eng.minta_persetujuan(r, oleh_admin="admin"))
        hasil = eng.terapkan(r)
        self.assertEqual(hasil["hasil"], "SUKSES_TERVERIFIKASI")

    def test_tes_gagal_menghentikan(self):
        r = self.buat()
        r.klasifikasi_risiko()
        eng, _ = self.engine(lulus=False)
        eng.inspeksi_diff(r)
        with self.assertRaises(RemediasiError):
            eng.jalankan_tes(r)
        self.assertEqual(r.state, "TES_GAGAL")

    def test_tanpa_persetujuan_tak_bisa_terapkan(self):
        r = self.buat()
        r.klasifikasi_risiko()
        eng, _ = self.engine()
        eng.inspeksi_diff(r)
        eng.jalankan_tes(r)
        eng.minta_persetujuan(r)  # tidak ada admin → menunggu
        self.assertEqual(r.state, "MENUNGGU_PERSETUJUAN")
        with self.assertRaises(RemediasiError):
            eng.terapkan(r)

    def test_verifikasi_gagal_rollback_otomatis(self):
        r = self.buat()
        r.klasifikasi_risiko()
        eng, state = self.engine(verif_ok=False, ada_rollback=True)
        eng.inspeksi_diff(r)
        eng.jalankan_tes(r)
        eng.minta_persetujuan(r, oleh_admin="admin")
        hasil = eng.terapkan(r)
        self.assertEqual(hasil["hasil"], "ROLLBACK")
        self.assertTrue(state["di_rollback"])
        self.assertEqual(r.data["rollback_hasil"]["dipulihkan"], True)

    def test_rollback_tak_tersedia_dijujurkan(self):
        r = self.buat()
        r.klasifikasi_risiko()
        eng = RemediationEngine(
            tester=lambda r: {"lulus": True},
            applier=lambda r: False,
            verifier=lambda r: (False, "x"),
            rollback=None, checkpoint=None)
        eng.inspeksi_diff(r)
        eng.jalankan_tes(r)
        eng.minta_persetujuan(r, oleh_admin="admin")
        hasil = eng.terapkan(r)
        self.assertEqual(hasil["hasil"], "GAGAL")
        self.assertIn("TIDAK TERSEDIA", r.data["rollback_hasil"])

    def test_laporan_teks(self):
        r = self.buat()
        r.klasifikasi_risiko()
        eng, _ = self.engine()
        eng.inspeksi_diff(r)
        eng.jalankan_tes(r)
        eng.minta_persetujuan(r, oleh_admin="admin")
        eng.terapkan(r)
        teks = laporan_teks(r)
        self.assertIn("REMEDIASI f-1", teks)
        self.assertIn("SUKSES_TERVERIFIKASI", teks)


if __name__ == "__main__":
    unittest.main()
