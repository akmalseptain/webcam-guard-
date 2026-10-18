#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test slc_demo + slc_ui v4.0 — demo sintetis berlabel, laporan evaluasi,
command center: frame event-driven, kontrol aksesibilitas, kejujuran data."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import slc_demo  # noqa: E402
import slc_ui  # noqa: E402


class TestDemoMode(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="slc_demo_t_")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_demo_misi_sintetis_lengkap(self):
        r = slc_demo.jalankan_demo(direktori=os.path.join(self.d, "a"),
                                   tampilkan=False)
        self.assertEqual(r["mode"], "DEMO")
        self.assertEqual(r["n_perangkat_sintetis"], 3)
        self.assertIn("SINTETIS", r["label_data"])
        for l in r["misi"]["langkah"] if "langkah" in r["misi"] else r["langkah"]:
            self.assertEqual(l["status"], "SELESAI_TERVERIFIKASI")
        self.assertIn("SINTETIS", r["output_teks"])
        self.assertIn("bukan perangkat nyata", r["label_data"].lower())

    def test_demo_tidak_pernah_pura_pura_nyata(self):
        inv = slc_demo.data_sintetis_inventaris()
        for d in inv:
            self.assertEqual(d["label"], slc_demo.LABEL_SINTETIS)

    def test_parse_hasil_ok_dan_gagal(self):
        ok = slc_demo.parse_hasil(
            "Ran 30 tests in 1.0s\n\nOK (skipped=2)\n")
        self.assertEqual(ok["total"], 30)
        self.assertTrue(ok["ok"])
        self.assertEqual(ok["skip"], 2)
        gagal = slc_demo.parse_hasil(
            "Ran 30 tests\n\nFAILED (failures=1, errors=2)\n")
        self.assertEqual((gagal["gagal"], gagal["error"]), (1, 2))

    def test_laporan_evaluasi_kategorinya_lengkap(self):
        md = slc_demo.laporan_evaluasi_md(
            teks_suite="Ran 10 tests\n\nOK\n")
        self.assertIn("acceptance", md.lower() or md)
        self.assertIn("TIDAK DIJALANKAN", md)
        self.assertIn("TLS", md)
        self.assertIn("Windows Service", md)

    def test_laporan_evaluasi_bisa_ditulis(self):
        p = os.path.join(self.d, "lap.md")
        slc_demo.laporan_evaluasi_md(
            teks_suite="Ran 5 tests\n\nOK\n", path_tulis=p)
        self.assertTrue(os.path.exists(p))


class TestCommandCenter(unittest.TestCase):
    def test_banner_tidak_menyamar(self):
        b = slc_ui.render_banner(mode="FISIK")
        self.assertIn("administrasi jarak jauh", b.lower() or b.lower())
        self.assertIn("EMERGENCY STOP", b)

    def test_frame_horor_event_driven(self):
        kritis = slc_ui.render_frame_horor({"severity": "KRITIS",
                                            "event": "beacon C2"})
        info = slc_ui.render_frame_horor({"severity": "INFO",
                                          "event": "hb"})
        self.assertNotEqual(kritis, info)
        self.assertIn("KRITIS", kritis)

    def test_frame_sintetis_dilabeli(self):
        f = slc_ui.render_frame_horor({"severity": "INFO",
                                       "event": "demo",
                                       "asal": "sintetis"})
        self.assertIn("SINTETIS", f)

    def test_kontrol_aksesibilitas(self):
        # gerak minim
        self.assertIn("gerak minim", slc_ui.render_frame_horor(
            {"severity": "PERINGATAN", "event": "x"}, gerak=False))
        # bisu → tanpa ikon suara
        self.assertNotIn("🔊", slc_ui.render_banner(bisu=True))
        self.assertIn("🔊", slc_ui.render_banner())
        # mode polos → tanpa emoji animasi
        self.assertNotIn("⚡", slc_ui.render_banner(mode_polos=True))
        self.assertNotIn("☠", slc_ui.render_frame_horor(
            {"severity": "KRITIS", "event": "x"}, mode_polos=True))

    def test_peta_lab_jujur_belum_terhubung(self):
        inv = [{"id": "d1", "nama": "PC-1", "grup": [], "last_seen": None,
                "emergency": False, "tertunda": 0}]
        p = slc_ui.render_peta_lab(inv)
        self.assertIn("TIDAK berarti sehat", p)
        self.assertIn("?", p)

    def test_timeline_kosong_jujur(self):
        t = slc_ui.render_timeline([])
        self.assertIn("TIDAK ADA DATA", t)

    def test_misi_replay_dari_data(self):
        m = type("M", (), {"nama": "uji", "state": "REPORTING",
                           "urutan": [{"id": "l1", "aksi": "kesehatan",
                                       "dev": "d1",
                                       "status": "SELESAI_TERVERIFIKASI"}]})
        r = slc_ui.render_misi_replay(m)
        self.assertIn("✓", r)
        self.assertIn("REPLAY MISI", r)

    def test_investigasi_kejujuran(self):
        r = slc_ui.render_investigasi({"per_dev": {}}, [])
        self.assertIn("TIDAK ADA DATA", r)
        r2 = slc_ui.render_investigasi({"per_dev": {"d1": 7}},
                                        [{"aturan": {"kind": "netmon"}}])
        self.assertIn("d1: 7", r2)
        self.assertIn("ALERT", r2)

    def test_grafik_aktivitas(self):
        g = slc_ui.render_grafik_aktivitas([1, 2, 3])
        self.assertIn("GRAFIK", g)
        self.assertIn("TIDAK ADA DATA", slc_ui.render_grafik_aktivitas([]))


if __name__ == "__main__":
    unittest.main()
