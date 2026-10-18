# -*- coding: utf-8 -*-
"""Test range_report.py — laporan before/after + kriteria terukur (R5).

TIDAK menjalankan posture penuh di sini (~30-60 dtk PBKDF2); hasil
posture di-inject sebagai dict tiruan. Pengukur cepat (netmon
evaluasi + scenario loopback) diuji NYATA.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from range_report import (BASELINE_V2, KRITERIA, bangun_laporan,
                          render_teks, main, ukur_netmon, ukur_skenario,
                          _delta)

SCOPE_LOOPBACK = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "scope_loopback.json")

POSTURE_OK = {"skor": 93.8, "n_lulus": 14, "n_peringat": 2,
              "n_gagal": 0, "bloker": []}
NETMON_OK = {"n_fixture": 9, "TP": 3, "FP": 0, "FN": 1, "TN": 5,
             "precision": 1.0, "recall": 0.75, "fpr": 0.0, "fnr": 0.25,
             "rincian": []}
SKENARIO_OK = {"n_dijalankan": 4, "n_terdeteksi": 4,
               "detection_rate": 1.0, "coverage": {}}


def _lap_full(**kw):
    a = {"n_test": 326, "n_test_range": 122, "hasil_posture": POSTURE_OK,
         "hasil_netmon": NETMON_OK, "hasil_skenario": SKENARIO_OK}
    a.update(kw)
    return bangun_laporan(**a)


class TestBaseline(unittest.TestCase):
    def test_baseline_dikunci_v2(self):
        self.assertEqual(BASELINE_V2["n_test"], 204)
        self.assertEqual(BASELINE_V2["posture_skor"], 93.8)
        self.assertEqual(BASELINE_V2["netmon"]["precision"], 1.0)
        self.assertEqual(BASELINE_V2["netmon"]["recall"], 0.75)
        self.assertIsNone(BASELINE_V2["skenario"])

    def test_lima_kriteria(self):
        self.assertEqual([k["id"] for k in KRITERIA],
                         ["K1", "K2", "K3", "K4", "K5"])


class TestKriteria(unittest.TestCase):
    def test_semua_lulus(self):
        lap = _lap_full()
        self.assertEqual([k["status"] for k in lap["kriteria"]],
                         ["LULUS"] * 5)
        self.assertTrue(lap["ringkasan"]["semua_lulus"])

    def test_k1_gagal_test_kurang(self):
        lap = _lap_full(n_test=250)
        self.assertEqual(lap["kriteria"][0]["status"], "GAGAL")
        self.assertFalse(lap["ringkasan"]["semua_lulus"])

    def test_k2_gagal_test_range_kurang(self):
        lap = _lap_full(n_test_range=50)
        self.assertEqual(lap["kriteria"][1]["status"], "GAGAL")

    def test_k3_gagal_posture_regres(self):
        lap = _lap_full(hasil_posture=dict(POSTURE_OK, skor=90.0))
        self.assertEqual(lap["kriteria"][2]["status"], "GAGAL")

    def test_k3_gagal_ada_bloker(self):
        p = dict(POSTURE_OK, n_gagal=1, bloker=["P-16"])
        lap = _lap_full(hasil_posture=p)
        self.assertEqual(lap["kriteria"][2]["status"], "GAGAL")

    def test_k4_gagal_netmon_regres(self):
        n = dict(NETMON_OK, recall=0.5)
        lap = _lap_full(hasil_netmon=n)
        self.assertEqual(lap["kriteria"][3]["status"], "GAGAL")

    def test_k5_gagal_skenario_tak_penuh(self):
        s = dict(SKENARIO_OK, n_terdeteksi=3, detection_rate=0.75)
        lap = _lap_full(hasil_skenario=s)
        self.assertEqual(lap["kriteria"][4]["status"], "GAGAL")

    def test_tak_diukur_bukan_gagal(self):
        lap = bangun_laporan()
        self.assertEqual([k["status"] for k in lap["kriteria"]],
                         ["TIDAK DIUKUR"] * 5)
        self.assertEqual(lap["ringkasan"]["n_gagal"], 0)
        self.assertEqual(lap["ringkasan"]["n_tak_diukur"], 5)
        self.assertTrue(lap["ringkasan"]["semua_lulus"])


class TestUkurNyata(unittest.TestCase):
    def test_ukur_netmon_flat_dict(self):
        n = ukur_netmon()
        for k in ("precision", "recall", "fpr", "fnr",
                  "TP", "FP", "FN", "TN"):
            self.assertIn(k, n)
        self.assertEqual(n["precision"], 1.0)
        self.assertEqual(n["recall"], 0.75)

    def test_ukur_skenario_loopback(self):
        s = ukur_skenario(SCOPE_LOOPBACK)
        self.assertEqual(s["n_dijalankan"], 4)
        self.assertEqual(s["n_terdeteksi"], 4)
        self.assertEqual(s["detection_rate"], 1.0)
        self.assertIn("netmon_beacon", s["coverage"])


class TestRender(unittest.TestCase):
    def test_render_memuat_bagian(self):
        teks = render_teks(_lap_full())
        for frag in ("BASELINE v2.0", "HASIL v3.0",
                     "KRITERIA PENERIMAAN", "[LULUS", "CATATAN JUJUR",
                     "delta +122", "detection_rate=1.0"):
            self.assertIn(frag, teks)

    def test_render_tak_diukur(self):
        teks = render_teks(bangun_laporan())
        self.assertIn("tidak diukur", teks)
        self.assertIn("[TIDAK DIUKUR", teks)

    def test_delta_negatif(self):
        self.assertIn("-", _delta(90.0, 93.8))


class TestCLI(unittest.TestCase):
    def _cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            kode = main(list(argv))
        return kode, buf.getvalue()

    def test_cli_lulus_exit0(self):
        kode, out = self._cli("--n-test", "326", "--n-test-range", "122",
                              "--jalankan-netmon",
                              "--jalankan-skenario", SCOPE_LOOPBACK)
        self.assertEqual(kode, 0)
        self.assertIn("LULUS 4/5", out)      # K3 posture tak diukur (jujur)
        self.assertIn("TIDAK DIUKUR 1", out)

    def test_cli_gagal_exit1(self):
        kode, out = self._cli("--n-test", "250", "--n-test-range", "122",
                              "--jalankan-netmon",
                              "--jalankan-skenario", SCOPE_LOOPBACK)
        self.assertEqual(kode, 1)
        self.assertIn("[GAGAL", out)

    def test_cli_json(self):
        kode, out = self._cli("--n-test", "326", "--n-test-range", "122",
                              "--jalankan-netmon", "--json")
        self.assertEqual(kode, 0)
        lap = json.loads(out)
        self.assertEqual(lap["v3"]["n_test"], 326)
        self.assertIsNotNone(lap["ukur"]["netmon"])
        self.assertIsNone(lap["ukur"]["posture"])

    def test_cli_tulis_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "laporan.md")
            kode, _ = self._cli("--n-test", "326", "--n-test-range",
                                "122", "--jalankan-netmon",
                                "--tulis", path)
            self.assertEqual(kode, 0)
            isi = open(path, encoding="utf-8").read()
            self.assertIn("RANGE REPORT v3.0", isi)
            self.assertIn("DIGENERATE", isi)


if __name__ == "__main__":
    unittest.main()
