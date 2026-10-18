#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test slc_redblue v4.0 — matriks coverage, precision/recall, FP,
cleanup verification, perbandingan baseline-improved, laporan."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import slc_redblue as rb  # noqa: E402


class TestRedBlue(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="rb_")
        self.scope = os.path.join(self.d, "scope.json")
        with open(self.scope, "w") as f:
            # scope lab sah utk runner (format lab_scope.json: hosts+cidrs)
            import json
            json.dump({"hosts": ["lab-01.local", "lab-02.local"],
                       "cidrs": ["192.168.56.0/24"]}, f)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_definisi_4_skenario_sintetis(self):
        d = rb.definisi_evaluasi()
        self.assertEqual(len(d), 4)
        for s in d:
            self.assertTrue(s["sintetis"])
            self.assertTrue(s["deteksi_diharapkan"])

    def test_jalankan_red_matriks(self):
        red = rb.jalankan_red(scope_path=self.scope,
                              events_path=os.path.join(self.d, "ev.jsonl"),
                              audit_path=os.path.join(self.d, "au.jsonl"))
        self.assertEqual(len(red["matriks"]), 4)
        for m in red["matriks"]:
            self.assertIn(m["id"], ("RB-01", "RB-02", "RB-03", "RB-04"))
            self.assertIn("cleanup", m)
            self.assertIn("evidence_ref", m)
        self.assertIn("sintetis", red["catatan_sintetis"].lower() or
                      red["catatan_sintetis"])

    def test_jalankan_blue_precision_recall(self):
        blue = rb.jalankan_blue()
        self.assertIn("precision", blue)
        self.assertIn("recall", blue)
        self.assertIn("rincian", blue)
        self.assertGreaterEqual(blue["n_fixture"], 9)

    def test_analisis_fp(self):
        blue = rb.jalankan_blue()
        fp = rb.analisis_fp(blue)
        self.assertEqual(fp["n_fp"], blue["FP"])
        self.assertEqual(fp["n_fn"], blue["FN"])
        self.assertTrue(fp["saran"])

    def test_bandingkan_konfigurasi_jujur(self):
        base = {"precision": 1.0, "recall": 0.75, "fpr": 0.0}
        impr = {"precision": 1.0, "recall": 1.0, "fpr": 0.0}
        c = rb.bandingkan_konfigurasi(base, impr)
        self.assertEqual(c["recall"]["delta"], 0.25)
        self.assertEqual(c["verdict"], "membaik")
        # TIDAK_DIUKUR tidak diklaim membaik
        c2 = rb.bandingkan_konfigurasi({"precision": 1.0}, impr)
        self.assertIn("TIDAK_DIUKUR", c2["recall"]["catatan"])

    def test_laporan_md(self):
        red = rb.jalankan_red(scope_path=self.scope,
                              events_path=os.path.join(self.d, "ev.jsonl"),
                              audit_path=os.path.join(self.d, "au.jsonl"))
        blue = rb.jalankan_blue()
        teks = rb.laporan_md(red=red, blue=blue,
                             fp=rb.analisis_fp(blue))
        self.assertIn("Matriks RED", teks)
        self.assertIn("precision", teks)
        self.assertIn("sintetis", teks)


if __name__ == "__main__":
    unittest.main()
