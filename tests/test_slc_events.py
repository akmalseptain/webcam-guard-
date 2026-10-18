#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test slc_events v4.0 — normalisasi, dedup, retensi, cari, alert,
korelasi, historis, pelabelan sintetis/telemetri/replay/inferensi."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from slc_events import EventPipeline, normalisasi  # noqa: E402


class TestNormalisasi(unittest.TestCase):
    def test_skema_lengkap(self):
        e = normalisasi({"kind": "slc", "event": "hb", "detail": "hidup"},
                        asal="telemetri", dev="DEV-1", misi="m-1")
        for k in ("id", "ts", "kind", "severity", "confidence",
                 "sumber", "asal", "dev", "misi"):
            self.assertIn(k, e)
        self.assertEqual(e["severity"], "INFO")

    def test_asal_wajib_valid(self):
        with self.assertRaises(ValueError):
            normalisasi({"kind": "slc"}, asal="karangan")

    def test_kind_dan_severity_tak_dikenal_ditolak(self):
        with self.assertRaises(ValueError):
            normalisasi({"kind": "ngawur"})
        with self.assertRaises(ValueError):
            normalisasi({"kind": "slc", "severity": "PANIK"})

    def test_confidence_inferensi_lebih_rendah(self):
        inf = normalisasi({"kind": "netmon", "event": "x"}, asal="inferensi")
        tel = normalisasi({"kind": "netmon", "event": "x"}, asal="telemetri")
        self.assertLess(inf["confidence"], tel["confidence"])


class TestPipeline(unittest.TestCase):
    def test_dedup_jendela(self):
        p = EventPipeline(dedup_jendela_s=60)
        e1 = p.masuk({"kind": "slc", "event": "hb"}, dev="D1",
                     ts_abs=time.time())
        e2 = p.masuk({"kind": "slc", "event": "hb"}, dev="D1",
                     ts_abs=time.time() + 1)
        self.assertIsNotNone(e1)
        self.assertIsNone(e2)  # duplikat dibuang
        self.assertEqual(len(p.events), 1)

    def test_dedup_lewat_jendela_diterima(self):
        p = EventPipeline(dedup_jendela_s=1)
        p.masuk({"kind": "slc", "event": "hb"}, dev="D1", ts_abs=1000.0)
        e = p.masuk({"kind": "slc", "event": "hb"}, dev="D1", ts_abs=2000.0)
        self.assertIsNotNone(e)
        self.assertEqual(len(p.events), 2)

    def test_dev_bedadak_dedup_terpisah(self):
        p = EventPipeline()
        p.masuk({"kind": "slc", "event": "hb"}, dev="D1", ts_abs=1.0)
        e = p.masuk({"kind": "slc", "event": "hb"}, dev="D2", ts_abs=1.0)
        self.assertIsNotNone(e)

    def test_retensi_jumlah(self):
        p = EventPipeline(retensi_maks=3)
        for i in range(5):
            p.masuk({"kind": "slc", "event": f"e{i}"}, dev="D1",
                     ts_abs=100.0 + i * 999)
        self.assertEqual(len(p.events), 3)

    def test_cari_dan_filter(self):
        p = EventPipeline()
        p.masuk({"kind": "netmon", "event": "beacon", "detail": "x"},
                asal="sintetis", dev="D1")
        p.masuk({"kind": "slc", "event": "heartbeat"}, asal="telemetri",
                dev="D2")
        self.assertEqual(len(p.cari(teks="beacon")), 1)
        self.assertEqual(len(p.cari(kind="slc")), 1)
        self.assertEqual(len(p.cari(dev="D1")), 1)
        self.assertEqual(len(p.cari(asal="sintetis")), 1)
        self.assertEqual(len(p.cari(severity_min="PERINGATAN")), 1)

    def test_alert_threshold(self):
        p = EventPipeline()
        p.atur_alert("netmon", 2, 60)
        self.assertEqual(p.cek_alert(), [])
        p.masuk({"kind": "netmon", "event": "a"}, dev="D1", ts_abs=1)
        p.masuk({"kind": "netmon", "event": "b"}, dev="D1", ts_abs=2)
        alert = p.cek_alert()
        self.assertEqual(len(alert), 1)
        self.assertEqual(alert[0]["n"], 2)

    def test_korelasi(self):
        p = EventPipeline()
        p.masuk({"kind": "slc", "event": "a"}, dev="D1", misi="m1",
                ts_abs=1)
        p.masuk({"kind": "slc", "event": "b"}, dev="D1", misi="m1",
                ts_abs=2)
        k = p.korelasi()
        self.assertEqual(k["per_dev"]["D1"], 2)
        self.assertEqual(k["per_misi"]["m1"], 2)


class TestHistorisKejujuran(unittest.TestCase):
    def test_baseline_tanpa_data_ditandai(self):
        p = EventPipeline()
        p.masuk({"kind": "netmon", "event": "a"}, dev="D1", ts_abs=1)
        l = p.bandingkan_historis({"slc": 5})
        by = {x["kind"]: x for x in l}
        self.assertEqual(by["slc"]["kini"], 0)
        self.assertEqual(by["netmon"]["baseline"], None)
        self.assertIn("TIDAK_ADA_DATA", by["netmon"]["catatan"])

    def test_delta_historis(self):
        p = EventPipeline()
        for i in range(3):
            p.masuk({"kind": "slc", "event": f"e{i}"}, dev="D1",
                     ts_abs=100 + i * 999)
        l = p.bandingkan_historis({"slc": 2})
        self.assertEqual(l[0]["delta"], 1)

    def test_label_milik(self):
        p = EventPipeline()
        p.masuk({"kind": "slc", "event": "a"}, asal="telemetri",
                ts_abs=1)
        p.masuk({"kind": "slc", "event": "b"}, asal="sintetis",
                ts_abs=2)
        p.masuk({"kind": "slc", "event": "c"}, asal="replay", ts_abs=3)
        self.assertEqual(p.label_milik(),
                         {"telemetri": 1, "sintetis": 1, "replay": 1})


if __name__ == "__main__":
    unittest.main()
