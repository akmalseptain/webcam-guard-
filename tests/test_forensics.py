"""test_forensics.py — Unit test normalisasi, EventStore, korelasi, laporan."""
import csv
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import forensics


class TestNormalize(unittest.TestCase):
    def test_normalisasi_valid(self):
        e = forensics.normalize("netmon", "anomali port_scan",
                                "10 port berbeda", host="lab-01")
        self.assertEqual(e["kind"], "netmon")
        self.assertEqual(e["host"], "lab-01")
        self.assertIn("ts", e)

    def test_kind_tidak_dikenal_raise(self):
        with self.assertRaises(ValueError):
            forensics.normalize("trojan", "x")

    def test_delapan_kind_lengkap(self):
        self.assertEqual(len(forensics.KINDS), 8)
        for k in forensics.KINDS:
            e = forensics.normalize(k, "tes")
            self.assertEqual(e["kind"], k)


class TestEventStore(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "events.jsonl")
        self.store = forensics.EventStore(self.path)

    def tearDown(self):
        self.dir.cleanup()

    def _isi(self, n=5):
        for i in range(n):
            self.store.append(forensics.normalize(
                "netmon" if i % 2 == 0 else "redsim",
                f"event-{i}" if i != 0 else "anomali beacon terdeteksi",
                f"detail-{i}", host="lab-01"))

    def test_append_dan_load(self):
        self._isi(3)
        self.assertEqual(len(self.store.load()), 3)

    def test_rantai_utuh(self):
        self._isi(4)
        self.assertIsNone(self.store.verify())

    def test_tamper_terdeteksi(self):
        self._isi(4)
        entries = self.store.load()
        entries[1]["detail"] = "DIGANTI"
        with open(self.path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        idx = self.store.verify()
        self.assertIsNotNone(idx)
        self.assertEqual(idx, 1)

    def test_query_filter_kind(self):
        self._isi(6)  # 3 netmon, 3 redsim
        self.assertEqual(len(self.store.query(kind="netmon")), 3)
        self.assertEqual(len(self.store.query(kind="redsim")), 3)

    def test_query_filter_host(self):
        self._isi(3)
        self.assertEqual(len(self.store.query(host="lab-01")), 3)
        self.assertEqual(len(self.store.query(host="lain")), 0)

    def test_timeline_terurut(self):
        self.store.append(forensics.normalize("netmon", "b", ts="2026-01-01 00:00:05"))
        self.store.append(forensics.normalize("netmon", "a", ts="2026-01-01 00:00:01"))
        tl = self.store.timeline()
        self.assertEqual(tl[0]["event"], "a")
        self.assertEqual(tl[1]["event"], "b")

    def test_correlate_mengelompokkan(self):
        self.store.append(forensics.normalize("netmon", "anomali beacon T1071",
                                              "beacon", host="lab-01"))
        self.store.append(forensics.normalize("redsim", "skenario terdeteksi",
                                              "S2", host="lab-01"))
        self.store.append(forensics.normalize("audit", "login biasa",
                                              "ok", host="lab-02"))
        grup = self.store.correlate()
        self.assertTrue(any(g["host"] == "lab-01" and g["n_event"] == 2
                            for g in grup))

    def test_export_csv(self):
        self._isi(3)
        out = os.path.join(self.dir.name, "ekspor.csv")
        forensics.export_csv(self.store.load(), out)
        with open(out, encoding="utf-8") as f:
            rows = list(csv.reader(f))
        self.assertEqual(len(rows), 4)  # header + 3
        self.assertEqual(rows[0][0], "ts")

    def test_build_report_memuat_ringkasan(self):
        self._isi(3)
        laporan = forensics.build_report(self.store)
        self.assertIn("Integritas rantai event: OK", laporan)
        self.assertIn("Timeline kronologis", laporan)


if __name__ == "__main__":
    unittest.main()
