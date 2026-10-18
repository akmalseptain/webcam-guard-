"""test_evidence.py — Evidence pack: build, manifest SHA-256, verify
read-only, deteksi tamper, pemisahan RAW vs DERIVED."""
import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence
import forensics


class TestEvidencePack(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.events = os.path.join(self.dir.name, "lab_events.jsonl")
        self.audit = os.path.join(self.dir.name, "lab_audit.jsonl")
        self.out = os.path.join(self.dir.name, "evidence_pack")
        store = forensics.EventStore(self.events)
        for i in range(4):
            store.append(forensics.normalize(
                "netmon" if i % 2 == 0 else "redsim",
                "anomali beacon terdeteksi" if i == 0 else f"event-{i}",
                f"detail-{i}", host="lab-01"))

    def tearDown(self):
        self.dir.cleanup()

    def test_build_menghasilkan_file_paket(self):
        hasil = evidence.build_pack(self.events, self.audit, self.out)
        self.assertTrue(hasil["rantai_utuh"])
        for nama in ("events.json", "analysis.json", "events.csv",
                     "report.md", "manifest.json", "reproduce.txt"):
            self.assertTrue(os.path.exists(os.path.join(self.out, nama)),
                            f"file paket hilang: {nama}")

    def test_verify_utuh(self):
        evidence.build_pack(self.events, self.audit, self.out)
        hasil = evidence.verify_pack(self.out)
        self.assertTrue(hasil["utuh"], hasil["masalah"])
        self.assertEqual(hasil["n_file"], 4)

    def test_tamper_file_terdeteksi(self):
        evidence.build_pack(self.events, self.audit, self.out)
        # ubah isi RAW tanpa update manifest
        p = os.path.join(self.out, "events.json")
        with open(p, "a", encoding="utf-8") as f:
            f.write("\n/* disisipkan */")
        hasil = evidence.verify_pack(self.out)
        self.assertFalse(hasil["utuh"])
        self.assertTrue(any("SHA-256" in m for m in hasil["masalah"]))

    def test_file_hilang_terdeteksi(self):
        evidence.build_pack(self.events, self.audit, self.out)
        os.unlink(os.path.join(self.out, "report.md"))
        hasil = evidence.verify_pack(self.out)
        self.assertFalse(hasil["utuh"])
        self.assertTrue(any("hilang" in m for m in hasil["masalah"]))

    def test_raw_dan_derived_dipisah(self):
        evidence.build_pack(self.events, self.audit, self.out)
        with open(os.path.join(self.out, "manifest.json"),
                  encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest["file"]["events.json"]["kelas"], "raw")
        self.assertEqual(manifest["file"]["analysis.json"]["kelas"],
                         "derived")
        self.assertEqual(manifest["file"]["events.csv"]["kelas"], "raw")
        self.assertEqual(manifest["file"]["report.md"]["kelas"], "derived")

    def test_verify_read_only(self):
        evidence.build_pack(self.events, self.audit, self.out)
        sebelum = {}
        for nama in sorted(os.listdir(self.out)):
            with open(os.path.join(self.out, nama), "rb") as f:
                sebelum[nama] = hashlib.sha256(f.read()).hexdigest()
        evidence.verify_pack(self.out)
        for nama, h in sebelum.items():
            with open(os.path.join(self.out, nama), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), h,
                                 f"verify_pack MENULIS file {nama}!")

    def test_rantai_sumber_rusak_dilaporkan(self):
        evidence.build_pack(self.events, self.audit, self.out)
        # rusak rantai sumber SETELAH paket dibangun
        with open(self.events, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": "x", "kind": "netmon", "host": "h",
                                "event": "e", "detail": "d",
                                "prev": "salah", "hash": "salah"}) + "\n")
        hasil = evidence.verify_pack(self.out)
        self.assertFalse(hasil["utuh"])
        self.assertTrue(any("rusak" in m for m in hasil["masalah"]))


if __name__ == "__main__":
    unittest.main()
