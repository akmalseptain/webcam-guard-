"""test_fuzz_lab.py — Unit test harness fuzz: determinisme, guard, bounded."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fuzz_lab


class TestDeterminisme(unittest.TestCase):
    def test_seed_sama_hasil_identik(self):
        a = fuzz_lab.run(seed=42)
        b = fuzz_lab.run(seed=42)
        ka = [(h["id"], h["status"]) for h in a["hasil"]]
        kb = [(h["id"], h["status"]) for h in b["hasil"]]
        self.assertEqual(ka, kb)

    def test_hasil_status_valid(self):
        for seed in (42, 7, 1234):
            laporan = fuzz_lab.run(seed=seed)
            for h in laporan["hasil"]:
                self.assertIn(h["status"],
                              ("AMAN", "GUARD_OK", "CRASH", "SKIP"))


class TestGuardBekerja(unittest.TestCase):
    def test_crash_nol(self):
        # di lingkungan lab, fuzz tidak boleh menemukan crash baru;
        # bila CRASH > 0 → REGRESI: perbaiki modul, JANGAN lemahkan test.
        for seed in (42, 7):
            laporan = fuzz_lab.run(seed=seed)
            self.assertEqual(laporan["n_crash"], 0,
                             f"seed {seed}: {[h for h in laporan['hasil'] if h['status'] == 'CRASH']}")

    def test_guard_ok_expected(self):
        """Guard yang membuktikan input jahat ditolak harus muncul:
        payload raksasa, PCAP korup, lockout, kind invalid."""
        laporan = fuzz_lab.run(seed=42)
        status = {(h["id"], h["status"]) for h in laporan["hasil"]}
        self.assertIn(("F1a", "GUARD_OK"), status)
        self.assertIn(("F1c", "GUARD_OK"), status)  # PCAP incl raksasa
        self.assertIn(("F3a", "GUARD_OK"), status)  # payload > 10 MiB
        self.assertIn(("F4", "GUARD_OK"), status)   # lockout brute force
        self.assertIn(("F5", "GUARD_OK"), status)   # kind invalid

    def test_pcap_guard_langsung(self):
        """Regresi bug v-awal: incl_len raksasa -> MemoryError.
        Guard harus menolak SEBELUM membaca."""
        import struct
        import tempfile
        import netmon
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "raksasa.pcap")
            with open(p, "wb") as f:
                f.write(netmon.pcap_global_header())
                f.write(struct.pack("<IIII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF))
                f.write(b"\xde\xad")
            with self.assertRaises(ValueError):
                netmon.baca_pcap(p)
        finally:
            for n in os.listdir(d):
                os.unlink(os.path.join(d, n))
            os.rmdir(d)


class TestBounded(unittest.TestCase):
    def test_waktu_terbatas(self):
        laporan = fuzz_lab.run(seed=42)
        self.assertLess(laporan["waktu_total_s"],
                        fuzz_lab.JATAH_WAKTU_S + 5.0)
        self.assertGreater(laporan["n_case"], 10)


if __name__ == "__main__":
    unittest.main()
