#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_slc_lab.py — regresi demo lab 1-perintah (slc_lab).

Memastikan alur end-to-end SATU proses tetap bekerja:
enroll → server TCP → agent loopback (socket NYATA) → tugas
endpoint-side terverifikasi → emergency stop → misi MissionEngine →
integritas audit. Ini test integrasi TERBESAR SLC (lintas 6 modul)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from slc_lab import jalankan_lab  # noqa: E402


class TestLabEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="test_slc_lab_")
        cls.hasil = jalankan_lab(direktori=cls.d, tampilkan=False)

    def test_tugas_tcp_terverifikasi(self):
        """Fase B: 3 tugas dieksekusi endpoint-side lewat socket TCP
        loopback NYATA dan SEMUA terverifikasi postcondition."""
        self.assertEqual(self.hasil["n_tugas_tcp_ok"], 3, self.hasil["log"][-8:])

    def test_misi_laporan_reporting_semua_sukses(self):
        """Fase D: misi sampai REPORTING dengan seluruh langkah
        SELESAI_TERVERIFIKASI."""
        m = self.hasil["misi"]
        self.assertEqual(m["state"], "REPORTING")
        self.assertEqual(m["status_langkah"].get("SELESAI_TERVERIFIKASI"),
                         m["n_langkah"])

    def test_integritas_audit_utuh(self):
        """Fase E: rantai audit hash-chain tetap utuh setelah seluruh
        alur (jujur: bukan sekadar 'tidak crash')."""
        self.assertTrue(self.hasil["integritas_audit"])

    def test_flag_ok_true(self):
        self.assertTrue(self.hasil["ok"])


if __name__ == "__main__":
    unittest.main()
