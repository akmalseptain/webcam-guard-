#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test slc_control v4.0 — control plane: policy, persetujuan, idempotensi,
kedaluwarsa, emergency stop, verifikasi postcondition, audit."""
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from range_registry import DeviceRegistry  # noqa: E402
import slc_actions  # noqa: E402
from slc_control import KontrolError, SLCControl  # noqa: E402


class Basis(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="slc_")
        reg = DeviceRegistry(path=os.path.join(self.d, "devices.json"),
                             audit_path=os.path.join(self.d, "audit.jsonl"))
        self.c = SLCControl(registry=reg,
                            meta_path=os.path.join(self.d, "meta.json"),
                            history_path=os.path.join(self.d, "hist.jsonl"),
                            audit_path=os.path.join(self.d, "audit.jsonl"),
                            events_path=os.path.join(self.d, "events.jsonl"))
        self.rec = self.c.enroll("LAB-PC-01", grup=["lab-a"], tags=["demo"])

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)


class TestEnrollInventaris(Basis):
    def test_enroll_dan_inventaris(self):
        inv = self.c.inventaris()
        self.assertEqual(len(inv), 1)
        self.assertEqual(inv[0]["nama"], "LAB-PC-01")

    def test_inventaris_filter(self):
        self.c.enroll("LAB-PC-02", grup=["lab-b"], tags=["cadangan"])
        self.assertEqual(len(self.c.inventaris(filter_grup="lab-a")), 1)
        self.assertEqual(len(self.c.inventaris(filter_tag="cadangan")), 1)
        self.assertEqual(len(self.c.inventaris(teks="pc-01")), 1)

    def test_revoke_membekukan(self):
        self.c.revoke(self.rec["id"])
        with self.assertRaises(KeyError):
            self.c.jadwalkan("admin", self.rec["id"], "kesehatan")


class TestPenjadwalan(Basis):
    def test_role_tak_diizinkan(self):
        with self.assertRaises(PermissionError):
            self.c.jadwalkan("auditor", self.rec["id"], "kesehatan")

    def test_aksi_tak_dikenal(self):
        with self.assertRaises(slc_actions.AksiError):
            self.c.jadwalkan("admin", self.rec["id"], "shell")

    def test_perangkat_tak_enroll(self):
        with self.assertRaises(KeyError):
            self.c.jadwalkan("admin", "dev-9999", "kesehatan")

    def test_jadwal_dan_poll(self):
        t = self.c.jadwalkan("admin", self.rec["id"], "kesehatan")
        self.assertEqual(t["status"], "SIAP")
        ambil = self.c.berikutnya(self.rec["id"])
        self.assertEqual(ambil["tugas_id"], t["tugas_id"])
        self.assertEqual(ambil["status"], "DIKIRIM")

    def test_idempotensi_anti_duplikat(self):
        t1 = self.c.jadwalkan("admin", self.rec["id"], "kesehatan", idem="k1")
        t2 = self.c.jadwalkan("admin", self.rec["id"], "kesehatan", idem="k1")
        self.assertEqual(t1["tugas_id"], t2["tugas_id"])
        self.assertEqual(len(self.c._antrean[self.rec["id"]]), 1)

    def test_kedaluwarsa(self):
        self.c.jadwalkan("admin", self.rec["id"], "kesehatan",
                         kedaluwarsa_s=0.05)
        time.sleep(0.08)
        self.assertIsNone(self.c.berikutnya(self.rec["id"]))
        self.assertEqual(self.c.history[-1]["status"], "KEDALUWARSA")

    def test_kedaluwarsa_tidak_menipu_waktu(self):
        t = self.c.jadwalkan("admin", self.rec["id"], "kesehatan",
                             kedaluwarsa_s=60, sekarang=time.time())
        self.assertIsNotNone(self.c.berikutnya(self.rec["id"]))


class TestPersetujuan(Basis):
    def test_tinggi_butuh_persetujuan(self):
        t = self.c.jadwalkan("admin", self.rec["id"], "restart_layanan",
                             {"layanan": "LabAgentDemoSvc"})
        self.assertEqual(t["status"], "MENUNGGU_PERSETUJUAN")
        self.assertIsNone(self.c.berikutnya(self.rec["id"]))  # tidak bocor

    def test_setuju_bukan_admin_ditolak(self):
        t = self.c.jadwalkan("admin", self.rec["id"], "restart_layanan",
                             {"layanan": "LabAgentDemoSvc"})
        with self.assertRaises(PermissionError):
            self.c.setujui(t["tugas_id"], oleh_admin="operator")

    def test_setuju_lalu_tereksekusi(self):
        t = self.c.jadwalkan("admin", self.rec["id"], "restart_layanan",
                             {"layanan": "LabAgentDemoSvc"})
        self.c.setujui(t["tugas_id"], oleh_admin="admin")
        ambil = self.c.berikutnya(self.rec["id"])
        self.assertEqual(ambil["status"], "DIKIRIM")

    def test_setujui_dua_kali_ditolak(self):
        t = self.c.jadwalkan("admin", self.rec["id"], "restart_layanan",
                             {"layanan": "LabAgentDemoSvc"})
        self.c.setujui(t["tugas_id"])
        with self.assertRaises(Exception):
            self.c.setujui(t["tugas_id"])


class TestEmergencyBatal(Basis):
    def test_emergency_stop(self):
        self.c.jadwalkan("admin", self.rec["id"], "kesehatan")
        self.c.emergency_stop(self.rec["id"])
        self.assertEqual(self.c._antrean[self.rec["id"]], [])
        with self.assertRaises(KontrolError):
            self.c.jadwalkan("admin", self.rec["id"], "kesehatan")
        self.assertIn("EMERGENCY STOP aktif",
                      self.c.detail_perangkat(self.rec["id"])["peringatan"])

    def test_lepas_emergency(self):
        self.c.emergency_stop(self.rec["id"])
        self.c.lepas_emergency(self.rec["id"])
        t = self.c.jadwalkan("admin", self.rec["id"], "kesehatan")
        self.assertEqual(t["status"], "SIAP")

    def test_batalkan_sebelum_eksekusi(self):
        t = self.c.jadwalkan("admin", self.rec["id"], "kesehatan")
        self.c.batalkan(t["tugas_id"])
        self.assertIsNone(self.c.berikutnya(self.rec["id"]))
        self.assertEqual(self.c.history[-1]["status"], "DIBATALKAN")

    def test_batalkan_yang_selesai_ditolak(self):
        t = self.c.jadwalkan("admin", self.rec["id"], "kesehatan")
        self.c.berikutnya(self.rec["id"])
        self.c.terima_hasil(self.rec["id"], t["tugas_id"],
                            {"data": {"platform": "test"}})
        with self.assertRaises(KontrolError):
            self.c.batalkan(t["tugas_id"])


class TestVerifikasiHasil(Basis):
    def _jalankan(self, aksi="kesehatan", params=None, hasil=None):
        t = self.c.jadwalkan("admin", self.rec["id"], aksi, params)
        self.c.berikutnya(self.rec["id"])
        return self.c.terima_hasil(self.rec["id"], t["tugas_id"],
                                   hasil or {"data": {"platform": "Linux"}})

    def test_postcondition_terverifikasi(self):
        t = self._jalankan()
        self.assertEqual(t["status"], "SELESAI_TERVERIFIKASI")

    def test_postcondition_gagal_ditandai(self):
        t = self._jalankan(hasil={"data": {}})  # tanpa platform → gagal verif
        self.assertEqual(t["status"], "GAGAL_VERIFIKASI")

    def test_error_eksekusi_jujur(self):
        t = self._jalankan(hasil={"error": "agent timeout"})
        self.assertEqual(t["status"], "GAGAL")

    def test_hasil_tak_dikenal_ditolak(self):
        with self.assertRaises(KeyError):
            self.c.terima_hasil(self.rec["id"], "t-tidak-ada", {"data": {}})

    def test_aksi_tanpa_verifikasi_tetap_selesai(self):
        t = self._jalankan(aksi="disk")
        self.assertEqual(t["status"], "SELESAI_TERVERIFIKASI")


class TestPolicyDetail(Basis):
    def test_policy_perangkat_melarang(self):
        self.c.set_meta(self.rec["id"],
                        policy={"aksi_diizinkan": ["disk"]})
        with self.assertRaises(KontrolError):
            self.c.jadwalkan("admin", self.rec["id"], "kesehatan")
        t = self.c.jadwalkan("admin", self.rec["id"], "disk")
        self.assertEqual(t["status"], "SIAP")

    def test_detail_perangkat(self):
        d = self.c.detail_perangkat(self.rec["id"])
        for k in ("id", "aksi_diizinkan", "aktivitas", "tugas_tertunda",
                  "peringatan", "last_seen"):
            self.assertIn(k, d)
        self.assertIn("kesehatan", d["aksi_diizinkan"])
        self.assertIn("belum pernah terhubung", d["peringatan"][0])

    def test_audit_utuh(self):
        self.c.jadwalkan("admin", self.rec["id"], "kesehatan")
        self.assertTrue(self.c.sehat_audit())


if __name__ == "__main__":
    unittest.main()
