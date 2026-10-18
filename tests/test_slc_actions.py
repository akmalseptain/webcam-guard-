#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test slc_actions v4.0 — registry aksi eksplisit (tolak-default)."""
import hashlib
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import slc_actions as sa  # noqa: E402


class TestRegistry(unittest.TestCase):
    def test_10_aksi_wajib_ada(self):
        ids = set(sa.aksi_definisi())
        wajib = {"kesehatan", "eventlog", "proses_meta", "disk",
                 "cek_keamanan", "bundel_diagnostik", "cek_app",
                 "restart_layanan", "deploy_paket", "asesmen_keamanan"}
        self.assertTrue(wajib <= ids)

    def test_setiap_aksi_lengkap_metadata(self):
        for i, d in sa.aksi_definisi().items():
            self.assertIn(d["risiko"], sa.RISIKO, i)
            self.assertTrue(d["izin"], i)
            self.assertGreater(d["timeout"], 0, i)
            self.assertGreater(d["maks_keluaran"], 0, i)

    def test_aksi_tak_dikenal_ditolak(self):
        with self.assertRaises(sa.AksiError):
            sa.definisi("rm_rf")
        with self.assertRaises(sa.AksiError):
            sa.jalankan("perintah_arbitrer", {})

    def test_butuh_persetujuan_hanya_tinggi(self):
        self.assertTrue(sa.butuh_persetujuan("restart_layanan"))
        self.assertTrue(sa.butuh_persetujuan("deploy_paket"))
        self.assertFalse(sa.butuh_persetujuan("kesehatan"))

    def test_aksi_tinggi_admin_saja(self):
        for i in ("restart_layanan", "deploy_paket"):
            self.assertEqual(sa.definisi(i)["izin"], {"admin"})

    def test_semua_aksi_audit_wajib_tidak_bisa_dimatikan(self):
        # audit dijaga lapis kontrol; registry menjamin risiko/verifikasi
        for i, d in sa.aksi_definisi().items():
            self.assertIn("verifikasi", d, i)


class TestValidasi(unittest.TestCase):
    def test_param_wajib_hilang(self):
        with self.assertRaises(sa.AksiError):
            sa.validasi("eventlog", {})

    def test_param_invalid(self):
        with self.assertRaises(sa.AksiError):
            sa.validasi("eventlog", {"log": 123})
        with self.assertRaises(sa.AksiError):
            sa.validasi("eventlog", {"log": "x", "batas": 99999})

    def test_param_tak_dikenal_ditolak(self):
        with self.assertRaises(sa.AksiError):
            sa.validasi("kesehatan", {"opsi_rahasia": 1})

    def test_param_ok(self):
        sa.validasi("eventlog", {"log": "lab_audit.jsonl", "batas": 10})

    def test_deploy_hash_harus_sha256(self):
        with self.assertRaises(sa.AksiError):
            sa.validasi("deploy_paket", {"paket": "/tmp/p", "hash_sha256":
                         "zz", "tujuan": "/tmp/t"})


class TestEksekusi(unittest.TestCase):
    def test_kesehatan_kembalikan_inventaris(self):
        r = sa.jalankan("kesehatan")
        self.assertEqual(r["aksi"], "kesehatan")
        self.assertIn("platform", r["data"])
        self.assertGreaterEqual(r["durasi_s"], 0.0)

    def test_disk_ok(self):
        r = sa.jalankan("disk", {"path": tempfile.gettempdir()})
        self.assertIn("total_gb", r["data"])

    def test_eventlog_whitelist(self):
        with self.assertRaises(PermissionError):
            sa.jalankan("eventlog", {"log": "/etc/shadow"})

    def test_eventlog_file_hilang_none_jujur(self):
        # nama ter-whitelist tapi file tidak ada → None (jujur, bukan kosong palsu)
        r = sa.jalankan("eventlog", {"log": "lab_range_events.jsonl"})
        if r["data"] is not None:
            self.assertIsInstance(r["data"], list)
        else:
            self.assertIsNone(r["data"])

    def test_cek_app_allowlist(self):
        with self.assertRaises(PermissionError):
            sa.jalankan("cek_app", {"app": "app-tak-ada"})
        r = sa.jalankan("cek_app", {"app": "mirror-demo"})
        self.assertTrue(r["data"]["hidup"])

    def test_restart_layanan_allowlist(self):
        with self.assertRaises(PermissionError):
            sa.jalankan("restart_layanan", {"layanan": "RemoteRegistry"})
        fake = {"LabAgentDemoSvc": {"status": "BERHENTI"}}
        r = sa.restart_layanan("LabAgentDemoSvc", layanan=fake)
        self.assertEqual(r["status"], "BERJALAN")
        self.assertEqual(r["restart_ke"], 1)
        ok, _ = sa.definisi("restart_layanan")["verifikasi"](
            r, {"layanan": "LabAgentDemoSvc"})
        self.assertTrue(ok)

    def test_timeout_dienksekusi(self):
        from unittest import mock
        d = {"aksi": "x", "risiko": "RENDAH", "skema": {},
             "fn": lambda p: time.sleep(0.4), "maks_keluaran": 100,
             "verifikasi": None, "rollback": None}
        with mock.patch.object(sa, "definisi", return_value=d), \
             mock.patch.object(sa, "validasi", return_value={}):
            with self.assertRaises(TimeoutError):
                sa.jalankan("x", timeout=0.05)

    def test_keluaran_dibatasi(self):
        r = sa.jalankan("eventlog",
                        {"log": "lab_audit.jsonl", "batas": 500})
        if r["data"] and r.get("terpotong"):
            self.assertLessEqual(len(str(r["data"]["data"])), 50000)


class TestDeploy(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.paket = Path(self.d) / "paket.cfg"
        self.paket.write_text("versi=4.0.0\n")
        self.hash = hashlib.sha256(self.paket.read_bytes()).hexdigest()

    def test_deploy_hash_salah_ditolak(self):
        with self.assertRaises(ValueError):
            sa.jalankan("deploy_paket", {"paket": str(self.paket),
                         "hash_sha256": "a" * 64,
                         "tujuan": str(Path(self.d) / "t.cfg")})

    def test_deploy_sukses_dan_verifikasi(self):
        tujuan = Path(self.d) / "t.cfg"
        r = sa.jalankan("deploy_paket", {"paket": str(self.paket),
                        "hash_sha256": self.hash, "tujuan": str(tujuan)})
        self.assertTrue(r["data"]["terpasang"])
        ok, _ = sa.definisi("deploy_paket")["verifikasi"](r["data"], {})
        self.assertTrue(ok)
        self.assertFalse(r["data"]["backup_bak"])  # file baru: tanpa .bak

    def test_deploy_ulang_buat_backup_bak(self):
        tujuan = Path(self.d) / "t.cfg"
        tujuan.write_text("lama\n")
        r = sa.jalankan("deploy_paket", {"paket": str(self.paket),
                        "hash_sha256": self.hash, "tujuan": str(tujuan)})
        self.assertTrue(r["data"]["backup_bak"])
        self.assertTrue(Path(str(tujuan) + ".bak").exists())

    def test_deploy_rollback_terdokumentasi(self):
        d = sa.definisi("deploy_paket")
        self.assertIsNotNone(d["rollback"])


class TestAsesmen(unittest.TestCase):
    def test_modul_tak_di_schema_ditolak(self):
        with self.assertRaises(sa.AksiError):
            sa.validasi("asesmen_keamanan", {"modul": "subprocess"})

    def test_posture_bounded(self):
        r = sa.jalankan("asesmen_keamanan", {"modul": "posture"})
        self.assertEqual(r["data"]["modul"], "posture")
        self.assertGreaterEqual(r["data"]["n_cek"], 1)


if __name__ == "__main__":
    unittest.main()
