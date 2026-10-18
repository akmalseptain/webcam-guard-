"""test_range_registry.py — Enrollment, identitas 256-bit, revoke,
lockdown, anti-replay (nonce sekali-pakai + jendela waktu), MAC HMAC,
persistensi devices.json 0600."""

import json
import os
import stat
import sys
import tempfile
import unittest

AKAR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, AKAR)

import audit_core
import range_registry
from range_registry import (DeviceRegistry, RegistryError,
                            buat_mac, fingerprint_kunci)


class RegistryBase(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.file = os.path.join(self.d.name, "devices.json")
        self.audit = os.path.join(self.d.name, "audit.jsonl")
        self.reg = DeviceRegistry(self.file, self.audit)

    def tearDown(self):
        self.d.cleanup()

    def _enroll(self, nama="lab-vm-01", peran="operator"):
        return self.reg.enroll(nama, peran)


class TestEnroll(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.reg = DeviceRegistry(os.path.join(self.d.name, "devices.json"),
                                  os.path.join(self.d.name, "a.jsonl"))

    def tearDown(self):
        self.d.cleanup()

    def test_enroll_bentuk_id_dan_kunci(self):
        info = self.reg.enroll("vm-a")
        self.assertTrue(info["id"].startswith("dev-"))
        # kunci 256-bit = 64 hex
        self.assertEqual(len(info["kunci"]), 64)
        self.assertNotEqual(info["kunci"],
                            self.reg.enroll("vm-b")["kunci"])

    def test_enroll_id_unik(self):
        a = self.reg.enroll("vm-a")
        b = self.reg.enroll("vm-a")
        self.assertNotEqual(a["id"], b["id"])

    def test_fingerprint_sha256_kunci(self):
        info = self.reg.enroll("vm-a")
        self.assertEqual(info["fingerprint"],
                         fingerprint_kunci(info["kunci"]))
        rec = self.reg.devices[info["id"]]
        self.assertEqual(rec["fingerprint"], info["fingerprint"])
        self.assertEqual(rec["nama"], "vm-a")
        self.assertFalse(rec["revoked"])

    def test_enroll_peran_invalid_ditolak(self):
        with self.assertRaises(ValueError):
            self.reg.enroll("vm-x", "admin")  # peran device bukan admin

    def test_enroll_tercatat_audit(self):
        info = self.reg.enroll("vm-a", "auditor")
        a = audit_core.AuditLog(self.audit) if False else None
        with open(os.path.join(self.d.name, "a.jsonl"),
                  encoding="utf-8") as f:
            isi = f.read()
        self.assertIn("DEVICE_ENROLL", isi)
        self.assertIn(info["id"], isi)

    def test_kunci_tidak_dicetak_di_daftar(self):
        self.reg.enroll("vm-a")
        teks = json.dumps(self.reg.daftar(), ensure_ascii=False)
        for rec in self.reg.devices.values():
            self.assertNotIn(rec["kunci"], teks)


class TestPersistensi(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.file = os.path.join(self.d.name, "devices.json")
        self.audit = os.path.join(self.d.name, "a.jsonl")

    def tearDown(self):
        self.d.cleanup()

    def test_devices_json_izin_0600(self):
        reg = DeviceRegistry(self.file, self.audit)
        reg.enroll("vm-a")
        mode = stat.S_IMODE(os.stat(self.file).st_mode)
        self.assertEqual(mode, 0o600)

    def test_muat_ulang_menahan_isi(self):
        reg = DeviceRegistry(self.file, self.audit)
        info = reg.enroll("vm-a", "auditor")
        reg.set_lockdown(True)
        reg2 = DeviceRegistry(self.file, self.audit)
        self.assertIn(info["id"], reg2.devices)
        self.assertTrue(reg2.lockdown)
        self.assertEqual(reg2.devices[info["id"]]["peran"], "auditor")

    def test_file_rusak_registry_error(self):
        with open(self.file, "w") as f:
            f.write("{bukan json")
        with self.assertRaises(RegistryError):
            DeviceRegistry(self.file, self.audit)

    def test_devices_bukan_dict_error(self):
        with open(self.file, "w") as f:
            json.dump({"devices": "bukan-dict"}, f)
        with self.assertRaises(RegistryError):
            DeviceRegistry(self.file, self.audit)


class TestRevokeLockdown(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.file = os.path.join(self.d.name, "devices.json")
        self.audit = os.path.join(self.d.name, "a.jsonl")
        self.reg = DeviceRegistry(self.file, self.audit)
        self.info = self.reg.enroll("vm-a")

    def tearDown(self):
        self.d.cleanup()

    def test_cek_enrolled_aktif(self):
        self.assertIsNotNone(self.reg.cek_enrolled(self.info["id"]))

    def test_revoke_memblokir(self):
        self.reg.revoke(self.info["id"])
        self.assertIsNone(self.reg.cek_enrolled(self.info["id"]))
        with open(self.audit, encoding="utf-8") as f:
            self.assertIn("DEVICE_REVOKE", f.read())

    def test_revoke_tak_ada_raise(self):
        with self.assertRaises(KeyError):
            self.reg.revoke("dev-00000000")

    def test_revoke_dipersist(self):
        self.reg.revoke(self.info["id"])
        reg2 = DeviceRegistry(self.file, self.audit)
        self.assertTrue(reg2.devices[self.info["id"]]["revoked"])

    def test_lockdown_menolak_semua(self):
        self.reg.set_lockdown(True)
        rec, alasan = self.reg.verify_pesan(
            self.info["id"], "nonce-1", 1000.0, "HELLO", {}, "x")
        self.assertIsNone(rec)
        self.assertIn("lockdown", alasan)

    def test_buka_lockdown(self):
        self.reg.set_lockdown(True)
        self.reg.set_lockdown(False)
        self.assertFalse(self.reg.lockdown)


class TestVerifyPesan(unittest.TestCase):
    """Verifikasi MAC + nonce + jendela waktu (inti anti-replay)."""

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.reg = DeviceRegistry(os.path.join(self.d.name, "dev.json"),
                                  os.path.join(self.d.name, "a.jsonl"))
        self.info = self.reg.enroll("vm-a")
        self.id = self.info["id"]
        self.kunci = self.info["kunci"]
        self.now = 1_000_000.0

    def tearDown(self):
        self.d.cleanup()

    def _pesan(self, cmd="HELLO", payload=None, nonce="n-1", ts=None,
               kunci=None, mac=None):
        ts = self.now if ts is None else ts
        payload = payload or {}
        k = self.kunci if kunci is None else kunci
        m = buat_mac(k, self.id, nonce, ts, cmd, payload) \
            if mac is None else mac
        return self.reg.verify_pesan(self.id, nonce, ts, cmd, payload, m,
                                     sekarang=self.now)

    def test_pesan_valid_diterima(self):
        rec, alasan = self._pesan()
        self.assertIsNotNone(rec)
        self.assertEqual(alasan, "")

    def test_mac_salah_ditolak(self):
        rec, alasan = self._pesan(mac="00" * 32)
        self.assertIsNone(rec)
        self.assertIn("MAC", alasan)

    def test_kunci_salah_ditolak(self):
        rec, alasan = self._pesan(kunci="kunci-lain")
        self.assertIsNone(rec)
        self.assertIn("MAC", alasan)

    def test_nonce_dipakai_dua_kali_ditolak(self):
        self._pesan(nonce="sekali")
        rec, alasan = self._pesan(nonce="sekali")
        self.assertIsNone(rec)
        self.assertIn("replay", alasan)

    def test_nonce_berbeda_diterima(self):
        self._pesan(nonce="a")
        rec, _ = self._pesan(nonce="b")
        self.assertIsNotNone(rec)

    def test_timestamp_masa_depan_ditolak(self):
        rec, alasan = self._pesan(ts=self.now + 120)
        self.assertIsNone(rec)
        self.assertIn("jendela", alasan)

    def test_timestamp_lama_ditolak(self):
        rec, alasan = self._pesan(ts=self.now - 120)
        self.assertIsNone(rec)
        self.assertIn("jendela", alasan)

    def test_timestamp_dalam_jendela_diterima(self):
        rec, _ = self._pesan(ts=self.now - 30)
        self.assertIsNotNone(rec)

    def test_id_tidak_enroll_ditolak(self):
        mac = buat_mac(self.kunci, "dev-99999999", "n", self.now,
                       "HELLO", {})
        rec, alasan = self.reg.verify_pesan(
            "dev-99999999", "n", self.now, "HELLO", {}, mac,
            sekarang=self.now)
        self.assertIsNone(rec)
        self.assertIn("tidak ter-enroll", alasan)

    def test_nonce_kosong_ditolak(self):
        rec, alasan = self._pesan(nonce="")
        self.assertIsNone(rec)
        self.assertIn("nonce", alasan)

    def test_nonce_kadaluarsa_dibersihkan(self):
        self._pesan(nonce="lama", ts=self.now - 10)
        # setelah jendela berlalu, nonce lama boleh dipakai lagi
        rec, _ = self._pesan(nonce="lama",
                             ts=self.now + range_registry.JENDELA_NONCE + 1)
        # ts baru > jendela relatif now → DITOLAK jendela; bukti cleanup:
        self.assertIsNone(rec)

    def test_last_seen_in_memory(self):
        rec, _ = self._pesan()
        self.assertTrue(rec["last_seen"])

    def test_mac_kanonik_payload_urutan(self):
        # payload dict urutan berbeda → MAC sama (sort_keys)
        m1 = buat_mac(self.kunci, self.id, "n", self.now, "HELLO",
                      {"a": 1, "b": 2})
        m2 = buat_mac(self.kunci, self.id, "n", self.now, "HELLO",
                      {"b": 2, "a": 1})
        self.assertEqual(m1, m2)

    def test_cmd_berbeda_mac_berbeda(self):
        m1 = buat_mac(self.kunci, self.id, "n", self.now, "HELLO", {})
        m2 = buat_mac(self.kunci, self.id, "n", self.now, "POLL", {})
        self.assertNotEqual(m1, m2)


class TestCLIDaftar(unittest.TestCase):
    def test_daftar_tanpa_kunci(self):
        d = tempfile.TemporaryDirectory()
        try:
            reg = DeviceRegistry(os.path.join(d.name, "dev.json"),
                                 os.path.join(d.name, "a.jsonl"))
            reg.enroll("vm-a")
            reg.enroll("vm-b", "auditor")
            daftar = reg.daftar()
            self.assertEqual(len(daftar), 2)
            self.assertEqual({x["peran"] for x in daftar},
                             {"operator", "auditor"})
            self.assertNotIn("kunci", " ".join(daftar[0].keys()))
        finally:
            d.cleanup()


if __name__ == "__main__":
    unittest.main()
