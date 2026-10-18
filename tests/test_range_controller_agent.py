"""test_range_controller_agent.py — OperatorStore (RBAC persisten,
anti-enumeration), RangeController (whitelist perintah, antrean FIFO,
rate limit login), dan agent (kolektor read-only + siklus socket
loopback NYATA).

PBKDF2 dipakai dengan iterasi rendah (1000) di test supaya cepat —
produksi 200k (lihat range_controller.ITER_PBKDF2).
"""

import json
import os
import socket
import stat
import sys
import tempfile
import time
import unittest

AKAR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, AKAR)

import audit_core
import forensics
import range_agent
import range_controller
from range_controller import (OperatorStore, RangeController,
                              jalankan_server)
from range_registry import DeviceRegistry, buat_mac

ITER_TEST = 1000  # PBKDF2 cepat untuk test


class Basis(unittest.TestCase):
    """Registry + operators + controller segar di direktori temp."""

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.dev_file = os.path.join(self.d.name, "devices.json")
        self.ops_file = os.path.join(self.d.name, "operators.json")
        self.events = os.path.join(self.d.name, "events.jsonl")
        self.audit = os.path.join(self.d.name, "audit.jsonl")
        self.reg = DeviceRegistry(self.dev_file, self.audit)
        self.ops = OperatorStore(self.ops_file, self.audit,
                                 iterasi=ITER_TEST)
        self.ops.add_user("admin", "pw-admin", "admin")
        self.ops.add_user("op01", "pw-op", "operator")
        self.ops.add_user("aud01", "pw-aud", "auditor")
        self.ctrl = RangeController(self.reg, self.ops, self.events,
                                    self.audit)

    def tearDown(self):
        self.d.cleanup()

    def _pesan_dev(self, cmd="HELLO", payload=None, nonce="n1",
                   ts=None, kunci=None, dev_id=None):
        dev_id = dev_id or self.info["id"]
        kunci = kunci or self.info["kunci"]
        ts = time.time() if ts is None else ts
        payload = payload or {}
        return {"jenis": "device", "id": dev_id, "nonce": nonce,
                "ts": ts, "cmd": cmd, "payload": payload,
                "mac": buat_mac(kunci, dev_id, nonce, ts, cmd, payload)}


class TestOperatorStore(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.ops_file = os.path.join(self.d.name, "operators.json")
        self.audit = os.path.join(self.d.name, "a.jsonl")
        self.ops = OperatorStore(self.ops_file, self.audit,
                                 iterasi=ITER_TEST)

    def tearDown(self):
        self.d.cleanup()

    def test_add_dan_authenticate(self):
        self.ops.add_user("admin", "pw", "admin")
        self.assertEqual(self.ops.authenticate("admin", "pw"), "admin")
        self.assertIsNone(self.ops.authenticate("admin", "salah"))

    def test_role_sesuai_simpanan(self):
        self.ops.add_user("op01", "pw", "operator")
        self.assertEqual(self.ops.authenticate("op01", "pw"), "operator")

    def test_username_ganda_ditolak(self):
        self.ops.add_user("admin", "pw", "admin")
        with self.assertRaises(ValueError):
            self.ops.add_user("admin", "pw2", "auditor")

    def test_role_invalid_ditolak(self):
        with self.assertRaises(ValueError):
            self.ops.add_user("x", "pw", "superuser")

    def test_persisten_antar_proses(self):
        self.ops.add_user("admin", "pw", "admin")
        ops2 = OperatorStore(self.ops_file, self.audit,
                             iterasi=ITER_TEST)
        self.assertEqual(ops2.authenticate("admin", "pw"), "admin")

    def test_operators_json_0600(self):
        self.ops.add_user("admin", "pw", "admin")
        mode = stat.S_IMODE(os.stat(self.ops_file).st_mode)
        self.assertEqual(mode, 0o600)

    def test_hash_tidak_polas_password(self):
        self.ops.add_user("admin", "pw-rahasia", "admin")
        with open(self.ops_file, encoding="utf-8") as f:
            isi = f.read()
        self.assertNotIn("pw-rahasia", isi)
        self.assertIn("pbkdf2$", isi)

    def test_file_rusak_raise(self):
        with open(self.ops_file, "w") as f:
            f.write("bukan json")
        with self.assertRaises(Exception):
            OperatorStore(self.ops_file, self.audit, iterasi=ITER_TEST)


class TestControllerWhitelist(Basis):
    def setUp(self):
        super().setUp()
        self.info = self.reg.enroll("vm-a")

    def test_hello_perangkat_valid(self):
        resp = self.ctrl.proses_pesan(self._pesan_dev())
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["data"]["nama"], "vm-a")

    def test_cmd_luar_whitelist_ditolak(self):
        resp = self.ctrl.proses_pesan(self._pesan_dev(cmd="EXEC"))
        self.assertFalse(resp["ok"])
        with open(self.audit, encoding="utf-8") as f:
            self.assertIn("PERINTAH_DITOLAK", f.read())

    def test_mac_salah_ditolak(self):
        p = self._pesan_dev()
        p["mac"] = "00"
        resp = self.ctrl.proses_pesan(p)
        self.assertFalse(resp["ok"])
        self.assertIn("MAC", resp["alasan"])

    def test_replay_ditolak_controller(self):
        p = self._pesan_dev()
        self.assertTrue(self.ctrl.proses_pesan(p)["ok"])
        resp = self.ctrl.proses_pesan(p)  # nonce sama
        self.assertFalse(resp["ok"])
        self.assertIn("replay", resp["alasan"])

    def test_perangkat_revoked_ditolak(self):
        self.reg.revoke(self.info["id"])
        resp = self.ctrl.proses_pesan(self._pesan_dev())
        self.assertFalse(resp["ok"])

    def test_lockdown_menolak_perangkat(self):
        self.reg.set_lockdown(True)
        resp = self.ctrl.proses_pesan(self._pesan_dev())
        self.assertFalse(resp["ok"])

    def test_operator_login_lihat(self):
        resp = self.ctrl.proses_pesan({
            "jenis": "operator", "username": "aud01",
            "password": "pw-aud", "cmd": "LIHAT"})
        self.assertTrue(resp["ok"])
        self.assertIn("devices", resp["data"])

    def test_operator_login_salah_ditolak(self):
        resp = self.ctrl.proses_pesan({
            "jenis": "operator", "username": "aud01",
            "password": "salah", "cmd": "LIHAT"})
        self.assertFalse(resp["ok"])

    def test_operator_tak_dikenal_ditolak(self):
        resp = self.ctrl.proses_pesan({
            "jenis": "operator", "username": "hantu",
            "password": "x", "cmd": "LIHAT"})
        self.assertFalse(resp["ok"])

    def test_tugas_admin_ok_operator_ditolak(self):
        self.info = self.reg.enroll("vm-a")  # pasti ada
        resp_admin = self.ctrl.proses_pesan({
            "jenis": "operator", "username": "admin",
            "password": "pw-admin", "cmd": "TUGAS",
            "dev_id": self.info["id"], "jenis_tugas": "health"})
        self.assertTrue(resp_admin["ok"])
        resp_op = self.ctrl.proses_pesan({
            "jenis": "operator", "username": "op01",
            "password": "pw-op", "cmd": "TUGAS",
            "dev_id": self.info["id"], "jenis_tugas": "health"})
        self.assertFalse(resp_op["ok"])
        with open(self.audit, encoding="utf-8") as f:
            isi = f.read()
        self.assertIn("TUGAS_DIBERI", isi)
        self.assertIn("TUGAS_DITOLAK", isi)

    def test_beri_tugas_operator_raise(self):
        with self.assertRaises(PermissionError):
            self.ctrl.beri_tugas("operator", self.info["id"], "health")

    def test_beri_tugas_jenis_invalid_raise(self):
        with self.assertRaises(ValueError):
            self.ctrl.beri_tugas("admin", self.info["id"], "rm_rf")

    def test_beri_tugas_dev_tak_ada_raise(self):
        with self.assertRaises(KeyError):
            self.ctrl.beri_tugas("admin", "dev-00000000", "health")

    def test_poll_fifo_konsumsi(self):
        self.ctrl.beri_tugas("admin", self.info["id"], "health")
        self.ctrl.beri_tugas("admin", self.info["id"], "proses")
        r1 = self.ctrl.proses_pesan(self._pesan_dev(cmd="POLL",
                                                    nonce="p1"))
        r2 = self.ctrl.proses_pesan(self._pesan_dev(cmd="POLL",
                                                    nonce="p2"))
        r3 = self.ctrl.proses_pesan(self._pesan_dev(cmd="POLL",
                                                    nonce="p3"))
        self.assertEqual(r1["data"]["tugas"]["jenis"], "health")
        self.assertEqual(r2["data"]["tugas"]["jenis"], "proses")
        self.assertIsNone(r3["data"]["tugas"])

    def test_poll_kosong(self):
        r = self.ctrl.proses_pesan(self._pesan_dev(cmd="POLL"))
        self.assertTrue(r["ok"])
        self.assertIsNone(r["data"]["tugas"])

    def test_hasil_menulis_event(self):
        r = self.ctrl.proses_pesan(self._pesan_dev(
            cmd="HASIL", payload={"tugas_id": "t-1", "jenis": "health",
                                  "data": "ok"}))
        self.assertTrue(r["ok"])
        store = forensics.EventStore(self.events)
        self.assertEqual(len(store.load()), 1)
        self.assertEqual(store.load()[0]["kind"], "process")

    def test_json_tidak_valid_santun(self):
        # lewat jalur socket di bawah; di sini cek pesan jenis asing
        r = self.ctrl.proses_pesan({"jenis": "hantu"})
        self.assertFalse(r["ok"])

    def test_login_gagal_tercatat_audit(self):
        self.ctrl.proses_pesan({
            "jenis": "operator", "username": "op01",
            "password": "salah", "cmd": "LIHAT"})
        with open(self.audit, encoding="utf-8") as f:
            self.assertIn("LOGIN_GAGAL", f.read())

    def test_rate_limit_login(self):
        for _ in range(12):
            self.ctrl.proses_pesan({
                "jenis": "operator", "username": "op01",
                "password": "salah", "cmd": "LIHAT"})
        r = self.ctrl.proses_pesan({
            "jenis": "operator", "username": "op01",
            "password": "pw-op", "cmd": "LIHAT"})
        # kena rate limit walau password benar
        self.assertFalse(r["ok"])

    def test_hasil_list_bertambah(self):
        n = len(self.ctrl._hasil)
        self.ctrl.proses_pesan(self._pesan_dev(
            cmd="HASIL", payload={"tugas_id": "t-1", "jenis": "fim",
                                  "data": "x"}))
        self.assertEqual(len(self.ctrl._hasil), n + 1)


class TestAgentKolektor(unittest.TestCase):
    """Kolektor agent: bentuk output & sifat read-only (whitelist)."""

    def test_proses_ada_pid(self):
        hasil = range_agent.kumpul_proses(batas=20)
        self.assertTrue(hasil)
        self.assertIn("pid", hasil[0])
        self.assertIn("ppid", hasil[0])

    def test_pohon_proses(self):
        p = range_agent.pohon_proses()
        self.assertIn("n", p)
        self.assertGreater(p["n"], 0)

    def test_koneksi_kolom_inode(self):
        hasil = range_agent.kumpul_koneksi()
        for k in hasil:
            self.assertIn("inode", k)   # kolom 9 = inode, bukan PID
            self.assertIn("lokal", k)

    def test_hex_ke_ip_loopback(self):
        alamat = range_agent._hex_ke_ip("0100007F:1F90")
        self.assertTrue(alamat.startswith("127.0.0.1"))
        self.assertIn("8080", alamat)

    def test_health(self):
        h = range_agent.kumpul_health()
        self.assertEqual(h["agent"], "range-agent-v3")
        self.assertGreater(h["n_pid"], 0)

    def test_priv_suid_ditemukan(self):
        p = range_agent.kumpul_priv()
        self.assertIn("suid_ditemukan", p)
        self.assertIn("catatan", p)  # jujur: bukan audit penuh

    def test_fim_baseline_lalu_ubah(self):
        d = tempfile.TemporaryDirectory()
        try:
            f = os.path.join(d.name, "a.txt")
            with open(f, "w") as fh:
                fh.write("versi-1")
            cfg = {"fim_dir": d.name, "fim_baseline": None}
            b = range_agent.kumpul_fim(cfg)
            self.assertEqual(b["n"], 1)
            cfg["fim_baseline"] = b["baseline"]
            with open(f, "w") as fh:
                fh.write("versi-2 TAMPER")
            r = range_agent.kumpul_fim(cfg)
            self.assertEqual(r["berubah"], [f])
        finally:
            d.cleanup()

    def test_fim_file_hilang(self):
        d = tempfile.TemporaryDirectory()
        try:
            f = os.path.join(d.name, "hapus.txt")
            open(f, "w").close()
            cfg = {"fim_dir": d.name, "fim_baseline": None}
            b = range_agent.kumpul_fim(cfg)
            cfg["fim_baseline"] = b["baseline"]
            os.unlink(f)
            r = range_agent.kumpul_fim(cfg)
            self.assertEqual(r["hilang"], [f])
        finally:
            d.cleanup()

    def test_jalankan_tugas_whitelist(self):
        self.assertIsNotNone(range_agent.jalankan_tugas("health"))
        with self.assertRaises(ValueError):
            range_agent.jalankan_tugas("shutdown")

    def test_tugas_jenis_sesuai_kontrak(self):
        self.assertEqual(set(range_agent.TUGAS_JENIS),
                         {"proses", "pohon_proses", "koneksi", "fim",
                          "priv", "health"})


class TestSiklusSocketNyata(Basis):
    """Siklus agent↔controller lewat socket loopback NYATA (port 0)."""

    def setUp(self):
        super().setUp()
        self.info = self.reg.enroll("vm-a")
        self.srv, self.port = jalankan_server(self.ctrl, "127.0.0.1", 0)

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.d.cleanup()

    def _kirim(self, pesan):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            s.sendall(json.dumps(pesan).encode() + b"\n")
            buf = b""
            while not buf.endswith(b"\n"):
                blok = s.recv(65536)
                if not blok:
                    break
                buf += blok
            return json.loads(buf)
        finally:
            s.close()

    def test_hello_soket_nyata(self):
        resp = self._kirim(self._pesan_dev())
        self.assertTrue(resp["ok"])

    def test_json_rusak_dijawab_santun(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            s.sendall(b"{bukan json}\n")
            buf = s.recv(65536)
            resp = json.loads(buf)
            self.assertFalse(resp["ok"])
        finally:
            s.close()

    def test_siklus_penuh_pesan_agent(self):
        # admin beri tugas → agent POLL → jalankan → HASIL → event
        self.ctrl.beri_tugas("admin", self.info["id"], "health")
        cfg = {"fim_dir": self.d.name, "fim_baseline": None}
        with socket.create_connection(("127.0.0.1", self.port),
                                      timeout=5) as sock:
            r = range_agent.satu_siklus(sock, self.info["id"],
                                        self.info["kunci"], cfg)
            self.assertTrue(r["ok"])
        store = forensics.EventStore(self.events)
        self.assertEqual(len(store.load()), 1)

    def test_agent_ditolak_kunci_salah(self):
        # HELLO dengan kunci salah → respons ok=False (MAC tidak cocok),
        # controller TIDAK crash dan koneksi dijawab santun
        resp = self._kirim(self._pesan_dev(kunci="kunci-salah"))
        self.assertFalse(resp["ok"])
        self.assertIn("MAC", resp["alasan"])


if __name__ == "__main__":
    unittest.main()
