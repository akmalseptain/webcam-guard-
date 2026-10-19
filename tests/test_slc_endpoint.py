#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test slc_endpoint + slc_server v4.0 — agent lifecycle, backoff, limit,
graceful shutdown, E2E loopback (HMAC, revokasi, cmd tak dikenal), TLS nyata
dengan pinning (sertifikat self-signed dibuat via openssl)."""
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from range_registry import buat_mac, DeviceRegistry  # noqa: E402
from slc_control import SLCControl  # noqa: E402
import slc_server  # noqa: E402
import slc_actions  # noqa: E402  (v4.0.1: stub pengukuran utk test limit)
from slc_endpoint import (SLCEndpoint, TransportLokal, TransportTCP,
                          TransportError, CARA_INSTALL)  # noqa: E402


def kontrol_baru(d):
    reg = DeviceRegistry(path=os.path.join(d, "devices.json"),
                         audit_path=os.path.join(d, "audit.jsonl"))
    return SLCControl(registry=reg,
                      meta_path=os.path.join(d, "meta.json"),
                      audit_path=os.path.join(d, "audit.jsonl"),
                      events_path=os.path.join(d, "events.jsonl"))


class TestAgentUnit(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="slc_")
        self.c = kontrol_baru(self.d)
        self.rec = self.c.enroll("LAB-PC-02")
        self.tr = TransportLokal(self.c, self.rec["id"])
        self.agent = SLCEndpoint(self.rec["id"], self.rec["kunci"], self.tr)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_tanpa_enroll_ditolak(self):
        with self.assertRaises(PermissionError):
            SLCEndpoint("", "", TransportLokal(self.c, "dev-x"))

    def test_backoff_terbatas(self):
        self.assertEqual(self.agent.backoff(), 0.5)
        for _ in range(30):
            self.agent.catat_gagal_koneksi()
        self.assertLessEqual(self.agent.backoff(), 30.0)
        self.agent.catat_sukses_koneksi()
        self.assertEqual(self.agent.backoff(), 0.5)

    def test_siklus_idle(self):
        self.assertEqual(self.agent.siklus()["status"], "IDLE")
        self.assertIsNotNone(self.c.last_seen.get(self.rec["id"]))

    def test_siklus_eksekusi_terverifikasi(self):
        self.c.jadwalkan("admin", self.rec["id"], "kesehatan")
        r = self.agent.siklus()
        self.assertEqual(r["status"], "EKSEKUSI")
        self.assertEqual(self.agent.n_eksekusi, 1)
        t = self.c.history[-1]
        self.assertEqual(t["status"], "SELESAI_TERVERIFIKASI")

    def test_graceful_shutdown(self):
        self.agent.shutdown()
        self.assertTrue(self.agent.berhenti)
        self.assertEqual(self.agent.siklus()["status"], "BERHENTI")

    def test_limit_sumber_daya_dijaga(self):
        # v4.0.1: pengukuran di-stub agar test DETERMINISTIK di semua
        # platform (Linux getrusage / Windows psapi) — yang diuji adalah
        # LOGIKA PENEGAKAN limit, bukan API pengukuran OS.
        with mock.patch.object(slc_actions, "kumpul_res_agent",
                               return_value={"maxrss_kb": 999_999_999}):
            self.agent.limits = {"maxrss_kb": 1}  # pasti terlampaui
            self.c.jadwalkan("admin", self.rec["id"], "kesehatan")
            self.agent.siklus()
        t = self.c.history[-1]
        self.assertEqual(t["status"], "GAGAL")
        self.assertIn("limit sumber daya", t["hasil"]["error"])

    def test_kesehatan_identitas_jujur(self):
        h = self.agent.kesehatan()
        self.assertIn("SLC Endpoint Agent", h["identitas"]["produk"])
        self.assertEqual(h["versi"], "4.0.0")
        self.assertEqual(h["n_eksekusi"], 0)
        self.assertFalse(h["berhenti"])

    def test_pasang_paket_integritas(self):
        p = os.path.join(self.d, "upd.cfg")
        with open(p, "w") as f:
            f.write("baru\n")
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        tujuan = os.path.join(self.d, "target.cfg")
        with open(tujuan, "w") as f:
            f.write("lama\n")
        with self.assertRaises(ValueError):
            self.agent.pasang_paket(p, "b" * 64, tujuan)
        r = self.agent.pasang_paket(p, h, tujuan)
        self.assertTrue(r["terpasang"])
        self.assertTrue(os.path.exists(tujuan + ".bak"))
        self.assertEqual(open(tujuan).read(), "baru\n")

    def test_prosedur_layanan_terdokumentasi(self):
        self.assertIn("sc.exe create SLCAgent", CARA_INSTALL)
        self.assertIn("sc.exe delete SLCAgent", CARA_INSTALL)


class TestServerE2E(unittest.TestCase):
    """E2E loopback NYATA via TCP (thread server + agent TCP)."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="slc_e2e_")
        cls.c = kontrol_baru(cls.d)
        cls.rec = cls.c.enroll("LAB-PC-E2E")
        cls.srv = slc_server.SLCServer(cls.c, "127.0.0.1", 0)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.d, ignore_errors=True)

    def _kirim(self, cmd, payload, dev_id=None, kunci=None, mac=None,
               nonce=None, ts=None):
        import secrets
        dev_id = dev_id or self.rec["id"]
        kunci = kunci or self.rec["kunci"]
        nonce = nonce or secrets.token_hex(16)
        ts = time.time() if ts is None else ts
        m = mac or buat_mac(kunci, dev_id, nonce, ts, cmd, payload)
        pesan = {"jenis": "device", "id": dev_id, "nonce": nonce, "ts": ts,
                 "cmd": cmd, "payload": payload, "mac": m}
        import socket
        with socket.create_connection(("127.0.0.1", self.port), 3) as s:
            s.sendall(json.dumps(pesan).encode() + b"\n")
            buf = b""
            while not buf.endswith(b"\n"):
                blok = s.recv(65536)
                if not blok:
                    break
                buf += blok
        return json.loads(buf)

    def test_mac_salah_ditolak(self):
        r = self._kirim("HEARTBEAT", {}, mac="deadbeef" * 8)
        self.assertFalse(r["ok"])
        self.assertIn("autentikasi gagal", r["alasan"])

    def test_cmd_tak_dikenal_ditolak(self):
        r = self._kirim("EXEC", {})
        self.assertFalse(r["ok"])

    def test_perangkat_tak_enroll_ditolak(self):
        # terjangkau di jaringan ≠ diizinkan
        r = self._kirim("HEARTBEAT", {}, dev_id="dev-nakal",
                        kunci=self.rec["kunci"])
        self.assertFalse(r["ok"])

    def test_e2e_penuh_heartbeat_poll_hasil(self):
        r = self._kirim("HEARTBEAT", {"status": "hidup"})
        self.assertTrue(r["ok"])
        t = self.c.jadwalkan("admin", self.rec["id"], "kesehatan")
        poll = self._kirim("POLL", {})
        self.assertEqual(poll["data"]["tugas"]["tugas_id"], t["tugas_id"])
        hasil = self._kirim("HASIL", {"tugas_id": t["tugas_id"],
                            "data": json.dumps({"aksi": "kesehatan",
                             "data": {"platform": "Linux"}})})
        self.assertEqual(hasil["data"]["status"], "SELESAI_TERVERIFIKASI")

    def test_emergency_stop_menutup_wire(self):
        self.c.emergency_stop(self.rec["id"])
        r = self._kirim("HEARTBEAT", {})
        self.assertFalse(r["ok"])
        self.assertIn("emergency stop", r["alasan"])
        self.c.lepas_emergency(self.rec["id"])

    def test_agent_tcp_penuh(self):
        tr = TransportTCP("127.0.0.1", self.port, self.rec["id"],
                          self.rec["kunci"])
        agent = SLCEndpoint(self.rec["id"], self.rec["kunci"], tr)
        self.assertEqual(agent.siklus()["status"], "IDLE")
        self.c.jadwalkan("admin", self.rec["id"], "disk",
                         {"path": self.d})
        r = agent.siklus()
        self.assertEqual(r["status"], "EKSEKUSI")
        self.assertEqual(self.c.history[-1]["status"], "SELESAI_TERVERIFIKASI")
        agent.shutdown()

    def test_revoke_memutus_agen(self):
        rec2 = self.c.enroll("LAB-PC-REVOKE")
        r = self._kirim("HEARTBEAT", {}, dev_id=rec2["id"], kunci=rec2["kunci"])
        self.assertTrue(r["ok"])
        self.c.revoke(rec2["id"])
        r = self._kirim("HEARTBEAT", {}, dev_id=rec2["id"], kunci=rec2["kunci"])
        self.assertFalse(r["ok"])


@unittest.skipIf(shutil.which("openssl") is None,
                 "openssl tidak tersedia — TLS skip")
class TestTLSPinning(unittest.TestCase):
    """TLS NYATA: sertifikat self-signed dibuat openssl; agent menolak
    sertifikat yang PIN-nya tidak cocok (validasi ketat, bukan dekorasi)."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="slc_tls_")
        cls.cert = os.path.join(cls.d, "srv.pem")
        cls.key = os.path.join(cls.d, "srv.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", cls.key, "-out", cls.cert, "-days", "2",
                        "-nodes", "-subj", "/CN=slc-lab.local"],
                       check=True, capture_output=True)
        with open(cls.cert, "rb") as f:
            der = ssl.PEM_cert_to_DER_cert(f.read())
        cls.pin = hashlib.sha256(der).hexdigest()
        cls.c = kontrol_baru(cls.d)
        cls.rec = cls.c.enroll("LAB-PC-TLS")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cls.cert, cls.key)
        cls.srv = slc_server.SLCServer(cls.c, "127.0.0.1", 0, tls_ctx=ctx)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_pin_benar_sukses(self):
        tr = TransportTCP("127.0.0.1", self.port, self.rec["id"],
                         self.rec["kunci"], use_tls=True, pin_sha256=self.pin,
                         ca_file=self.cert)
        r = tr.kirim("HEARTBEAT", {"status": "hidup"})
        self.assertTrue(r["ok"])

    def test_pin_salah_ditolak(self):
        tr = TransportTCP("127.0.0.1", self.port, self.rec["id"],
                         self.rec["kunci"], use_tls=True,
                         pin_sha256="f" * 64, ca_file=self.cert)
        with self.assertRaises(TransportError):
            tr.kirim("HEARTBEAT", {})

    def test_tanpa_ca_ditolak(self):
        # validasi ketat: sertifikat tanpa CA terpercaya → gagal handshake
        tr = TransportTCP("127.0.0.1", self.port, self.rec["id"],
                         self.rec["kunci"], use_tls=True, pin_sha256=self.pin)
        with self.assertRaises(TransportError):
            tr.kirim("HEARTBEAT", {})


if __name__ == "__main__":
    unittest.main()
