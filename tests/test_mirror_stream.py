"""test_mirror_stream.py — Integration test protokol mirroring.

JUJUR soal TLS: unit test ini memakai socket POLOS (ssl_ctx=None)
untuk menguji logika protokol/auth. Enkripsi TLS asli diuji manual
di laptop: jalankan mirror_server.py lalu mirror_viewer.py —
klien tanpa TLS akan gagal handshake. Sertifikat dibuat via
cryptography/openssl (lihat mirror_stream.ensure_cert).
"""
import os
import socket
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mirror_auth
import mirror_stream


def _tunggu(kondisi, timeout=5.0):
    """Polling sampai kondisi True atau timeout."""
    akhir = time.monotonic() + timeout
    while time.monotonic() < akhir:
        if kondisi():
            return True
        time.sleep(0.05)
    return kondisi()


class TestWireFormat(unittest.TestCase):
    def test_payload_roundtrip(self):
        a, b = socket.socketpair()
        with a, b:
            mirror_stream.kirim_payload(a, b"data-uji-123")
            self.assertEqual(mirror_stream.terima_payload(b), b"data-uji-123")

    def test_json_roundtrip(self):
        a, b = socket.socketpair()
        with a, b:
            mirror_stream.kirim_json(a, {"cmd": "PAUSE", "n": 1})
            self.assertEqual(mirror_stream.terima_json(b),
                             {"cmd": "PAUSE", "n": 1})

    def test_frame_roundtrip(self):
        a, b = socket.socketpair()
        with a, b:
            mirror_stream.kirim_frame(a, b"\xff\xd8fakejpeg")
            jenis, data = mirror_stream.terima_frame(b)
            self.assertEqual(jenis, "FRM")
            self.assertEqual(data, b"\xff\xd8fakejpeg")

    def test_payload_terlalu_besar_raise(self):
        a, b = socket.socketpair()
        with a, b:
            a.sendall(struct.pack(">I", 999 * 1024 * 1024))
            with self.assertRaises(ValueError):
                mirror_stream.terima_payload(b)


class ServerBase(unittest.TestCase):
    """Harness: server polos (ssl_ctx=None) di port ephemeral."""

    def setUp(self):
        self.kode = mirror_auth.buat_kode_pairing()
        self.srv = mirror_stream.MirrorServer(
            self.kode, "lab-laptop", host="127.0.0.1", port=0,
            ssl_ctx=None, max_penonton=3)
        self.srv.start()
        self.port = self.srv.server_sock.getsockname()[1]
        threading.Thread(target=self.srv.accept_loop, daemon=True).start()

    def tearDown(self):
        self.srv.stop()

    def _sambung(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.settimeout(5)
        return s

    def _hello(self, s, role="viewer", token=None):
        token = token or mirror_auth.buat_token(self.kode, role)
        mirror_stream.kirim_json(s, {"cmd": "HELLO", "kode": self.kode,
                                     "role": role, "token": token})
        return mirror_stream.terima_json(s)


class TestMirrorServer(ServerBase):
    def test_hello_token_salah_ditolak(self):
        with self._sambung() as s:
            resp = self._hello(s, "viewer", token="0" * 64)
            self.assertEqual(resp["cmd"], "DENY")
            self.assertIn("token", resp["alasan"])

    def test_welcome_dengan_token_valid(self):
        with self._sambung() as s:
            resp = self._hello(s, "admin")
            self.assertEqual(resp["cmd"], "WELCOME")
            self.assertEqual(resp["device"], "lab-laptop")
            self.assertTrue(resp["id"].startswith("admin@"))

    def test_penonton_penuh_ditolak(self):
        self.srv.max_penonton = 1
        with self._sambung() as s1:
            self.assertEqual(self._hello(s1)["cmd"], "WELCOME")
            with self._sambung() as s2:
                resp = self._hello(s2)
                self.assertEqual(resp["cmd"], "DENY")
                self.assertIn("penuh", resp["alasan"])

    def test_pause_resume_mengubah_state(self):
        with self._sambung() as s:
            self._hello(s)
            mirror_stream.kirim_json(s, {"cmd": "PAUSE"})
            self.assertTrue(_tunggu(lambda: self.srv.state == "jeda"))
            mirror_stream.kirim_json(s, {"cmd": "RESUME"})
            self.assertTrue(_tunggu(lambda: self.srv.state == "aktif"))

    def test_stop_req_menghentikan_sesi(self):
        with self._sambung() as s:
            self._hello(s)
            mirror_stream.kirim_json(s, {"cmd": "STOP_REQ"})
            jenis, data = mirror_stream.terima_frame(s)
            self.assertEqual(data["cmd"], "STOP")
            self.assertTrue(_tunggu(lambda: not self.srv.running))
            self.assertEqual(self.srv.state, "berhenti")

    def test_revoke_mengirim_revoked(self):
        with self._sambung() as s:
            resp = self._hello(s, "viewer")
            cid = resp["id"]
            self.srv.revoke(cid)
            jenis, data = mirror_stream.terima_frame(s)
            self.assertEqual(data["cmd"], "REVOKED")

    def test_broadcast_frame_ke_penonton(self):
        with self._sambung() as s:
            self._hello(s)
            self.assertTrue(_tunggu(lambda: self.srv.n_penonton() == 1))
            self.srv.broadcast_frame(b"\xff\xd8jpg")
            jenis, data = mirror_stream.terima_frame(s)
            self.assertEqual(jenis, "FRM")
            self.assertEqual(data, b"\xff\xd8jpg")


if __name__ == "__main__":
    unittest.main()
