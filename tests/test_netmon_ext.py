"""test_netmon_ext.py — Ekstensi netmon v3.0 (R3): inspeksi sertifikat
TLS (fingerprint SHA-256 + metadata, guarded), ukur kualitas capture
(duplikat/reorder/gap, estimasi drop dilabeli jujur), korelasi
DNS↔SNI/HTTP-Host, dan integrasi analyze_pcap."""

import base64
import hashlib
import os
import sys
import tempfile
import unittest

AKAR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, AKAR)

import netmon

CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"


def _meta(app, detail, ts=1000.0, src="10.0.0.5", dst="10.0.0.9"):
    return {"ts": ts, "src": src, "dst": dst, "proto": 6, "bytes": 60,
            "sport": 12345, "dport": 443 if app == "tls_sni" else 80,
            "app": app, "detail": detail}


class TestInspeksiSertifikat(unittest.TestCase):
    def _cert_pertama(self, d):
        """Ambil blok PEM pertama dari bundle CA sistem (bila ada)."""
        if not os.path.exists(CA_BUNDLE):
            return None
        with open(CA_BUNDLE, encoding="utf-8") as f:
            isi = f.read()
        awal = isi.find("-----BEGIN CERTIFICATE-----")
        akhir = isi.find("-----END CERTIFICATE-----", awal)
        if awal < 0 or akhir < 0:
            return None
        blok = isi[awal:akhir + len("-----END CERTIFICATE-----")]
        path = os.path.join(d, "satu.pem")
        with open(path, "w", encoding="utf-8") as f:
            f.write(blok + "\n")
        return path

    def test_fingerprint_der_satu_cert(self):
        d = tempfile.TemporaryDirectory()
        try:
            path = self._cert_pertama(d.name)
            if path is None:
                self.skipTest("bundle CA tidak ada di lingkungan ini")
            hasil = netmon.inspeksi_sertifikat(path)
            self.assertIsNone(hasil["error"])
            # fingerprint harus = SHA-256 DER (terverifikasi independen)
            with open(path, encoding="utf-8") as f:
                isi = f.read()
            body = isi.split("-----BEGIN CERTIFICATE-----")[1] \
                      .split("-----END CERTIFICATE-----")[0]
            der = base64.b64decode("".join(body.split()))
            self.assertEqual(hasil["fingerprint_sha256"],
                             hashlib.sha256(der).hexdigest())
            self.assertEqual(len(hasil["fingerprint_sha256"]), 64)
        finally:
            d.cleanup()

    def test_metadata_cert_nyata(self):
        d = tempfile.TemporaryDirectory()
        try:
            path = self._cert_pertama(d.name)
            if path is None:
                self.skipTest("bundle CA tidak ada di lingkungan ini")
            hasil = netmon.inspeksi_sertifikat(path)
            self.assertTrue(hasil["subject"])
            self.assertTrue(hasil["issuer"])
            self.assertTrue(hasil["not_before"])
            self.assertTrue(hasil["not_after"])
            self.assertTrue(hasil["berlaku"])
        finally:
            d.cleanup()

    def test_file_tidak_ada_error_jujur(self):
        hasil = netmon.inspeksi_sertifikat("/tmp/tidak-ada.pem")
        self.assertIsNotNone(hasil["error"])
        self.assertIn("tidak bisa dibaca", hasil["error"])

    def test_bukan_pem_error_jujur(self):
        d = tempfile.TemporaryDirectory()
        try:
            p = os.path.join(d.name, "bukan.pem")
            with open(p, "w") as f:
                f.write("hello dunia")
            hasil = netmon.inspeksi_sertifikat(p)
            self.assertIsNotNone(hasil["error"])
            self.assertIn("bukan file PEM", hasil["error"])
            self.assertIsNone(hasil["fingerprint_sha256"])
        finally:
            d.cleanup()

    def test_cli_inspeksi_sert(self):
        d = tempfile.TemporaryDirectory()
        try:
            path = self._cert_pertama(d.name)
            if path is None:
                self.skipTest("bundle CA tidak ada di lingkungan ini")
            import subprocess
            r = subprocess.run(
                [sys.executable, "netmon.py", "--inspeksi-sert", path],
                cwd=AKAR, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0)
            self.assertIn("fingerprint", r.stdout)
        finally:
            d.cleanup()


class TestUkurKualitas(unittest.TestCase):
    def _pkt(self, ts, isi=b"\x01\x02"):
        return (ts, bytes(isi))

    def test_kosong_dan_satu(self):
        self.assertEqual(netmon.ukur_kualitas([])["n_paket"], 0)
        self.assertEqual(netmon.ukur_kualitas([self._pkt(1.0)])["n_paket"],
                         1)

    def test_duplikat_terdeteksi(self):
        pkts = [self._pkt(1.0), self._pkt(1.2), self._pkt(1.4)]
        hasil = netmon.ukur_kualitas(pkts)
        self.assertEqual(hasil["n_duplikat"], 2)

    def test_duplikat_berjauhan_tidak_dihitung(self):
        pkts = [self._pkt(1.0), self._pkt(100.0)]
        hasil = netmon.ukur_kualitas(pkts)
        self.assertEqual(hasil["n_duplikat"], 0)

    def test_reorder_terdeteksi(self):
        pkts = [self._pkt(1.0, b"a"), self._pkt(0.5, b"b")]
        hasil = netmon.ukur_kualitas(pkts)
        self.assertEqual(hasil["n_reorder"], 1)

    def test_gap_terdeteksi(self):
        pkts = [self._pkt(1.0, b"a"), self._pkt(1.1, b"b"),
                self._pkt(9.0, b"c")]
        hasil = netmon.ukur_kualitas(pkts)
        self.assertEqual(hasil["n_gap"], 1)
        self.assertEqual(hasil["gaps"][0]["indeks"], 2)

    def test_ambang_gap_bisa_diatur(self):
        pkts = [self._pkt(1.0, b"a"), self._pkt(3.5, b"b")]
        self.assertEqual(netmon.ukur_kualitas(pkts)["n_gap"], 1)
        self.assertEqual(
            netmon.ukur_kualitas(pkts, ambang_gap_s=10.0)["n_gap"], 0)

    def test_estimasi_drop_dilabeli_jujur(self):
        hasil = netmon.ukur_kualitas([self._pkt(1.0), self._pkt(50.0)])
        self.assertIn("BUKAN pengukuran", hasil["catatan"])
        self.assertEqual(hasil["estimasi_drop"], 1)

    def test_durasi(self):
        pkts = [self._pkt(10.0, b"a"), self._pkt(12.5, b"b")]
        self.assertEqual(netmon.ukur_kualitas(pkts)["durasi_s"], 2.5)

    def test_paket_bersih_tak_temu_apa_pun(self):
        pkts = [self._pkt(1.0 + i * 0.1, bytes([i]))
                for i in range(20)]
        hasil = netmon.ukur_kualitas(pkts)
        self.assertEqual((hasil["n_duplikat"], hasil["n_reorder"],
                          hasil["n_gap"]), (0, 0, 0))


class TestKorelasiDNS(unittest.TestCase):
    def test_match_penuh(self):
        meta = [_meta("dns", "lab.local", ts=1000.0),
                _meta("tls_sni", "lab.local", ts=1005.0)]
        hasil = netmon.korelasi_dns(meta)
        self.assertEqual(hasil["n_pasangan"], 1)
        self.assertEqual(hasil["pasangan"][0]["jenis"], "match")
        self.assertTrue(hasil["pasangan"][0]["src_sama"])

    def test_subdomain(self):
        meta = [_meta("dns", "lab.local", ts=1000.0),
                _meta("tls_sni", "vpn.lab.local", ts=1001.0)]
        hasil = netmon.korelasi_dns(meta)
        self.assertEqual(hasil["pasangan"][0]["jenis"], "subdomain")

    def test_tanpa_dns(self):
        meta = [_meta("tls_sni", "asing.example", ts=1000.0)]
        hasil = netmon.korelasi_dns(meta)
        self.assertEqual(hasil["n_pasangan"], 0)
        self.assertEqual(hasil["n_tanpa_dns"], 1)

    def test_dns_setelah_koneksi_tidak_dipakai(self):
        meta = [_meta("tls_sni", "lab.local", ts=1000.0),
                _meta("dns", "lab.local", ts=1005.0)]
        hasil = netmon.korelasi_dns(meta)
        self.assertEqual(hasil["n_pasangan"], 0)

    def test_jendela_waktu(self):
        meta = [_meta("dns", "a.local", ts=1000.0),
                _meta("tls_sni", "b.example", ts=1001.0),
                _meta("tls_sni", "a.local", ts=1200.0)]  # > 60 dtk
        hasil = netmon.korelasi_dns(meta)
        # koneksi a.local terlambat: DNS sudah di luar jendela
        tanpa = [x["host"] for x in hasil["tanpa_dns"]]
        self.assertIn("a.local", tanpa)

    def test_src_bedas_notasi(self):
        meta = [_meta("dns", "lab.local", ts=1000.0, src="10.0.0.5"),
                _meta("tls_sni", "lab.local", ts=1001.0,
                      src="10.0.0.7")]
        hasil = netmon.korelasi_dns(meta)
        self.assertFalse(hasil["pasangan"][0]["src_sama"])

    def test_multi_nama_dns_detail_koma(self):
        meta = [_meta("dns", "a.local,b.local", ts=1000.0),
                _meta("tls_sni", "b.local", ts=1002.0)]
        hasil = netmon.korelasi_dns(meta)
        self.assertEqual(hasil["n_dns"], 2)
        self.assertEqual(hasil["n_pasangan"], 1)

    def test_catatan_jujur(self):
        hasil = netmon.korelasi_dns([])
        self.assertIn("bukan bukti sebab-akibat", hasil["catatan"])
        self.assertEqual(hasil["n_dns"], 0)


class TestIntegrasiAnalyze(unittest.TestCase):
    """analyze_pcap kini memuat 'kualitas' + 'korelasi_dns' (v3.0)."""

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.d.cleanup()

    def test_analyze_pcap_kunci_baru(self):
        packets = netmon.demo_packets()
        p = os.path.join(self.d.name, "demo.pcap")
        netmon.tulis_pcap(p, packets)
        hasil = netmon.analyze_pcap(p)
        self.assertIn("kualitas", hasil)
        self.assertIn("korelasi_dns", hasil)
        self.assertIn("catatan", hasil["kualitas"])
        self.assertEqual(hasil["kualitas"]["n_paket"],
                         hasil["n_paket"])

    def test_analyze_pcap_tetap_mendeteksi_anomali_lama(self):
        packets = netmon.demo_packets()
        p = os.path.join(self.d.name, "demo.pcap")
        netmon.tulis_pcap(p, packets)
        hasil = netmon.analyze_pcap(p)
        self.assertTrue(hasil["anomali"])  # demo memang berisi anomali

    def test_pcapy_v1_lama_tetap_terbaca(self):
        packets = netmon.demo_packets()[:5]
        p = os.path.join(self.d.name, "kecil.pcap")
        netmon.tulis_pcap(p, packets)
        hasil = netmon.analyze_pcap(p)
        self.assertEqual(hasil["n_paket"], 5)


if __name__ == "__main__":
    unittest.main()
