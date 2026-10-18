"""test_netmon.py — Unit test PCAP, parser metadata, flow, deteksi anomali."""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import netmon


class TestPcapFormat(unittest.TestCase):
    def test_global_header_format(self):
        gh = netmon.pcap_global_header()
        magic, vmaj, vmin, tz, sigfigs, snaplen, linktype = \
            struct.unpack("<IHHiIII", gh)
        self.assertEqual(hex(magic), "0xa1b2c3d4")
        self.assertEqual((vmaj, vmin), (2, 4))
        self.assertEqual(sigfigs, 0)   # field wajib ada (bug v-awal pernah hilang)
        self.assertEqual(linktype, 1)  # Ethernet

    def test_tulis_baca_roundtrip(self):
        pkts = netmon.demo_packets()[:5]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.pcap")
            netmon.tulis_pcap(path, pkts)
            hasil = netmon.baca_pcap(path)
        self.assertEqual(len(hasil), 5)
        self.assertEqual(hasil[0][1], pkts[0][1])

    def test_baca_file_bukan_pcap_raise(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bogus.pcap")
            with open(path, "wb") as f:
                f.write(b"bukan pcap sama sekali")
            with self.assertRaises(ValueError):
                netmon.baca_pcap(path)


class TestParser(unittest.TestCase):
    def _frame_udp_dns(self):
        dns = (b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
               b"\x04lab2\x05local\x00\x00\x01\x00\x01")
        return netmon.build_ethernet(
            "02:00:00:00:00:02", "02:00:00:00:00:01", 0x0800,
            netmon.build_ipv4("192.168.56.10", "192.168.56.1", 17,
                              netmon.build_udp(53000, 53, dns)))

    def test_parse_ethernet(self):
        eth = netmon.parse_ethernet(self._frame_udp_dns())
        self.assertEqual(eth["ethertype"], 0x0800)
        self.assertEqual(eth["src_mac"], "02:00:00:00:00:01")

    def test_parse_ethernet_terlalu_pendek(self):
        self.assertIsNone(netmon.parse_ethernet(b"\x01\x02"))

    def test_parse_ipv4(self):
        eth = netmon.parse_ethernet(self._frame_udp_dns())
        ip = netmon.parse_ipv4(eth["payload"])
        self.assertEqual(ip["src"], "192.168.56.10")
        self.assertEqual(ip["dst"], "192.168.56.1")
        self.assertEqual(ip["proto"], 17)

    def test_parse_ipv4_bukan_ipv4(self):
        data = b"\x06" + b"\x00" * 19  # version 6
        self.assertIsNone(netmon.parse_ipv4(data))

    def test_parse_udp(self):
        eth = netmon.parse_ethernet(self._frame_udp_dns())
        ip = netmon.parse_ipv4(eth["payload"])
        udp = netmon.parse_udp(ip["payload"])
        self.assertEqual((udp["sport"], udp["dport"]), (53000, 53))

    def test_parse_dns_query(self):
        eth = netmon.parse_ethernet(self._frame_udp_dns())
        ip = netmon.parse_ipv4(eth["payload"])
        udp = netmon.parse_udp(ip["payload"])
        q = netmon.parse_dns_query(udp["payload"])
        self.assertEqual(len(q), 1)
        self.assertEqual(q[0]["nama"], "lab2.local")
        self.assertEqual(q[0]["tipe"], 1)

    def test_parse_http_request(self):
        payload = (b"GET /a.html HTTP/1.1\r\nHost: lab.local\r\n\r\n")
        h = netmon.parse_http_request(payload)
        self.assertEqual(h["metode"], "GET")
        self.assertEqual(h["path"], "/a.html")
        self.assertEqual(h["host"], "lab.local")

    def test_parse_http_request_sampah(self):
        self.assertIsNone(netmon.parse_http_request(b"\xff\xff\xff\xff"))

    def test_checksum16(self):
        self.assertEqual(netmon.checksum16(b"\x00\x00"), 0xFFFF)


class TestEkstraksiMetadata(unittest.TestCase):
    def test_udp_dns_meta(self):
        frame = netmon.demo_packets()[0][1]
        meta = netmon.ekstrak_metadata(netmon.demo_packets()[0])
        self.assertEqual(meta["app"], "dns")
        self.assertIn("lab-01", meta["detail"])

    def test_tcp_sni_meta(self):
        pkts = netmon.demo_packets()
        sni_pkt = pkts[5]  # paket TLS ClientHello pertama
        meta = netmon.ekstrak_metadata(sni_pkt)
        self.assertEqual(meta["app"], "tls_sni")
        self.assertEqual(meta["detail"], "lab-service.local")

    def test_tcp_http_meta(self):
        pkts = netmon.demo_packets()
        meta = netmon.ekstrak_metadata(pkts[3])
        self.assertEqual(meta["app"], "http")
        self.assertIn("GET", meta["detail"])

    def test_non_ip_dilewati(self):
        frame = netmon.build_ethernet("aa:bb:cc:dd:ee:ff",
                                      "02:00:00:00:00:01", 0x0806, b"arp")
        self.assertIsNone(netmon.ekstrak_metadata((1.0, frame)))


class TestFlowTable(unittest.TestCase):
    def test_agregasi_flow(self):
        ft = netmon.FlowTable()
        for p in netmon.demo_packets():
            meta = netmon.ekstrak_metadata(p)
            if meta:
                ft.add(meta)
        flows = ft.daftar()
        self.assertTrue(all(f["packets"] >= 1 for f in flows))
        beacon = [f for f in flows if f["dport"] == 4444]
        self.assertEqual(len(beacon), 1)
        self.assertEqual(beacon[0]["packets"], 8)


class TestDeteksiAnomali(unittest.TestCase):
    def _flows_demo(self):
        ft = netmon.FlowTable()
        for p in netmon.demo_packets():
            meta = netmon.ekstrak_metadata(p)
            if meta:
                ft.add(meta)
        return ft.daftar()

    def test_port_c2_terdeteksi(self):
        anomali = netmon.detect_anomalies(self._flows_demo())
        self.assertTrue(any(a["tipe"] == "port_c2" and
                            a["mitre"] == "T1071" for a in anomali))

    def test_port_scan_terdeteksi(self):
        anomali = netmon.detect_anomalies(self._flows_demo())
        self.assertTrue(any(a["tipe"] == "port_scan" and
                            a["mitre"] == "T1046" for a in anomali))

    def test_beacon_terdeteksi(self):
        anomali = netmon.detect_anomalies(self._flows_demo())
        self.assertTrue(any(a["tipe"] == "beacon" for a in anomali))

    def test_trafik_wajar_tanpa_anomali(self):
        flows = [{"src": "10.0.0.1", "sport": 1, "dst": "10.0.0.2",
                  "dport": 443, "proto": "TCP", "packets": 2,
                  "bytes": 200, "first": 1, "last": 2, "durasi_s": 1.0,
                  "apps": []}]
        self.assertEqual(netmon.detect_anomalies(flows), [])


class TestDemoEndToEnd(unittest.TestCase):
    def test_demo_25_paket_semua_parse(self):
        pkts = netmon.demo_packets()
        self.assertEqual(len(pkts), 25)
        parsed = [p for p in pkts if netmon.ekstrak_metadata(p)]
        self.assertEqual(len(parsed), 25)

    def test_demo_run_menghasilkan_anomali(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "demo.pcap")
            hasil = netmon.run_demo(save_pcap=out)
            self.assertGreaterEqual(hasil["n_flow"], 10)
            self.assertGreaterEqual(len(hasil["anomali"]), 3)
            # hasil tulis-pcap bisa dibaca ulang & dianalisis
            analisis = netmon.analyze_pcap(out)
            self.assertEqual(analisis["n_paket"], 25)

    def test_cari_adapter_tidak_palsu(self):
        # di sandbox mungkin tidak ada adapter — fungsi tidak boleh menggantung
        hasil = netmon.cari_adapter()
        self.assertTrue(hasil is None or hasil in netmon.ADAPTER_CAPTURE)


if __name__ == "__main__":
    unittest.main()
