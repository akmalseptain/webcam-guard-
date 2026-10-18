# -*- coding: utf-8 -*-
"""Test range_scenarios.py — scenario engine cyber range v3.0 (R4).

Semua skenario nyata dijalankan di loopback dengan fixture
tests/scope_loopback.json (memuat 127.0.0.1). lab_scope.json ASLI
(sanctity scope produksi) TIDAK memuat 127.0.0.1 → harus menolak
semuanya tanpa mengeksekusi apa pun.
"""

import io
import json
import contextlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import forensics
from range_scenarios import (KATALOG, ScenarioRunner, render_teks, main,
                              TARGET_DEFAULT)

SCOPE_LOOPBACK = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "scope_loopback.json")
SCOPE_PRODUKSI = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "lab_scope.json")


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.events = os.path.join(self.d.name, "events.jsonl")
        self.audit = os.path.join(self.d.name, "audit.jsonl")

    def tearDown(self):
        self.d.cleanup()

    def runner(self, scope=SCOPE_LOOPBACK, **kw):
        return ScenarioRunner(scope, self.events, self.audit, **kw)


class TestKatalog(unittest.TestCase):
    def test_empat_skenario(self):
        self.assertEqual([s["nama"] for s in KATALOG],
                         ["R-RECON", "R-C2-BEACON", "R-FIM-TAMPER",
                          "R-PRIVILEGE"])

    def test_mitre_terpetakan(self):
        peta = {s["nama"]: s["mitre"] for s in KATALOG}
        self.assertEqual(peta["R-RECON"], "T1046")
        self.assertEqual(peta["R-C2-BEACON"], "T1071")
        self.assertEqual(peta["R-FIM-TAMPER"], "T1565.001")
        self.assertEqual(peta["R-PRIVILEGE"], "T1078")

    def test_kontrol_unik(self):
        kontrol = [s["kontrol"] for s in KATALOG]
        self.assertEqual(len(kontrol), len(set(kontrol)))


class TestFixtureLoopback(_Base):
    """Skenario dijalankan PENUH dengan scope loopback 127.0.0.1."""

    @classmethod
    def setUpClass(cls):
        cls.d_kls = tempfile.TemporaryDirectory()
        cls.lap = ScenarioRunner(
            SCOPE_LOOPBACK,
            os.path.join(cls.d_kls.name, "events.jsonl"),
            os.path.join(cls.d_kls.name, "audit.jsonl")).jalankan()

    @classmethod
    def tearDownClass(cls):
        cls.d_kls.cleanup()

    def test_semua_dijalankan(self):
        self.assertEqual(self.lap["n_dijalankan"], 4)
        self.assertEqual(self.lap["n_skenario"], 4)

    def test_semua_terdeteksi(self):
        self.assertEqual(self.lap["n_terdeteksi"], 4)
        self.assertEqual(self.lap["detection_rate"], 1.0)

    def test_semua_status_selesai(self):
        for h in self.lap["skenario"]:
            self.assertEqual(h["status"], "SELESAI", h["nama"])

    def test_coverage_empat_kontrol(self):
        cov = self.lap["coverage"]
        self.assertEqual(set(cov), {"netmon_port_scan", "netmon_beacon",
                                    "fim", "rbac"})
        for k, c in cov.items():
            self.assertEqual(c["n"], 1, k)
            self.assertEqual(c["n_detected"], 1, k)

    def test_evidence_recon(self):
        h = next(x for x in self.lap["skenario"]
                 if x["nama"] == "R-RECON")
        self.assertIn("12 koneksi loopback nyata", h["evidence"][0])
        self.assertIn("port_scan", h["evidence"][2])

    def test_evidence_c2_jujur_ambang(self):
        h = next(x for x in self.lap["skenario"]
                 if x["nama"] == "R-C2-BEACON")
        self.assertTrue(any("CATATAN JUJUR" in e for e in h["evidence"]))
        self.assertIn("beacon", h["evidence"][2])

    def test_evidence_fim(self):
        h = next(x for x in self.lap["skenario"]
                 if x["nama"] == "R-FIM-TAMPER")
        gabung = " ".join(h["evidence"])
        self.assertIn("b.txt", gabung)
        self.assertIn("baru.txt", gabung)
        self.assertIn("c.txt", gabung)

    def test_evidence_privilege(self):
        h = next(x for x in self.lap["skenario"]
                 if x["nama"] == "R-PRIVILEGE")
        self.assertIn("PermissionError: True", " ".join(h["evidence"]))
        self.assertIn("TUGAS_DITOLAK", " ".join(h["evidence"]))

    def test_rollback_tidak_dieksekusi(self):
        rb = self.lap["rollback"]
        self.assertEqual(rb["status"], "NOT RUN")
        self.assertIn("manual owner", rb["catatan"])


class TestScopeProduksi(_Base):
    """lab_scope.json asli TIDAK memuat 127.0.0.1 → semua DITOLAK."""

    def test_semua_ditolak_scope(self):
        r = self.runner(scope=SCOPE_PRODUKSI)
        lap = r.jalankan()
        self.assertEqual(lap["n_dijalankan"], 0)
        self.assertEqual(lap["detection_rate"], None)
        for h in lap["skenario"]:
            self.assertEqual(h["status"], "DITOLAK_SCOPE", h["nama"])
        self.assertEqual(lap["coverage"], {})

    def test_audit_skenario_ditolak(self):
        r = self.runner(scope=SCOPE_PRODUKSI)
        r.jalankan()
        isi = open(self.audit, encoding="utf-8").read()
        self.assertIn("SKENARIO_DITOLAK", isi)
        self.assertNotIn("SKENARIO_MULAI", isi)


class TestAuditDanEvent(_Base):
    def test_audit_mulai_selesai(self):
        self.runner().jalankan()
        isi = open(self.audit, encoding="utf-8").read()
        self.assertEqual(isi.count("SKENARIO_MULAI"), 4)
        self.assertEqual(isi.count("SKENARIO_SELESAI"), 4)
        self.assertNotIn("SKENARIO_DITOLAK", isi)

    def test_event_redsim_rantai_utuh(self):
        self.runner().jalankan()
        store = forensics.EventStore(self.events)
        self.assertIsNone(store.verify())  # None = rantai utuh
        ev = store.query(kind="redsim")
        self.assertEqual(len(ev), 4)


class TestSubsetDanError(_Base):
    def test_satu_skenario(self):
        lap = self.runner().jalankan("R-FIM-TAMPER")
        self.assertEqual(lap["n_skenario"], 1)
        self.assertEqual(lap["skenario"][0]["nama"], "R-FIM-TAMPER")
        self.assertTrue(lap["skenario"][0]["detected"])

    def test_nama_tidak_dikenal(self):
        with self.assertRaises(ValueError):
            self.runner().jalankan("R-TIDAK-ADA")

    def test_rollback_cmd_dicatat_tapi_not_run(self):
        r = self.runner(rollback_cmd="VBoxManage snapshot lab-01 "
                                     "restore clean")
        lap = r.jalankan("R-FIM-TAMPER")
        self.assertEqual(lap["rollback"]["status"], "NOT RUN")
        self.assertIn("VBoxManage", lap["rollback"]["cmd"])


class TestRenderDanCLI(_Base):
    def test_render_teks(self):
        lap = self.runner().jalankan()
        teks = render_teks(lap)
        self.assertIn("detection_rate", teks)
        self.assertIn("coverage per kontrol", teks)
        self.assertIn("rollback: NOT RUN", teks)

    def _cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            kode = main(list(argv))
        return kode, buf.getvalue()

    def test_cli_fixture_exit0(self):
        kode, out = self._cli("--scope", SCOPE_LOOPBACK,
                              "--events", self.events, "--audit", self.audit)
        self.assertEqual(kode, 0)
        self.assertIn("terdeteksi 4", out)

    def test_cli_produksi_exit2(self):
        kode, out = self._cli("--scope", SCOPE_PRODUKSI,
                              "--events", self.events, "--audit", self.audit)
        self.assertEqual(kode, 2)
        self.assertIn("DITOLAK_SCOPE", out)

    def test_cli_json(self):
        kode, out = self._cli("--scope", SCOPE_LOOPBACK, "--json",
                              "--events", self.events, "--audit", self.audit)
        self.assertEqual(kode, 0)
        lap = json.loads(out)
        self.assertEqual(len(lap["skenario"]), 4)
        self.assertEqual(lap["detection_rate"], 1.0)

    def test_cli_skenario_tak_dikenal_exit3(self):
        kode, _ = self._cli("--scope", SCOPE_LOOPBACK,
                            "--skenario", "R-TIDAK-ADA",
                            "--events", self.events, "--audit", self.audit)
        self.assertEqual(kode, 3)


if __name__ == "__main__":
    unittest.main()
