"""test_redsim.py — Unit test scope guard, skenario, runner, penolakan out-of-scope."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

AKAR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import audit_core
import forensics
import redsim


class ScopeBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.scope_path = os.path.join(self.dir.name, "scope.json")
        with open(self.scope_path, "w", encoding="utf-8") as f:
            json.dump({"hosts": ["lab-01.local", "lab-02.local"],
                       "cidrs": ["192.168.56.0/24"]}, f)
        self.events_path = os.path.join(self.dir.name, "events.jsonl")
        self.audit_path = os.path.join(self.dir.name, "audit.jsonl")
        # v4.0: simpan nilai asli agar bisa direstore di tearDown (dulu bocor
        # ke test lain — test_redsim menimpa AUDIT_FILE global tanpa restore,
        # membuat test_slc_redblue gagal dengan tmpdir yang sudah dihapus).
        self._audit_asli = redsim.AUDIT_FILE
        redsim.AUDIT_FILE = self.audit_path
        self.guard = redsim.ScopeGuard(self.scope_path)

    def tearDown(self):
        redsim.AUDIT_FILE = self._audit_asli  # v4.0: pulihkan modul
        self.dir.cleanup()


class TestScopeGuard(ScopeBase):
    def test_host_scope_valid(self):
        self.assertTrue(self.guard.in_scope("lab-01.local"))

    def test_ip_dalam_cidr(self):
        self.assertTrue(self.guard.in_scope("192.168.56.77"))

    def test_ip_luar_cidr_ditolak(self):
        self.assertFalse(self.guard.in_scope("8.8.8.8"))

    def test_host_tidak_dikenal_ditolak(self):
        self.assertFalse(self.guard.in_scope("komp-korban.local"))

    def test_assert_out_of_scope_raise_dan_audit(self):
        with self.assertRaises(redsim.ScopeError):
            self.guard.assert_in_scope("8.8.8.8", aktor="tester")
        audit = audit_core.AuditLog(self.audit_path)
        entries = audit.entries()
        self.assertTrue(any(e["aksi"] == "REFUSED_OUT_OF_SCOPE"
                            for e in entries))
        self.assertIsNone(audit.verify())


class TestScenarioRunner(ScopeBase):
    def setUp(self):
        super().setUp()
        self.runner = redsim.ScenarioRunner(
            self.scope_path, self.events_path, self.audit_path)

    def test_empat_skenario_jalan(self):
        laporan = self.runner.run()
        self.assertEqual(laporan["n_run"], 4)
        self.assertEqual(len([h for h in laporan["hasil"]
                              if h["status"] == "OK"]), 4)

    def test_semua_skenario_terdeteksi(self):
        laporan = self.runner.run()
        self.assertEqual(laporan["n_detected"], 4)
        self.assertEqual(laporan["detection_rate"], 1.0)

    def test_mitre_mapping_ada(self):
        for s in self.runner.skenario:
            self.assertIn(s.mitre, ("T1046", "T1071", "T1547", "T1078"))

    def test_event_dipersist_ke_file(self):
        self.runner.run()
        store = forensics.EventStore(self.events_path)
        entries = store.load()
        self.assertEqual(len(entries), 4)  # bug v-awal: dulu tidak persist
        self.assertIsNone(store.verify())
        self.assertTrue(all(e["kind"] == "redsim" for e in entries))

    def test_audit_utuh_setelah_run(self):
        laporan = self.runner.run()
        self.assertTrue(laporan["integritas_audit"])

    def test_cleanup_tanpa_artefak_sistem(self):
        self.runner.run()
        for h in self.runner.run()["hasil"]:
            self.assertIn("tidak ada artefak", h["cleanup"])


class TestScopeFileRepo(unittest.TestCase):
    def test_scope_default_repo_valid(self):
        path = os.path.join(AKAR, "lab_scope.json")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("lab-01.local", data["hosts"])
        self.assertEqual(data["cidrs"], ["192.168.56.0/24"])


if __name__ == "__main__":
    unittest.main()
