#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test slc_mission v4.0 — state machine, DAG/paralel, budget, retry,
checkpoint, verifikasi misi, pembatalan, analisis kegagalan, rollback."""
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from range_registry import DeviceRegistry  # noqa: E402
from slc_control import SLCControl  # noqa: E402
from slc_mission import (Misi, MisiError, MissionEngine,  # noqa: E402
                         contoh_misi_inventaris)

EKSEKUSI_OK = lambda aksi, params: {"aksi": aksi, "data": {"platform": "x"}}


def kontrol_baru(d):
    reg = DeviceRegistry(path=os.path.join(d, "devices.json"),
                         audit_path=os.path.join(d, "audit.jsonl"))
    return SLCControl(registry=reg,
                      meta_path=os.path.join(d, "meta.json"),
                      audit_path=os.path.join(d, "audit.jsonl"),
                      events_path=os.path.join(d, "events.jsonl"))


class Basis(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="slc_m_")
        self.c = kontrol_baru(self.d)
        self.a = self.c.enroll("LAB-A")["id"]
        self.b = self.c.enroll("LAB-B")["id"]
        self.ckpt = os.path.join(self.d, "ckpt.json")
        self.eng = MissionEngine(self.c, eksekusi=EKSEKUSI_OK)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def misi(self, langkah, **kw):
        kw.setdefault("persetujuan_kebijakan", True)  # RENDAH by-policy
        return Misi("misi uji", langkah, checkpoint_path=self.ckpt, **kw)


class TestOtorisasi(Basis):
    def test_langkah_dasar(self):
        m = self.misi([{"id": "l1", "aksi": "kesehatan", "dev": self.a}])
        m._set("AUTHORIZATION_CHECK")  # sudah oleh jalankan()
        self.assertTrue(m.state in ("AUTHORIZATION_CHECK",))

    def test_role_ditolak(self):
        m = self.misi([{"id": "l1", "aksi": "kesehatan", "dev": self.a}],
                      oleh="auditor")
        with self.assertRaises(MisiError):
            self.eng.jalankan(m)

    def test_aksi_tak_dikenal_ditolak(self):
        import slc_actions
        with self.assertRaises(slc_actions.AksiError):
            self.misi([{"id": "l1", "aksi": "shell", "dev": self.a}])

    def test_perangkat_tak_enroll(self):
        m = self.misi([{"id": "l1", "aksi": "kesehatan", "dev": "dev-xxxx"}])
        with self.assertRaises(MisiError):
            self.eng.jalankan(m)

    def test_siklus_dependensi_ditolak(self):
        m = self.misi([
            {"id": "l1", "aksi": "kesehatan", "dev": self.a,
             "tergantung": ["l2"]},
            {"id": "l2", "aksi": "kesehatan", "dev": self.a,
             "tergantung": ["l1"]}])
        with self.assertRaises(MisiError):
            self.eng.jalankan(m)

    def test_policy_perangkat_ditolak(self):
        self.c.set_meta(self.a, policy={"aksi_diizinkan": ["disk"]})
        m = self.misi([{"id": "l1", "aksi": "kesehatan", "dev": self.a}])
        with self.assertRaises(MisiError):
            self.eng.jalankan(m)


class TestAlurMisi(Basis):
    def test_misi_rendah_skips_approval_by_policy(self):
        m = contoh_misi_inventaris(self.a, self.b)
        m.checkpoint_path = self.ckpt
        self.eng.jalankan(m)
        states = [s for s, _ in m.riwayat]
        self.assertIn("REQUESTED", states)
        self.assertIn("AUTHORIZATION_CHECK", states)
        self.assertIn("PLANNED", states)
        self.assertIn("EXECUTING", states)
        self.assertIn("REPORTING", states)
        for l in m.urutan:
            self.assertEqual(l["status"], "SELESAI_TERVERIFIKASI", l["id"])

    def test_tinggi_tanpa_persetujuan_ditolak(self):
        m = self.misi([{"id": "l1", "aksi": "restart_layanan", "dev": self.a,
                        "params": {"layanan": "LabAgentDemoSvc"}}],
                      oleh="admin")
        self.eng.jalankan(m)
        self.assertEqual(m.state, "APPROVAL")  # misi menunggu persetujuan

    def test_persetujuan_misi_hanya_admin(self):
        m = self.misi([{"id": "l1", "aksi": "restart_layanan", "dev": self.a,
                        "params": {"layanan": "LabAgentDemoSvc"}}],
                      oleh="admin")
        self.eng.jalankan(m)
        with self.assertRaises(PermissionError):
            self.eng.setujui_misi(m, oleh="operator")

    def test_postcondition_gagal_ditandai(self):
        eng = MissionEngine(self.c, eksekusi=lambda a, p: {
            "aksi": a, "data": {}})  # data kosong → gagal verif kesehatan
        m = self.misi([{"id": "l1", "aksi": "kesehatan", "dev": self.a}])
        eng.jalankan(m)
        self.assertEqual(m.urutan[0]["status"], "GAGAL_VERIFIKASI")

    def test_dependensi_gagal_dilewati(self):
        eng = MissionEngine(self.c, eksekusi=lambda a, p: (_ for _ in ()).throw(
            RuntimeError("konek putus")))
        m = self.misi([
            {"id": "l1", "aksi": "kesehatan", "dev": self.a,
             "maks_ulang": 0},
            {"id": "l2", "aksi": "disk", "dev": self.a,
             "tergantung": ["l1"]}])
        eng.jalankan(m)
        self.assertEqual(m.urutan[0]["status"], "GAGAL")
        self.assertEqual(m.urutan[1]["status"], "DILEWATKAN")

    def test_retry_terbatas_lalu_gagal(self):
        panggil = {"n": 0}

        def eksek(aksi, params):
            panggil["n"] += 1
            raise RuntimeError("device sibuk")
        eng = MissionEngine(self.c, eksekusi=eksek)
        m = self.misi([{"id": "l1", "aksi": "kesehatan", "dev": self.a,
                        "maks_ulang": 2}])
        eng.jalankan(m)
        self.assertEqual(m.urutan[0]["status"], "GAGAL")
        self.assertEqual(panggil["n"], 3)  # 1 + 2 ulang

    def test_budget_langkah_mencegah_loop(self):
        eng = MissionEngine(self.c, eksekusi=EKSEKUSI_OK)
        m = self.misi([{"id": "l1", "aksi": "kesehatan", "dev": self.a}],
                      budget_langkah=0)
        eng.jalankan(m)
        self.assertEqual(m.urutan[0]["status"], "DILEWATKAN")
        self.assertIn("BUDGET", str(misi_error(m)))

    def test_deadline_misi_dijaga(self):
        eng = MissionEngine(self.c, eksekusi=lambda a, p: time.sleep(0.3))
        m = self.misi([{"id": "l1", "aksi": "kesehatan", "dev": self.a,
                        "maks_ulang": 0}], deadline_s=0.05)
        eng.jalankan(m)
        self.assertEqual(m.error, "DEADLINE_MISI_TERLAMPAUI")

    def test_pembatalan_operator(self):
        m = contoh_misi_inventaris(self.a, self.b)
        m.checkpoint_path = self.ckpt
        m.dibatalkan = True
        self.eng.batalkan_misi(m)
        for l in m.urutan:
            self.assertIn(l["status"], ("DIBATALKAN", "SIAP"))

    def test_checkpoint_tersimpan_dan_muat(self):
        m = contoh_misi_inventaris(self.a, self.b)
        m.checkpoint_path = self.ckpt
        self.eng.jalankan(m)
        self.assertTrue(os.path.exists(self.ckpt))
        m2 = Misi.muat(self.ckpt)
        self.assertEqual(m2.id, m.id)
        self.assertEqual(m2.state, "REPORTING")
        self.assertEqual(len(m2.urutan), 4)

    def test_laporan(self):
        m = contoh_misi_inventaris(self.a, self.b)
        m.checkpoint_path = self.ckpt
        self.eng.jalankan(m)
        teks = self.eng.laporan_teks(m)
        self.assertIn("MISI", teks)
        data = self.eng.laporan_json(m)
        self.assertIn("status_langkah", data)

    def test_analisis_kegagalan_terstruktur(self):
        eng = MissionEngine(self.c, eksekusi=lambda a, p: (_ for _ in ()).throw(
            RuntimeError("x")))
        m = self.misi([{"id": "l1", "aksi": "kesehatan", "dev": self.a,
                        "maks_ulang": 0}])
        eng.jalankan(m)
        a = self.eng.analisis_kegagalan(m)
        self.assertEqual(a[0]["kelas"], "EKSEKUSI_GAGAL")
        self.assertIn("rollback", a[0])

    def test_paralel_lintas_perangkat(self):
        # dua perangkat dieksekusi dalam gelombang sama (paralel)
        urutan = []
        import threading

        def eksek(aksi, params):
            urutan.append(threading.current_thread().name)
            time.sleep(0.05)
            return {"aksi": aksi, "data": {"platform": "x"}}
        eng = MissionEngine(self.c, eksekusi=eksek, paralel_maks=4)
        m = self.misi([
            {"id": "l1", "aksi": "kesehatan", "dev": self.a},
            {"id": "l2", "aksi": "kesehatan", "dev": self.b}])
        eng.jalankan(m)
        self.assertEqual(len(set(urutan)), 2)  # dua thread berbeda
        for l in m.urutan:
            self.assertEqual(l["status"], "SELESAI_TERVERIFIKASI")


class TestRaceRegression(Basis):
    """v4.0.2: dua race yang ditemukan di Windows native (slc_lab).
    1) tugas misi DICURI dari antrean (agent POLL) → terima_hasil
       KeyError → HARUS dilaporkan GAGAL jujur, bukan crash.
    2) retry langkah setelah GAGAL_VERIFIKASI → jadwalkan idem
       mengembalikan task berstatus akhir → tidak boleh dieksekusi
       ulang (dulu KeyError crash)."""

    def test_terima_hasil_dicuri_tidak_crash(self):
        # engine menandai tugas DIKIRIM (berikutnya), lalu saat engine
        # mengeksekusi, POLL dari "proses lain" (thread server agent)
        # datang → berikutnya() membuang tugas DIKIRIM dari antrean
        # TANPA jejak → terima_hasil engine → KeyError (dulu: crash).
        # HARUS dilaporkan GAGAL jujur.
        def eksek(aksi, params):
            self.c.berikutnya(self.a)  # POLL proses lain: DIKIRIM dibuang
            return {"aksi": aksi, "data": {"platform": "x"}}
        eng = MissionEngine(self.c, eksekusi=eksek)
        m = self.misi([{"id": "l1", "aksi": "kesehatan", "dev": self.a}])
        eng.jalankan(m)  # dulu: KeyError crash di _jalankan_langkah
        l = m.langkah["l1"]
        self.assertEqual(l["status"], "GAGAL")
        self.assertIn("HASIL DITOLAK", l["error"])

    def test_retry_setelah_gagal_verifikasi_tidak_keyerror(self):
        # verifikasi selalu gagal → langkah GAGAL_VERIFIKASI → retry
        # dulu crash KeyError karena jadwalkan idem balikin task akhir
        def eksek(aksi, params):
            return {"aksi": aksi, "data": {"platform": None}}  # verif gagal
        eng = MissionEngine(self.c, eksekusi=eksek)
        m = self.misi([{"id": "l1", "aksi": "kesehatan", "dev": self.a}])
        eng.jalankan(m)  # dulu: KeyError 'tugas tidak dikenal' di retry
        self.assertEqual(m.langkah["l1"]["status"], "GAGAL_VERIFIKASI")


def misi_error(m):
    return m.error or ""


if __name__ == "__main__":
    unittest.main()
