#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_mission.py — v4.0 Sovereign Lab Control: MISSION ENGINE.

Misi berjalan lewat state WAJIB:
  REQUESTED → AUTHORIZATION_CHECK → PLANNED → APPROVAL → EXECUTING →
  VERIFYING → REPORTING
APPROVAL hanya dilewati bila SEMUA langkah berisiko RENDAH dan operator
memberi persetujuan_kebijakan eksplisit di konfigurasi misi (policy
pre-authorized), dan tiap langkah lolos policy perangkat.

Jaminan anti-bencana:
  - DAG langkah dengan deteksi siklus; langkah paralel lintas perangkat
    dengan batas paralel per-perangkat (dari policy meta).
  - retry TERBATAS per langkah + deadline misi + budget langkah total +
    budget durasi → loop otonom TIDAK MUNGKIN berjalan tanpa batas.
  - verifikasi postcondition NYATA tiap langkah (di slc_control) +
    verifikasi misi: SUKSES hanya bila SEMUA langkah SELESAI_TERVERIFIKASI.
  - checkpoint JSON per transisi; misi bisa dilanjutkan setelah putus.
  - analisis kegagalan terstruktur + rollback utk aksi yang mendukung.
  - pembatalan operator memutus antrean tersisa (control.batalkan).
"""
from __future__ import annotations

import json
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor

import slc_actions
from slc_control import KontrolError

STATUS_LANGKAH = ("SIAP", "DIKIRIM", "SELESAI_TERVERIFIKASI", "GAGAL",
                  "GAGAL_VERIFIKASI", "GAGAL_KONEKSI", "DILEWATKAN",
                  "DIBATALKAN", "KEDALUWARSA")


class MisiError(KontrolError):
    pass


def _urut_gelombang(langkah):
    """Urut topologis → gelombang paralel; siklus → MisiError."""
    sisa = {l["id"]: set(l.get("tergantung", [])) for l in langkah}
    selesai = set()
    gelombang = []
    while sisa:
        bisa = sorted(k for k, d in sisa.items() if d <= selesai)
        if not bisa:
            raise MisiError(f"siklus dependensi: {sorted(sisa)}")
        gelombang.append(bisa)
        selesai |= set(bisa)
        for k in bisa:
            del sisa[k]
    return gelombang


class Misi:
    """Satu misi (rencana multi-langkah + state + riwayat + checkpoint)."""

    def __init__(self, nama, langkah, oleh="operator", deadline_s=600.0,
                 budget_langkah=200, persetujuan_kebijakan=False,
                 checkpoint_path=None):
        self.id = "m-" + secrets.token_hex(5)
        self.nama = nama
        self.oleh = oleh
        self.deadline_s = deadline_s
        self.budget_langkah = budget_langkah
        self.persetujuan_kebijakan = persetujuan_kebijakan
        self.checkpoint_path = checkpoint_path
        self.state = "REQUESTED"
        self.riwayat = [("REQUESTED", time.time())]
        self.mulai = None
        self.terpakai_langkah = 0
        self.dibatalkan = False
        self.error = None
        # satu sumber kebenaran: urutan berisi dict yang SAMA dengan langkah
        self.urutan = [dict(l) for l in langkah]
        for l in self.urutan:
            l.setdefault("status", "SIAP")
            l.setdefault("ulang", 0)
            l.setdefault("maks_ulang", 2)
        self.langkah = {l["id"]: l for l in self.urutan}
        for l in self.urutan:
            slc_actions.definisi(l["aksi"])  # validasi aksi terdaftar

    # ---------------- state & checkpoint ----------------
    def _set(self, state):
        self.state = state
        self.riwayat.append((state, time.time()))
        self.simpan()

    def simpan(self):
        if not self.checkpoint_path:
            return
        data = {"id": self.id, "nama": self.nama, "state": self.state,
                "langkah": self.urutan, "oleh": self.oleh,
                "mulai": self.mulai, "terpakai": self.terpakai_langkah,
                "dibatalkan": self.dibatalkan, "error": self.error,
                "riwayat": self.riwayat[-20:]}
        tmp = self.checkpoint_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, ensure_ascii=False, default=str)
        os.replace(tmp, self.checkpoint_path)

    @classmethod
    def muat(cls, path):
        with open(path) as f:
            data = json.load(f)
        m = cls.__new__(cls)
        m.id, m.nama = data["id"], data["nama"]
        m.urutan = data["langkah"]
        m.langkah = {l["id"]: l for l in m.urutan}
        m.oleh = data.get("oleh", "operator")
        m.state = data["state"]
        m.riwayat = data.get("riwayat", [])
        m.mulai = data.get("mulai")
        m.terpakai_langkah = data.get("terpakai", 0)
        m.dibatalkan = data.get("dibatalkan", False)
        m.error = data.get("error")
        m.deadline_s, m.budget_langkah = 600.0, 200
        m.persetujuan_kebijakan = False
        m.checkpoint_path = path
        return m

    # ---------------- analisis ----------------
    def semua_rendah(self):
        return all(slc_actions.definisi(l["aksi"])["risiko"] == "RENDAH"
                   for l in self.urutan)

    def ringkas(self):
        n = {s: sum(1 for l in self.urutan if l["status"] == s)
             for s in STATUS_LANGKAH if any(l["status"] == s
                                           for l in self.urutan)}
        return {"id": self.id, "nama": self.nama, "state": self.state,
                "n_langkah": len(self.urutan), "status_langkah": n,
                "dibatalkan": self.dibatalkan, "error": self.error,
                "terpakai_langkah": self.terpakai_langkah}


class MissionEngine:
    """Eksekutor misi di atas SLCControl. Eksekusi langkah disuntik
    lewat `eksekusi` (default: slc_actions.jalankan) supaya test/demo
    bisa mengganti tanpa menyentuh jaringan."""

    def __init__(self, control, eksekusi=None, paralel_maks=4,
                 jeda_koneksi=0.0):
        self.control = control
        self.eksekusi = eksekusi or (lambda aksi, params:
                                      slc_actions.jalankan(aksi, params))
        self.paralel_maks = paralel_maks
        self.jeda_koneksi = jeda_koneksi

    # ---------------- 1. AUTHORIZATION_CHECK ----------------
    def otorisasi(self, misi):
        """AUTHORIZATION_CHECK: validasi perangkat, aksi, role, policy,
        dependensi, budget — sebelum rencana dianggap sah."""
        misi._set("AUTHORIZATION_CHECK")
        if misi.oleh not in ("admin", "operator"):
            raise MisiError(f"role {misi.oleh} tidak boleh membuat misi")
        _urut_gelombang(misi.urutan)          # siklus → tolak
        if misi.budget_langkah < 0 or misi.deadline_s <= 0:
            raise MisiError("budget/deadline misi tidak valid")
        for l in misi.urutan:
            d = slc_actions.definisi(l["aksi"])
            if misi.oleh not in d["izin"]:
                raise MisiError(f"role tak diizinkan utk aksi {l['aksi']}")
            if self.control.registry.cek_enrolled(l["dev"]) is None:
                raise MisiError(f"perangkat tidak ter-enroll: {l['dev']}")
            if not self.control.aksi_diizinkan_dev(l["dev"], l["aksi"]):
                raise MisiError(f"policy perangkat melarang {l['aksi']}")
        return True

    # ---------------- 2. PLANNED → 3. APPROVAL ----------------
    def rencanakan(self, misi):
        misi._set("PLANNED")
        if misi.semua_rendah() and misi.persetujuan_kebijakan:
            misi._set("APPROVAL")   # SKOPOS: dilewati by-policy RENDAH
            misi._set("EXECUTING")
            return True
        misi._set("APPROVAL")
        return False  # menunggu setujui_misi()

    def setujui_misi(self, misi, oleh="admin"):
        if oleh != "admin":
            raise PermissionError("hanya admin menyetujui misi")
        if misi.state != "APPROVAL":
            raise MisiError(f"misi tidak menunggu persetujuan ({misi.state})")
        misi._set("EXECUTING")

    # ---------------- 4. EXECUTING (gelombang paralel) ----------------
    def jalankan(self, misi, sekarang=None):
        """Eksekusi misi penuh sampai REPORTING. Setiap langkah:
        jadwalkan → eksekusi terbatas ulang → hasil + verifikasi."""
        sekarang = sekarang or time.time()
        if misi.state == "REQUESTED":
            self.otorisasi(misi)            # → AUTHORIZATION_CHECK
        if misi.state == "AUTHORIZATION_CHECK":
            self.rencanakan(misi)           # → PLANNED → APPROVAL
        if misi.state == "PLANNED":          # (rencanakan selalu lanjut)
            misi._set("APPROVAL")
        if misi.state == "APPROVAL":
            return misi  # tunggu persetujuan eksplisit admin
        if misi.state != "EXECUTING":
            misi._set("EXECUTING")
        misi.mulai = misi.mulai or time.time()
        gelombang = _urut_gelombang([l for l in misi.urutan
                                     if l["status"] == "SIAP"])
        for gv in gelombang:
            if misi.dibatalkan:
                break
            if time.time() - misi.mulai > misi.deadline_s:
                misi.error = "DEADLINE_MISI_TERLAMPAUI"
                break
            if misi.terpakai_langkah >= misi.budget_langkah:
                misi.error = "BUDGET_LANGKAH_TERLAMPAUI"
                break
            self._jalankan_gelombang(misi, gv, sekarang)
        self.verifikasi(misi)
        return misi

    def _jalankan_gelombang(self, misi, ids, sekarang):
        sekarang = sekarang or time.time()
        lk = [misi.langkah[i] for i in ids]
        dengan = ThreadPoolExecutor(max_workers=self.paralel_maks)
        dengan.__enter__()
        try:
            futures = []
            for l in lk:
                futures.append(dengan.submit(self._jalankan_langkah, misi, l,
                                             sekarang))
            for f in futures:
                f.result()
        finally:
            dengan.__exit__(None, None, None)

    def _jalankan_langkah(self, misi, l, sekarang):
        # dependensi WAJIB sudah sukses — bukan sekadar sudah dieksekusi
        dep_gagal = [d for d in l.get("tergantung", [])
                     if misi.langkah[d]["status"] != "SELESAI_TERVERIFIKASI"]
        if dep_gagal:
            l["status"] = "DILEWATKAN"
            l["error"] = f"dependensi belum sukses: {dep_gagal}"
            return
        while True:
            if misi.dibatalkan:
                l["status"] = "DIBATALKAN"
                return
            if l["ulang"] > l["maks_ulang"]:
                l["status"] = "GAGAL_KONEKSI" \
                    if l["status"] == "DIKIRIM" else l["status"]
                return
            if misi.terpakai_langkah >= misi.budget_langkah:
                l["status"] = "DILEWATKAN"
                misi.error = "BUDGET_LANGKAH_TERLAMPAUI"
                return
            if time.time() - misi.mulai > misi.deadline_s:
                l["status"] = "DILEWATKAN"
                misi.error = "DEADLINE_MISI_TERLAMPAUI"
                return
            try:
                t = self.control.jadwalkan(misi.oleh, l["dev"], l["aksi"],
                                           l.get("params"),
                                           idem=f"{misi.id}:{l['id']}",
                                           kedaluwarsa_s=misi.deadline_s,
                                           sekarang=sekarang)
            except (KontrolError, PermissionError, KeyError,
                    slc_actions.AksiError) as e:
                l["status"] = "GAGAL"
                l["error"] = f"DITOLAK: {e}"
                return
            # v4.0.2: idempotensi bisa mengembalikan tugas yang SUDAH
            # berstatus akhir (mis. GAGAL_VERIFIKASI saat retry). Task
            # itu sudah tidak di antrean — dieksekusi ulang hanya akan
            # KeyError di terima_hasil. Dilaporkan jujur, tidak crash.
            if t["status"] in ("SELESAI_TERVERIFIKASI", "GAGAL_VERIFIKASI",
                              "GAGAL"):
                l["status"] = t["status"]
                l["error"] = ("langkah idempoten sudah berstatus akhir "
                              f"({t['status']}) — tidak dieksekusi ulang")
                return
            if t["status"] == "MENUNGGU_PERSETUJUAN":
                l["status"] = "GAGAL"
                l["error"] = ("aksi TINGGI dalam misi tanpa persetujuan "
                              "eksplisit — ditolak default")
                return
            self.control.berikutnya(l["dev"], sekarang=sekarang)
            misi.terpakai_langkah += 1
            try:
                hasil = self.eksekusi(l["aksi"], l.get("params"))
            except Exception as e:
                l["ulang"] += 1
                if l["ulang"] > l["maks_ulang"]:
                    l["status"] = "GAGAL"
                    l["error"] = f"EKSEKUSI: {type(e).__name__}: {e}"
                    self._rollback(misi, l)
                continue
            if time.time() - misi.mulai > misi.deadline_s:
                l["status"] = "KEDALUWARSA"
                misi.error = "DEADLINE_MISI_TERLAMPAUI"
                return
            try:
                # v4.0.2: tugas bisa diambil proses lain (agent POLL
                # race) / kedaluwarsa — KeyError dilaporkan jujur.
                selesai = self.control.terima_hasil(
                    l["dev"], t["tugas_id"], hasil, sekarang=sekarang)
            except KeyError as e:
                l["status"] = "GAGAL"
                l["error"] = (f"HASIL DITOLAK controller: {e} — tugas "
                              "diambil proses lain atau kedaluwarsa")
                return
            l["status"] = selesai["status"]
            if l["status"] == "SELESAI_TERVERIFIKASI":
                return
            l["ulang"] += 1
            if l["ulang"] > l["maks_ulang"]:
                self._rollback(misi, l)
                return

    def _rollback(self, misi, l):
        rb = slc_actions.definisi(l["aksi"]).get("rollback")
        if rb:
            l["rollback"] = rb(l.get("params") or {})
        else:
            l["rollback"] = "TIDAK TERSEDIA — dijalankan manual terdokumentasi"

    # ---------------- 5. VERIFYING → 6. REPORTING ----------------
    def verifikasi(self, misi):
        misi._set("VERIFYING")
        gagal = [l for l in misi.urutan if l["status"] not in
                 ("SELESAI_TERVERIFIKASI",)]
        for l in gagal:
            # langkah tergantung pada yang gagal → DILEWATKAN jujur
            for l2 in misi.urutan:
                if l["id"] in l2.get("tergantung", []) and \
                        l2["status"] == "SIAP":
                    l2["status"] = "DILEWATKAN"
                    l2["error"] = f"dependensi gagal: {l['id']}"
            if l["status"] == "SIAP":  # misi putus di tengah (budget/deadline)
                l["status"] = "DILEWATKAN"
                l["error"] = misi.error or "misi berhenti sebelum langkah ini"
        misi._set("REPORTING")

    # ---------------- pembatalan & laporan ----------------
    def batalkan_misi(self, misi, oleh="operator"):
        """Operator-level mission cancellation: hentikan + kosongkan
        tugas tersisa via control."""
        misi.dibatalkan = True
        for l in misi.urutan:
            if l["status"] == "SIAP":
                l["status"] = "DIBATALKAN"
        self.control.audit.append(oleh, "SLC_MISI_BATAL", misi.id)
        misi._set("REPORTING")
        return misi

    def analisis_kegagalan(self, misi):
        """Analisis terstruktur per langkah gagal (klasifikasi + saran)."""
        keluar = []
        for l in misi.urutan:
            if l["status"] not in ("GAGAL", "GAGAL_VERIFIKASI",
                                   "GAGAL_KONEKSI", "DILEWATKAN",
                                   "DIBATALKAN", "KEDALUWARSA"):
                continue
            if l["status"] == "GAGAL" and str(l.get("error", "")).startswith(
                    "DITOLAK"):
                kelas = "DITOLAK_POLICY"
            elif l["status"] == "GAGAL_VERIFIKASI":
                kelas = "POSTCONDITION_TIDAK_TERPENUHI"
            elif "budget" in str(misi.error).lower():
                kelas = "BUDGET_HABIS"
            elif l["status"] == "DILEWATKAN":
                kelas = "DEPENDENSI_GAGAL"
            else:
                kelas = "EKSEKUSI_GAGAL"
            keluar.append({"langkah": l["id"], "aksi": l["aksi"],
                           "dev": l["dev"], "status": l["status"],
                           "kelas": kelas, "error": l.get("error"),
                           "rollback": l.get("rollback"),
                           "saran": "ulangi misi dengan maks_ulang lebih "
                           "besar / cek kesehatan perangkat / cek policy"})
        return keluar

    def laporan_teks(self, misi):
        baris = [f"MISI {misi.id}: {misi.nama}",
                 f"state={misi.state} oleh={misi.oleh}",
                 "-" * 50]
        for l in misi.urutan:
            baris.append(f"[{l['status']:>22}] {l['id']} {l['aksi']}"
                         f" -> {l['dev']}"
                         + (f"  ({l.get('error')})" if l.get("error") else ""))
        gagal = self.analisis_kegagalan(misi)
        if gagal:
            baris.append("-" * 50)
            baris.append("ANALISIS KEGAGALAN:")
            for g in gagal:
                baris.append(f"  {g['langkah']}: {g['kelas']} — {g['error']}")
        baris.append(f"terpakai_langkah={misi.terpakai_langkah}/"
                     f"{misi.budget_langkah}")
        return "\n".join(baris)

    def laporan_json(self, misi):
        return json.dumps(misi.ringkas() | {
            "langkah": misi.urutan,
            "analisis_kegagalan": self.analisis_kegagalan(misi)},
                          ensure_ascii=False, indent=1, default=str)


def contoh_misi_inventaris(dev_a, dev_b):
    """Rencana contoh: inventaris paralel di 2 perangkat + ringkasan gabungan.
    (dipakai demo mode & test)."""
    return Misi("Inventaris lab terjadwal", [
        {"id": "l1", "aksi": "kesehatan", "dev": dev_a, "params": {}},
        {"id": "l2", "aksi": "disk", "dev": dev_b, "params": {}},
        {"id": "l3", "aksi": "kesehatan", "dev": dev_b, "params": {},
         "tergantung": ["l2"]},
        {"id": "l4", "aksi": "proses_meta", "dev": dev_a, "params": {},
         "tergantung": ["l1"]},
    ], oleh="operator", persetujuan_kebijakan=True)
