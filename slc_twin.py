#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_twin.py — v4.0 Sovereign Lab Control: CYBER DIGITAL TWIN.

Model lab dari inventaris terverifikasi + relasi yang DIAMATI (bukan
ditebak). Aturan kejujuran:
  - dependensi ditandai "terverifikasi" HANYA bila ada bukti telemetri;
    sisanya adalah ASUMSI dan selalu dilabeli demikian.
  - temuan punya confidence 0..1 + bukti; tidak pernah "fakta" tanpa bukti.
  - WHAT-IF tidak pernah menyentuh perangkat fisik — hanya mengevaluasi
    model; hasil memisahkan dampak terverifikasi vs asumsi vs informasi
    yang kurang + usulan uji validasi.
"""
from __future__ import annotations

import json
import time


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class TwinError(ValueError):
    pass


class TwinModel:
    """Model: endpoint, layanan, dependensi (terverifikasi/asumsi),
    kesehatan, temuan, dan sejarah perubahan konfigurasi."""

    def __init__(self, nama_lab="Lab Universitas"):
        self.nama = nama_lab
        self.endpoints = {}    # id -> {nama, grup, sehat: bool|None, meta}
        self.layanan = {}      # id -> {"dev", "nama", "status"}
        self.dependensi = []   # {"dari","ke","jenis","terverifikasi","bukti"}
        self.temuan = []       # {"id","deskripsi","confidence","bukti"}
        self.sejarah = []      # perubahan konfigurasi (audit model)

    # ---------------- isi model ----------------
    def tambah_endpoint(self, dev_id, nama, grup=None, sehat=None):
        if dev_id in self.endpoints:
            raise TwinError(f"endpoint duplikat: {dev_id}")
        self.endpoints[dev_id] = {"nama": nama, "grup": grup or [],
                                  "sehat": sehat, "sejak": now_iso()}
        return self.endpoints[dev_id]

    def tambah_layanan(self, layanan_id, dev_id, nama, status="BERJALAN"):
        if dev_id not in self.endpoints:
            raise TwinError(f"dev tidak ada di model: {dev_id}")
        self.layanan[layanan_id] = {"dev": dev_id, "nama": nama,
                                    "status": status}
        return self.layanan[layanan_id]

    def tambah_dependensi(self, dari, ke, jenis="menggunakan",
                          terverifikasi=False, bukti=None):
        for e in (dari, ke):
            if e not in self.layanan and e not in self.endpoints:
                raise TwinError(f"objek dependensi tidak ada: {e}")
        d = {"dari": dari, "ke": ke, "jenis": jenis,
             "terverifikasi": bool(terverifikasi), "bukti": bukti}
        if d["terverifikasi"] and not bukti:
            raise TwinError("dependensi terverifikasi WAJIB punya bukti")
        self.dependensi.append(d)
        return d

    def tambah_temuan(self, temuan_id, deskripsi, confidence, bukti):
        if not (0.0 <= confidence <= 1.0):
            raise TwinError("confidence harus 0..1")
        self.temuan.append({"id": temuan_id, "deskripsi": deskripsi,
                            "confidence": confidence, "bukti": bukti})
        return self.temuan[-1]

    def catat_perubahan(self, objek, perubahan, oleh="model"):
        self.sejarah.append({"ts": now_iso(), "objek": objek,
                             "perubahan": perubahan, "oleh": oleh})

    # ---------------- kesehatan & tampilan ----------------
    def status(self):
        ep = []
        for k, v in self.endpoints.items():
            lay = [l for l, m in self.layanan.items()
                   if m["dev"] == k]
            ep.append({"id": k, "nama": v["nama"], "grup": v["grup"],
                       "sehat": v["sehat"],
                       "sehat_catatan": "TIDAK DIKETAHUI — belum ada "
                       "telemetri kesehatan" if v["sehat"] is None else "",
                       "layanan": lay})
        return {"lab": self.nama, "endpoints": ep, "n_layanan":
                len(self.layanan),
                "n_dependensi": len(self.dependensi),
                "n_dependensi_terverifikasi": sum(
                    1 for d in self.dependensi if d["terverifikasi"]),
                "temuan": self.temuan}

    # ---------------- WHAT-IF ----------------
    def what_if(self, aksi, target, catatan_operator=None):
        """Evaluasi hipotesis terhadap MODEL saja (tidak menyentuh fisik).
        Contoh: what_if("matikan_layanan", "svc-demo")"""
        dampak_tapak, asumsi, kurang, uji = [], [], [], []
        if aksi == "matikan_layanan":
            if target not in self.layanan:
                raise TwinError(f"layanan tidak ada di model: {target}")
            svc = self.layanan[target]
            self.catat_perubahan(target, f"SIMULASI {aksi} (what-if)",
                                 oleh="what-if")
            # dependensi TERVERIFIKASI yang putus = dampak faktual
            for d in self.dependensi:
                if d["ke"] == target and d["terverifikasi"]:
                    dampak_tapak.append(
                        f"{d['dari']} {d['jenis']} {target} — PUTUS "
                        f"(bukti: {d['bukti']})")
                elif d["ke"] == target:
                    asumsi.append(
                        f"{d['dari']} mungkin bergantung pada {target} "
                        "— ASUMSI (belum ada bukti telemetri)")
            uji.append(f"jalankan aksi 'kesehatan' di {svc['dev']} "
                       "sebelum & sesudah (bila benar-benar dieksekusi)")
            uji.append(f"pantau event kind=slc dari {svc['dev']}")
            if svc["status"] == "BERHENTI":
                kurang.append("layanan target sudah BERHENTI — "
                              "dampak mungkin sudah terjadi")
        else:
            raise TwinError(f"aksi what-if tidak dikenal: {aksi}")
        return {
            "aksi": aksi, "target": target, "model_saja": True,
            "catatan": catatan_operator,
            "dampak_terverifikasi": dampak_tapak,
            "asumsi": asumsi,
            "informasi_kurang": kurang,
            "usulan_uji_validasi": uji,
            "peringatan": "HASIL SIMULASI MODEL — bukan bukti empiris; "
                          "dependensi asumsi TIDAK boleh dilaporkan "
                          "sebagai fakta.",
        }

    def ekspor(self):
        return json.dumps(self.status(), ensure_ascii=False, indent=1)
