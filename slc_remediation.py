#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_remediation.py — v4.0 Sovereign Lab Control: AUTONOMOUS REMEDIATION.

Alur WAJIB 12 langkah:
  1 temukan → 2 kumpulkan bukti → 3 usulkan remediasi → 4 klasifikasi
  risiko operasional → 5 inspeksi diff/konfigurasi → 6 jalankan tes
  relevan → 7 persetujuan → 8 checkpoint → 9 terapkan → 10 verifikasi
  state pasca → 11 rollback bila verifikasi gagal → 12 catat hasil.

Jaminan:
  - default hanya perubahan REVERSIBEL; TIDAK ADA (bahkan disetujui)
    penyusunan ulang kebijakan keamanan / akun user / firewall / sistem
    kritis TANPA rencana pemulihan tertulis (recovery_plan wajib).
  - tes HARUS lulus sebelum boleh minta persetujuan.
  - verifikasi gagal → rollback otomatis dijalankan bila tersedia.
"""
from __future__ import annotations

import json
import time

ZONA_LARANGAN = ("kebijakan_keamanan", "akun_pengguna", "firewall",
                 "konfigurasi_sistem_kritis")


class RemediasiError(ValueError):
    pass


class Remediasi:
    """Satu usulan remediasi (state machine 12 langkah)."""

    def __init__(self, temuan_id, deskripsi, bukti, usulan, diff,
                 zona=None, recovery_plan=None):
        if not bukti:
            raise RemediasiError("temuan TANPA bukti ditolak (langkah 2)")
        self.state = "DITEMUKAN"
        self.data = {"temuan_id": temuan_id, "deskripsi": deskripsi,
                     "bukti": bukti, "usulan": usulan, "diff": diff,
                     "zona": zona, "recovery_plan": recovery_plan,
                     "dibuat": time.strftime("%Y-%m-%d %H:%M:%S")}
        self.hasil_tes = None
        self.persetujuan = None
        self.checkpoint = None
        self.hasil_akhir = None
        self.riwayat = [("DITEMUKAN", self.data["dibuat"])]

    def _set(self, s):
        self.state = s
        self.riwayat.append((s, time.strftime("%Y-%m-%d %H:%M:%S")))

    def klasifikasi_risiko(self):
        """Langkah 4: risiko operasional (REVERSIBEL/TIDAK_REVERSIBEL/
        ZONA_LARANGAN — zona larangan butuh rencana pemulihan eksplisit)."""
        if self.data["zona"] in ZONA_LARANGAN and not self.data.get(
                "recovery_plan"):
            raise RemediasiError(
                f"zona '{self.data['zona']}' TIDAK BOLEH diubah tanpa "
                "rencana pemulihan tertulis")
        self._set("DIKLASIFIKASI")
        return self.data["zona"]


class RemediationEngine:
    """Menjalankan langkah 5..12 dengan callback nyata (testable)."""

    def __init__(self, tester=None, applier=None, verifier=None,
                 rollback=None, checkpoint=None):
        """Semua callback disuntik: tester()->hasil tes, applier(state)
        →sukses?, verifier(state)->(ok,catatan), rollback(checkpoint),
        checkpoint()→data backup."""
        self.tester = tester
        self.applier = applier
        self.verifier = verifier
        self.rollback = rollback
        self.checkpoint_maker = checkpoint

    def inspeksi_diff(self, remedi):
        """Langkah 5: diff WAJIB ada & terbaca operator."""
        if not remedi.data.get("diff"):
            raise RemediasiError("diff/konfigurasi usulan KOSONG — "
                                 "tidak boleh diterapkan buta")
        self._set(remedi, "DIINSPEKSI")
        return True

    def jalankan_tes(self, remedi):
        """Langkah 6: tes relevan wajib LULUS sebelum minta persetujuan."""
        if self.tester is None:
            raise RemediasiError("tidak ada test harness — remediasi "
                                 "dihentikan (tidak boleh lanjut buta)")
        hasil = self.tester(remedi)
        remedi.hasil_tes = hasil
        if not (hasil and hasil.get("lulus")):
            self._set(remedi, "TES_GAGAL")
            raise RemediasiError("tes remediasi GAGAL — tidak dilanjutkan")
        self._set(remedi, "TES_LULUS")
        return hasil

    def minta_persetujuan(self, remedi, oleh_admin=None):
        """Langkah 7: persetujuan eksplisit admin (id tercatat)."""
        if remedi.state != "TES_LULUS":
            raise RemediasiError(f"belum boleh minta persetujuan "
                                 f"({remedi.state})")
        remedi.persetujuan = oleh_admin or None
        if not oleh_admin:
            self._set(remedi, "MENUNGGU_PERSETUJUAN")
            return False
        self._set(remedi, "DISETUJUI")
        return True

    def terapkan(self, remedi):
        """Langkah 8..12: checkpoint → apply → verify → (rollback) → catat."""
        if remedi.persetujuan is None:
            raise RemediasiError("BELUM disetujui — terapkan ditolak")
        if self.checkpoint_maker:
            remedi.checkpoint = self.checkpoint_maker(remedi)
        self._set(remedi, "MENERAPKAN")
        sukses = self.applier(remedi) if self.applier else True
        if not sukses:
            self._set(remedi, "APPLY_GAGAL")
            self._rollback_jika_bisa(remedi, alasan="apply gagal")
            return self._catat(remedi, "GAGAL")
        ok, catatan = (self.verifier(remedi) if self.verifier
                       else (True, "tanpa verifier khusus"))
        if ok:
            self._set(remedi, "TERVERIFIKASI")
            return self._catat(remedi, "SUKSES_TERVERIFIKASI", catatan)
        self._set(remedi, "VERIFIKASI_GAGAL")
        self._rollback_jika_bisa(remedi, alasan=catatan)
        return self._catat(remedi, "ROLLBACK", catatan)

    def _rollback_jika_bisa(self, remedi, alasan):
        if remedi.checkpoint and self.rollback:
            hasil_rb = self.rollback(remedi.checkpoint)
            self._set(remedi, "ROLLBACK_DIJALANKAN")
            remedi.data["rollback_hasil"] = hasil_rb
        else:
            remedi.data["rollback_hasil"] = (
                "TIDAK TERSEDIA — pulihkan manual sesuai recovery_plan")
        remedi.data["alasan_rollback"] = alasan

    def _catat(self, remedi, hasil, catatan=None):
        remedi.hasil_akhir = {"hasil": hasil, "catatan": catatan,
                              "riwayat": remedi.riwayat}
        self._set(remedi, "DICATAT")
        return remedi.hasil_akhir

    def _set(self, remedi, s):
        remedi._set(s)


def laporan_teks(remedi):
    r = remedi
    baris = [f"REMEDIASI {r.data['temuan_id']}: {r.data['deskripsi']}",
             f"zona={r.data['zona']} state={r.state}"]
    if r.hasil_akhir:
        baris.append(f"hasil={r.hasil_akhir['hasil']} "
                     f"({r.hasil_akhir['catatan']})")
        if r.data.get("alasan_rollback"):
            baris.append(f"alasan_rollback={r.data['alasan_rollback']}")
        baris.append(f"rollback={r.data.get('rollback_hasil')}")
    return "\n".join(baris)


def laporan_json(remedi):
    return json.dumps({"data": remedi.data, "state": remedi.state,
                       "hasil_tes": remedi.hasil_tes,
                       "hasil_akhir": remedi.hasil_akhir,
                       "riwayat": remedi.riwayat},
                      ensure_ascii=False, indent=1, default=str)
