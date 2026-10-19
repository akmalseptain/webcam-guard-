#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_control.py — v4.0 Sovereign Lab Control: CONTROL PLANE (logika murni).

Komposisi di atas fondasi teruji v3.0 (TIDAK diduplikasi):
  - range_registry.DeviceRegistry : identitas + enrollment + HMAC + nonce
  - range_controller.OperatorStore: autentikasi operator (PBKDF2 + limiter)
  - audit_core.AuditLog           : audit hash-chain
  - forensics.EventStore          : event terverifikasi

Fitur control plane:
  - grup, tag, peran, policy per-perangkat (allowlist aksi + paralel maks)
  - penjadwalan tugas per-perangkat dengan: idempotensi (anti duplikat),
    masa kedaluwarsa, persetujuan eksplisit utk aksi risiko TINGGI
  - verifikasi postcondition hasil eksekusi (bukan sekadar exit 0)
  - last_seen, history, emergency stop per-perangkat, pembatalan operator
  - audit untuk SETIAP operasi administratif
  - detail_perangkat() = halaman detail (kesehatan, aksi diizinkan,
    aktivitas terbaru, tugas tertunda, peringatan)
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time

import audit_core
import forensics
from range_registry import DeviceRegistry, now_ts

import slc_actions

PERAN_OPERATOR = ("admin", "operator", "auditor")


class KontrolError(Exception):
    """Penolakan control plane (policy/persetujuan/scope)."""


class PersetujuanError(KontrolError):
    pass


class SLCControl:
    """Otak centralized lab control (pure — testable tanpa socket)."""

    def __init__(self, registry=None, operators=None, meta_path="slc_devices.json",
                 history_path="slc_history.jsonl", audit_path="lab_audit.jsonl",
                 events_path="lab_events.jsonl"):
        self.registry = registry or DeviceRegistry(path="devices.json")
        self.operators = operators
        self.meta_path = meta_path
        self.audit = audit_core.AuditLog(audit_path)
        self.events = forensics.EventStore(events_path)
        self._meta = self._muat(meta_path)
        # antrean: dev_id -> list tugas ; history: list ringkas
        self._antrean = {}
        self._idempotensi = {}   # key -> tugas_id
        self._persetujuan = {}   # tugas_id -> {"oleh", "ts"}
        self.history = []
        self.last_seen = {}
        self._emergency = set()  # dev_id yang di-emergency-stop
        self._dibatalkan = set()  # tugas_id yang dibatalkan operator
        # v4.0.3: kunci antrean/thread-safety — gelombang misi paralel
        # memutasi _antrean/history dari >1 thread (di Windows race ini
        # menyebabkan cross-steal tugas antar langkah).
        self._kunci = threading.RLock()

    # ---------------- meta (grup/tag/policy) ----------------
    def _muat(self, path):
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    def _simpan_meta(self):
        tmp = self.meta_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._meta, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.meta_path)
        try:
            os.chmod(self.meta_path, 0o600)
        except OSError:
            pass

    def enroll(self, nama, oleh="admin", grup=None, tags=None, policy=None):
        """Enroll perangkat BARU + metadata SLC (grup/tag/policy)."""
        rec = self.registry.enroll(nama, aktor=oleh)
        self._meta[rec["id"]] = {"nama": nama, "grup": grup or [],
                                 "tags": tags or [],
                                 "policy": policy or {"maks_paralel": 1},
                                 "dibuat": now_ts()}
        self._simpan_meta()
        self.audit.append(oleh, "SLC_ENROLL",
                          f"{rec['id']} grup={grup} tags={tags}")
        return rec

    def revoke(self, dev_id, oleh="admin"):
        rec = self.registry.revoke(dev_id, aktor=oleh)
        self._emergency.discard(dev_id)
        self.audit.append(oleh, "SLC_REVOKE", dev_id)
        return rec

    def set_meta(self, dev_id, oleh="admin", **ubah):
        self._cek_dev(dev_id)
        m = self._meta.setdefault(dev_id, {})
        m.update(ubah)
        self._simpan_meta()
        self.audit.append(oleh, "SLC_SET_META", f"{dev_id} {sorted(ubah)}")

    def _cek_dev(self, dev_id):
        rec = self.registry.cek_enrolled(dev_id)
        if rec is None:
            raise KeyError(f"perangkat tidak ter-enroll/aktif: {dev_id}")
        return rec

    # ---------------- policy ----------------
    def aksi_diizinkan_dev(self, dev_id, aksi):
        pol = (self._meta.get(dev_id) or {}).get("policy") or {}
        allow = pol.get("aksi_diizinkan")
        if allow is not None and aksi not in allow:
            return False
        return True

    # ---------------- penjadwalan ----------------
    def jadwalkan(self, oleh_role, dev_id, aksi, params=None,
                  idem=None, kedaluwarsa_s=300.0, persetujuan_id=None,
                  sekarang=None):
        """Jadwalkan aksi terdaftar ke perangkat. Pengecekan berlapis:
        role→aksi, scope perangkat, policy perangkat, emergency stop,
        idempotensi, persetujuan risiko TINGGI."""
        sekarang = time.time() if sekarang is None else sekarang
        d = slc_actions.definisi(aksi)          # raises AksiError bila tak dikenal
        slc_actions.validasi(aksi, params)
        if oleh_role not in d["izin"]:
            self.audit.append(oleh_role, "SLC_JADWAL_DITOLAK",
                              f"role {oleh_role} → {aksi}")
            raise PermissionError(f"role '{oleh_role}' tidak diizinkan utk {aksi}")
        if oleh_role not in PERAN_OPERATOR:
            raise KontrolError(f"peran tidak dikenal: {oleh_role}")
        self._cek_dev(dev_id)
        if dev_id in self._emergency:
            self.audit.append(oleh_role, "SLC_JADWAL_DITOLAK",
                              f"emergency stop aktif: {dev_id}")
            raise KontrolError("perangkat dalam emergency stop")
        if not self.aksi_diizinkan_dev(dev_id, aksi):
            self.audit.append(oleh_role, "SLC_JADWAL_DITOLAK",
                              f"policy perangkat melarang {aksi} di {dev_id}")
            raise KontrolError("policy perangkat melarang aksi ini")
        if idem and idem in self._idempotensi:
            lama = self._cari_tugas(self._idempotensi[idem])
            if lama is not None and lama["status"] not in ("SELESAI", "GAGAL"):
                self.audit.append(oleh_role, "SLC_DUPLIKAT_DITOLAK",
                                  f"idempotensi={idem}")
                return lama  # anti eksekusi ganda
        tugas = {"tugas_id": "t-" + secrets.token_hex(5), "aksi": aksi,
                 "params": params or {}, "dev_id": dev_id,
                 "oleh": oleh_role, "dibuat": sekarang,
                 "kedaluwarsa": sekarang + kedaluwarsa_s,
                 "status": "MENUNGGU_PERSETUJUAN" if
                 (d["risiko"] == "TINGGI" and persetujuan_id is None)
                 else "SIAP"}
        if d["risiko"] == "TINGGI" and persetujuan_id is not None:
            tugas["disetujui_oleh"] = persetujuan_id
            tugas["status"] = "SIAP"
        self._antrean.setdefault(dev_id, []).append(tugas)
        if idem:
            self._idempotensi[idem] = tugas["tugas_id"]
        self.audit.append(oleh_role, "SLC_TUGAS_DIJADWALKAN",
                          f"{tugas['tugas_id']} {aksi} -> {dev_id} "
                          f"[{tugas['status']}]")
        return tugas

    def setujui(self, tugas_id, oleh_admin="admin"):
        """Persetujuan eksplisit aksi TINGGI — hanya admin."""
        if oleh_admin != "admin":
            raise PermissionError("hanya admin dapat menyetujui")
        t = self._cari_tugas(tugas_id)
        if t is None:
            raise KeyError(f"tugas tidak ditemukan: {tugas_id}")
        if t["status"] != "MENUNGGU_PERSETUJUAN":
            raise PersetujuanError(f"status tidak meminta persetujuan: {t['status']}")
        t["status"] = "SIAP"
        t["disetujui_oleh"] = oleh_admin
        t["disetujui_ts"] = now_ts()
        self._persetujuan[tugas_id] = {"oleh": oleh_admin, "ts": now_ts()}
        self.audit.append(oleh_admin, "SLC_PERSETUJUAN", tugas_id)
        return t

    def _cari_tugas(self, tugas_id):
        for q in self._antrean.values():
            for t in q:
                if t["tugas_id"] == tugas_id:
                    return t
        for t in self.history:
            if t["tugas_id"] == tugas_id:
                return t
        return None

    def berikutnya(self, dev_id, sekarang=None):
        """POLL perangkat: ambil tugas SIAP berikutnya; tugas kedaluwarsa
        dibuang jujur dengan status KEDALUWARSA."""
        sekarang = time.time() if sekarang is None else sekarang
        with self._kunci:
            self.last_seen[dev_id] = now_ts()
            q = self._antrean.get(dev_id, [])
            while q:
                t = q[0]
                if t["status"] == "MENUNGGU_PERSETUJUAN":
                    return None  # jangan bocorkan tugas yang belum disetujui
                if t["status"] == "SIAP" and sekarang > t["kedaluwarsa"]:
                    q.pop(0)
                    t["status"] = "KEDALUWARSA"
                    self.history.append(t)
                    self.audit.append("controller", "SLC_TUGAS_KEDALUWARSA",
                                      t["tugas_id"])
                    continue
                if t["status"] == "SIAP" and t["tugas_id"] in self._dibatalkan:
                    q.pop(0)
                    t["status"] = "DIBATALKAN"
                    self.history.append(t)
                    continue
                if t["status"] == "SIAP":
                    t["status"] = "DIKIRIM"
                    return t
                q.pop(0)  # status aneh → buang jujur
            return None

    def kirim_tugas(self, dev_id, tugas_id, sekarang=None):
        """v4.0.3: tandai TUGAS SPESIFIK sebagai DIKIRIM (thread-safe).

        Untuk mission engine gelombang PARALEL: berikutnya() mengambil
        tugas SIAP *pertama* pada dev yang sama, sehingga dua langkah
        paralel saling mencuri tugas (cross-steal) lalu membuangnya di
        branch 'status aneh'. kirim_tugas() hanya menyentuh tugas milik
        langkahnya sendiri. Return tugas, atau None bila tidak siap /
        kedaluwarsa / dibatalkan (pemanggil melaporkan jujur)."""
        sekarang = time.time() if sekarang is None else sekarang
        with self._kunci:
            for q_i, q in enumerate(self._antrean.values()):
                for idx, t in enumerate(q):
                    if t["tugas_id"] != tugas_id:
                        continue
                    if t["status"] == "MENUNGGU_PERSETUJUAN":
                        return None
                    if sekarang > t["kedaluwarsa"]:
                        q.pop(idx)
                        t["status"] = "KEDALUWARSA"
                        self.history.append(t)
                        self.audit.append("controller",
                                          "SLC_TUGAS_KEDALUWARSA", tugas_id)
                        return None
                    if t["tugas_id"] in self._dibatalkan:
                        q.pop(idx)
                        t["status"] = "DIBATALKAN"
                        self.history.append(t)
                        return None
                    if t["status"] == "SIAP":
                        t["status"] = "DIKIRIM"
                    return t
            return None

    def terima_hasil(self, dev_id, tugas_id, hasil, sekarang=None):
        """Terima HASIL dari perangkat: verifikasi postcondition NYATA,
        bukan sekadar 'eksekusi selesai'."""
        with self._kunci:  # v4.0.3: pop antrean + history thread-safe
            self.last_seen[dev_id] = now_ts()
            t = None
            for q in self._antrean.values():
                for i, tt in enumerate(q):
                    if tt["tugas_id"] == tugas_id:
                        t = q.pop(i)
                        break
            if t is None:
                t = self._cari_tugas(tugas_id)
                if t is None:
                    raise KeyError(f"tugas tidak dikenal: {tugas_id}")
        gagal = bool((hasil or {}).get("error"))
        t["selesai"] = now_ts()
        if gagal:
            t["status"] = "GAGAL"
            t["hasil"] = {"error": hasil["error"]}
        else:
            verif = slc_actions.definisi(t["aksi"])["verifikasi"]
            ok, catatan = (True, "tanpa verifikasi khusus") if verif is None \
                else verif((hasil or {}).get("data", hasil), t["params"])
            t["status"] = "SELESAI_TERVERIFIKASI" if ok else "GAGAL_VERIFIKASI"
            t["verifikasi"] = catatan
            t["hasil"] = hasil
        self.history.append(t)
        self.audit.append("controller", "SLC_TUGAS_SELESAI",
                          f"{tugas_id} {t['status']}")
        event = forensics.normalize(
            "slc", f"tugas {t['aksi']} di {dev_id}",
            f"status={t['status']}", host=dev_id)
        self.events.append(event)
        return t

    # ---------------- kontrol administratif ----------------
    def emergency_stop(self, dev_id, oleh="admin"):
        """Device-level emergency stop: antrean dikosongkan + perangkat
        dibekukan sampai dilepas eksplisit."""
        self._cek_dev(dev_id)
        for t in self._antrean.get(dev_id, []):
            t["status"] = "DIBATALKAN"
            self.history.append(t)
        self._antrean[dev_id] = []
        self._emergency.add(dev_id)
        self.audit.append(oleh, "SLC_EMERGENCY_STOP", dev_id)
        event = forensics.normalize("slc", "emergency stop", f"dev={dev_id}",
                                   host=dev_id)
        self.events.append(event)

    def lepas_emergency(self, dev_id, oleh="admin"):
        self._emergency.discard(dev_id)
        self.audit.append(oleh, "SLC_EMERGENCY_LEPAS", dev_id)

    def batalkan(self, tugas_id, oleh="admin"):
        """Operator-level mission/task cancellation."""
        t = self._cari_tugas(tugas_id)
        if t is None:
            raise KeyError(tugas_id)
        if t["status"] in ("SELESAI_TERVERIFIKASI", "GAGAL", "GAGAL_VERIFIKASI"):
            raise KontrolError("tugas sudah selesai — tidak bisa dibatalkan")
        self._dibatalkan.add(tugas_id)
        t["dibatalkan_oleh"] = oleh
        self.audit.append(oleh, "SLC_BATALKAN", tugas_id)
        return t

    # ---------------- inventaris & detail ----------------
    def inventaris(self, filter_grup=None, filter_tag=None, teks=None):
        """Inventaris searchable (grup/tag/teks)."""
        keluar = []
        for dev_id, m in self._meta.items():
            if filter_grup and filter_grup not in m.get("grup", []):
                continue
            if filter_tag and filter_tag not in m.get("tags", []):
                continue
            if teks and teks.lower() not in (m.get("nama", "").lower()
                                             + " " + dev_id.lower()):
                continue
            keluar.append({
                "id": dev_id, "nama": m.get("nama"),
                "grup": m.get("grup", []), "tags": m.get("tags", []),
                "last_seen": self.last_seen.get(dev_id),
                "emergency": dev_id in self._emergency,
                "tertunda": len(self._antrean.get(dev_id, [])),
            })
        return keluar

    def detail_perangkat(self, dev_id):
        """Halaman detail perangkat: kesehatan, aksi diizinkan,
        aktivitas terbaru, tugas tertunda, peringatan."""
        rec = self._cek_dev(dev_id)
        m = self._meta.get(dev_id, {})
        aktifitas = [t for t in self.history if t.get("dev_id") == dev_id][-10:]
        tertunda = [t for t in self._antrean.get(dev_id, [])
                    if t["status"] in ("SIAP", "MENUNGGU_PERSETUJUAN")]
        peringatan = []
        if dev_id in self._emergency:
            peringatan.append("EMERGENCY STOP aktif")
        ls = self.last_seen.get(dev_id)
        if ls is None:
            peringatan.append("belum pernah terhubung (last_seen TIDAK ADA — "
                              "bukan berarti sehat)")
        aksi_ok = [a for a in slc_actions.aksi_definisi()
                   if self.aksi_diizinkan_dev(dev_id, a)]
        return {"id": dev_id, "nama": rec.get("nama"), "grup": m.get("grup"),
                "tags": m.get("tags"), "last_seen": ls,
                "emergency": dev_id in self._emergency,
                "aksi_diizinkan": aksi_ok, "aktivitas": aktifitas,
                "tugas_tertunda": tertunda, "peringatan": peringatan,
                "policy": m.get("policy")}

    def pesan_device(self, msg, ip="127.0.0.1"):
        """Entrypoint pesan wire dari slc_server (delegasi)."""
        from slc_server import pesan_device
        return pesan_device(self, msg, ip)

    def sehat_audit(self):
        return self.audit.verify() is None


def main():
    import argparse
    ap = argparse.ArgumentParser(description="slc_control v4.0 CLI ringkas")
    ap.add_argument("--inventaris", action="store_true")
    a = ap.parse_args()
    if a.inventaris:
        c = SLCControl()
        for d in c.inventaris():
            print(d)
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
