#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_lab.py — v4.0: DEMO LAB 1-PERINTAH (satu proses, TCP loopback NYATA).

MENGAPA FILE INI ADA (jujur):
  Antrean tugas & last_seen SLCControl hidup DI MEMORI proses server.
  Menjadwalkan tugas dari terminal/proses TERPISAH TIDAK PERNAH sampai
  ke agent (proses itu mati membawa antreannya sendiri). Demo end-to-end
  TCP karena itu HARUS berjalan DALAM SATU PROSES — file ini menjalankan
  server, agent, penjadwalan, dan misi sekaligus.

FASE DEMO (urut):
  A. ENROLL + server TCP (socket betulan, 127.0.0.1 port ephemeral)
  B. AGENT loopback: heartbeat → POLL → eksekusi endpoint-side → HASIL
     (3 tugas nyata: kesehatan, disk, cek_app) — transport TCP NYATA.
  C. EMERGENCY STOP: buktikan penolakan penjadwalan saat dibekukan,
     lalu dilepas.
  D. MISI "Inventaris lab terjadwal" via MissionEngine (7 state,
     verifikasi postcondition, laporan teks). Misi dieksekusi
     controller-side (in-process) — DILABELI jujur, bukan lewat socket.

Label data: hasil aksi = telemetri NYATA mesin ini. Tidak ada data
sintetis yang dicampur di sini (mode sintetis ada di slc_demo.py).
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import threading
import time


def tunggu(kondisi, timeout=30.0, jeda=0.1):
    """Poll sampai kondisi True atau timeout (jujur: return bool)."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        if kondisi():
            return True
        time.sleep(jeda)
    return False


def jalankan_lab(direktori=None, host="127.0.0.1", interval=0.2,
                 tampilkan=True):
    from range_registry import DeviceRegistry
    from slc_control import KontrolError, SLCControl
    from slc_endpoint import SLCEndpoint, TransportTCP, layanan_loop
    from slc_mission import Misi, MissionEngine
    from slc_server import jalankan_server

    d = direktori or tempfile.mkdtemp(prefix="slc_lab_")
    out = []

    def cetak(*baris):
        out.extend(baris)
        if tampilkan:
            for b in baris:
                print(b)

    cetak("=" * 62)
    cetak("SLC LAB — demo end-to-end satu proses (TCP loopback NYATA)")
    cetak(f"state sementara: {d}")
    cetak("=" * 62)

    # ---------- FASE A: control + enroll + server TCP ----------
    control = SLCControl(
        registry=DeviceRegistry(path=f"{d}/devices.json",
                                audit_path=f"{d}/audit.jsonl"),
        meta_path=f"{d}/slc_devices.json",
        history_path=f"{d}/slc_history.jsonl",
        audit_path=f"{d}/audit.jsonl",
        events_path=f"{d}/events.jsonl")
    rec = control.enroll("lab-lokal", oleh="admin", grup=["loopback"],
                         tags=["demo-uts"])
    cetak(f"[A] ENROLL OK: {rec['id']} (kunci ditampilkan sekali, "
          f"disimpan 0600 di {d}/devices.json)")
    srv = jalankan_server(control, host=host, port=0)
    port = srv.server_address[1]
    cetak(f"[A] server TCP mendengarkan {host}:{port} (socket NYATA)")

    # ---------- FASE B: agent loopback + tugas endpoint-side ----------
    tr = TransportTCP(host, port, rec["id"], rec["kunci"])
    agent = SLCEndpoint(rec["id"], rec["kunci"], tr,
                        {"interval_heartbeat": interval})
    t_agent = threading.Thread(
        target=layanan_loop, args=(agent, tr, 400), daemon=True)
    t_agent.start()
    if not tunggu(lambda: rec["id"] in control.last_seen, timeout=15):
        cetak("[B] GAGAL: agent tidak pernah heartbeat — cek port/firewall")
        agent.shutdown()
        return {"ok": False, "fase": "B-heartbeat", "log": out}
    cetak(f"[B] agent heartbeat OK (last_seen={control.last_seen[rec['id']]})")

    aksi_b = [("kesehatan", {}), ("disk", {}),
              ("cek_app", {"app": "mirror-demo"})]
    id_tugas = []
    for aksi, params in aksi_b:
        t = control.jadwalkan("admin", rec["id"], aksi, params)
        id_tugas.append((t["tugas_id"], aksi))
    for tid, aksi in id_tugas:
        ok = tunggu(
            lambda tid=tid: any(h.get("tugas_id") == tid and
                                h.get("status") == "SELESAI_TERVERIFIKASI"
                                for h in control.history), timeout=45)
        status = next((h.get("status") for h in control.history
                       if h.get("tugas_id") == tid), "TUNGGU")
        cetak(f"[B] tugas {aksi:<10} -> {status}"
              + ("" if ok else "  (TIMEOUT)"))
    n_ok = sum(1 for tid, _ in id_tugas
               if any(h.get("tugas_id") == tid and
                      h.get("status") == "SELESAI_TERVERIFIKASI"
                      for h in control.history))
    cetak(f"[B] eksekusi endpoint-side via TCP: {n_ok}/{len(id_tugas)} "
          f"SELESAI_TERVERIFIKASI (telemetri NYATA mesin ini)")

    # ---------- FASE C: emergency stop ----------
    control.emergency_stop(rec["id"], oleh="admin")
    try:
        control.jadwalkan("admin", rec["id"], "kesehatan")
        cetak("[C] BUG: penjadwalan seharusnya DITOLAK saat emergency")
    except KontrolError as e:
        cetak(f"[C] emergency stop bekerja: penjadwalan DITOLAK ({e})")
    control.lepas_emergency(rec["id"], oleh="admin")
    cetak("[C] emergency stop dilepas — perangkat aktif kembali")

    # matikan agent sebelum fase misi (antrean misi dikelola engine
    # in-process; agent aktif akan berebut POLL — DIBEKUKAN jujur)
    agent.shutdown()
    tunggu(lambda: agent.berhenti, timeout=5)
    cetak("[C] agent graceful shutdown (BYE terkirim)")

    # ---------- FASE D: misi via MissionEngine ----------
    misi = Misi("Inventaris lab terjadwal (slc_lab)", [
        {"id": "l1", "aksi": "kesehatan", "dev": rec["id"], "params": {}},
        {"id": "l2", "aksi": "disk", "dev": rec["id"], "params": {}},
        {"id": "l3", "aksi": "cek_app", "dev": rec["id"],
         "params": {"app": "mirror-demo"}, "tergantung": ["l2"]},
    ], oleh="operator", persetujuan_kebijakan=True,
        checkpoint_path=f"{d}/misi_checkpoint.json")
    engine = MissionEngine(control)
    engine.jalankan(misi)
    cetak("-" * 62)
    cetak(engine.laporan_teks(misi))
    cetak("[D] catatan jujur: misi dieksekusi controller-side "
          "(in-process); fase B di atas yang lewat socket TCP.")

    integritas = control.sehat_audit()
    cetak("-" * 62)
    cetak(f"[E] integritas audit hash-chain: {'UTUH' if integritas else 'RUSAK'}")
    inv = json.dumps(control.inventaris(), ensure_ascii=False)
    cetak(f"[E] inventaris: {inv}")
    cetak("=" * 62)

    srv.shutdown()
    srv.server_close()
    return {"ok": n_ok == len(id_tugas) and misi.state == "REPORTING"
            and integritas,
            "n_tugas_tcp_ok": n_ok, "misi": misi.ringkas(),
            "integritas_audit": integritas, "log": out}


def main():
    ap = argparse.ArgumentParser(
        description="slc_lab v4.0 — demo lab end-to-end SATU proses "
                    "(server TCP + agent loopback + misi).")
    ap.add_argument("--dir", help="direktori state (default: temp sementara)")
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    hasil = jalankan_lab(direktori=a.dir, host=a.host)
    return 0 if hasil.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
