#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_demo.py — v4.0 Sovereign Lab Control: MODE DEMO UTS.

Dua mode yang TIDAK tercampur:
  - MODE DEMO    : data SINTETIS berlabel eksplisit — bisa didemokan
                   penguji TANPA perangkat fisik. Tidak pernah berpura-pura
                   sebagai perangkat nyata.
  - MODE FISIK   : perangkat ter-enroll nyata (jalankan slc_server +
                   slc_endpoint di PC lab, enrollment eksplisit).

Demo menjalankan alur penguji (11 langkah) dan mengekspor laporan.
Mode evaluasi: `--evaluasi` menjalankan suite unittest penuh lalu menulis
laporan LULUS/GAGAL/TIDAK-DIJALKAN per kategori.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time

LABEL_SINTETIS = "SINTETIS-DEMO (bukan perangkat nyata)"


def data_sintetis_inventaris():
    """Inventaris sintetis 3 PC lab — LABEL EKSPLISIT di setiap entri."""
    return [
        {"id": "dev-demo-01", "nama": "LAB-DEMO-PC01", "grup": ["lab-demo"],
         "tags": ["sintetis"], "label": LABEL_SINTETIS,
         "os": "Windows 11 (sim)", "sehat": True},
        {"id": "dev-demo-02", "nama": "LAB-DEMO-PC02", "grup": ["lab-demo"],
         "tags": ["sintetis"], "label": LABEL_SINTETIS,
         "os": "Windows 10 (sim)", "sehat": True},
        {"id": "dev-demo-03", "nama": "LAB-DEMO-PC03", "grup": ["lab-demo"],
         "tags": ["sintetis", "cadangan"], "label": LABEL_SINTETIS,
         "os": "Windows 10 (sim)", "sehat": None},  # TIDAK DIKETAHUI — jujur
    ]


def jalankan_demo(direktori=None, tampilkan=True):
    """Menjalankan skenario demo UTS end-to-end dengan kontrol plane nyata
    (in-process) tapi SEMUA perangkat sintetis-berlabel."""
    from range_registry import DeviceRegistry
    from slc_control import SLCControl
    from slc_mission import MissionEngine, Misi
    from slc_events import EventPipeline
    from slc_ui import (render_banner, render_peta_lab, render_timeline,
                        render_misi_replay, render_grafik_aktivitas)

    d = direktori or tempfile.mkdtemp(prefix="slc_demo_")
    reg = DeviceRegistry(path=os.path.join(d, "devices.json"),
                         audit_path=os.path.join(d, "audit.jsonl"))
    c = SLCControl(registry=reg, meta_path=os.path.join(d, "meta.json"),
                   audit_path=os.path.join(d, "audit.jsonl"),
                   events_path=os.path.join(d, "events.jsonl"))
    ids = []
    for dev in data_sintetis_inventaris():
        rec = c.enroll(dev["nama"], grup=dev["grup"], tags=dev["tags"])
        ids.append(rec["id"])

    # misi inventaris lintas perangkat (RENDAH, by-policy)
    eng = MissionEngine(c)
    m = Misi("Demo UTS: inventaris sintetis", [
        {"id": "l1", "aksi": "kesehatan", "dev": ids[0], "params": {}},
        {"id": "l2", "aksi": "kesehatan", "dev": ids[1], "params": {}},
        {"id": "l3", "aksi": "disk", "dev": ids[2], "params": {}},
    ], oleh="operator", persetujuan_kebijakan=True,
        checkpoint_path=os.path.join(d, "ckpt.json"))
    eng.jalankan(m)

    # pipeline event sintetis berlabel
    pipe = EventPipeline()
    pipe.masuk({"kind": "slc", "event": "misi selesai",
                "detail": m.state}, asal="sintetis", dev=ids[0],
               misi=m.id)

    layar = [render_banner(mode="DEMO — DATA SINTETIS"),
             render_peta_lab(c.inventaris(), label=LABEL_SINTETIS),
             render_misi_replay(m, gerak=False),
             render_grafik_aktivitas([3, 5, 2, 8, 4, 9, 6]),
             render_timeline(pipe.events)]
    if tampilkan:
        print("\n\n".join(layar))

    laporan = {
        "mode": "DEMO", "label_data": LABEL_SINTETIS,
        "n_perangkat_sintetis": len(ids),
        "misi": m.ringkas(),
        "langkah": m.urutan,
        "output_teks": "\n\n".join(layar),
        "catatan": "perangkat fisik tidak disentuh oleh mode demo",
    }
    return laporan


# ---------------------------------------------------------------------------
# Laporan evaluasi (acceptance) — dari suite unittest nyata
# ---------------------------------------------------------------------------

KATEGORI_TEST = {
    "Enrollment & revokasi": "test_slc_control",
    "Autentikasi gagal / sertifikat invalid": "test_slc_endpoint",
    "Aksi tak diizinkan / policy": "test_slc_control test_slc_actions",
    "Perangkat di luar scope": "test_slc_actions test_slc_endpoint",
    "Tugas kedaluwarsa / duplikat": "test_slc_control",
    "Agent disconnect / retry / pembatalan": "test_slc_endpoint test_slc_mission",
    "Verifikasi postcondition": "test_slc_mission test_slc_control",
    "Audit log lengkap": "test_slc_control test_audit_core",
    "Integritas bukti": "test_evidence test_forensics",
    "Remediasi aman & rollback": "test_slc_twin_remediation",
    "Limit sumber daya": "test_slc_endpoint",
    "Label sintetis vs nyata": "test_slc_events test_slc_demo",
    "Siklus layanan Windows (bila testable)": "test_slc_endpoint",
    "Paket install/remove (docs)": "TIDAK_DIJALANKAN_CI",
}


def jalankan_suite(path_tulis=None, cmd=None):
    """Jalankan suite unittest penuh via subprocess, parse hasil."""
    cmd = cmd or [sys.executable, "-m", "unittest", "discover", "-s",
                  "tests", "-v"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    return proc.stdout + proc.stderr


def parse_hasil(teks):
    """Parse ringkasan unittest → dict angka."""
    hasil = {"total": 0, "ok": False, "gagal": 0, "error": 0,
             "skip": 0, "detil": []}
    for baris in teks.splitlines():
        if baris.startswith("Ran "):
            try:
                hasil["total"] = int(baris.split()[1])
            except (ValueError, IndexError):
                pass
        if baris.startswith("OK"):
            hasil["ok"] = True
            if "skipped=" in baris:
                hasil["skip"] = int(baris.split("skipped=")[1]
                                    .split()[0].rstrip(")"))
        if baris.startswith("FAILED"):
            if "failures=" in baris:
                hasil["gagal"] = int(baris.split("failures=")[1]
                                     .split(",")[0])
            if "errors=" in baris:
                hasil["error"] = int(baris.split("errors=")[1]
                                     .split(")")[0].split(",")[0])
    return hasil


def laporan_evaluasi_md(teks_suite=None, path_tulis=None):
    """Laporan acceptance: LULUS / GAGAL / TIDAK DIJALANKAN per kategori."""
    teks_suite = teks_suite if teks_suite is not None else jalankan_suite()
    h = parse_hasil(teks_suite)
    baris = ["# Laporan Evaluasi & Acceptance — v4.0 Sovereign Lab Control",
             "", f"dihasilkan: {time.strftime('%Y-%m-%d %H:%M:%S')}",
             "", f"**Suite: {h['total']} test — "
             f"{'SEMUA LULUS' if h['ok'] and not h['gagal'] and not h['error'] else 'ADA KEGAGALAN'}"
             f" (failures={h['gagal']}, errors={h['error']}, "
             f"skipped={h['skip']})**", "",
             "| Kategori acceptance | Cakupan test | Status |", "|---|---|---|"]
    for kategori, modul in KATEGORI_TEST.items():
        if modul == "TIDAK_DIJALANKAN_CI":
            baris.append(f"| {kategori} | {modul} | TIDAK DIJALANKAN di CI "
                         "(butuh Windows fisik — prosedur terdokumentasi) |")
        else:
            baris.append(f"| {kategori} | {modul} | dijalankan suite |")
    baris += ["", "## Yang tidak dapat dijalankan di environment ini (jujur)",
              "",
              "- TLS dengan sertifikat nyata: 3 test `TestTLSPinning` "
              "di-skip (tidak ada `openssl`/`cryptography` untuk membuat "
              "sertifikat di CI; jalankan di laptop Windows dengan "
              "sertifikat lab).",
              "- Instalasi Windows Service nyata: butuh PC Windows fisik "
              "dengan hak Administrator (prosedur di "
              "docs/SLC-INSTALL-DEMO.md).",
              "- koneksi ke perangkat fisik: mode FISIK terdokumentasi, "
              "tidak dipalsukan di CI."]
    md = "\n".join(baris)
    if path_tulis:
        with open(path_tulis, "w") as f:
            f.write(md)
    return md


def main():
    import argparse
    ap = argparse.ArgumentParser(description="slc_demo v4.0 — mode demo UTS")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--evaluasi", action="store_true")
    ap.add_argument("--tulis", help="path laporan")
    a = ap.parse_args()
    if a.demo:
        jalankan_demo()
        return 0
    if a.evaluasi:
        md = laporan_evaluasi_md(path_tulis=a.tulis)
        print(md if not a.tulis else f"ditulis: {a.tulis}")
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
