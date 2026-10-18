#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_redblue.py — v4.0 Sovereign Lab Control: EVALUASI RED/BLUE.

Reproduktif utk demo UTS. Merangkai modul TERUJI yang sudah ada
(TIDAK diduplikasi):
  - redsim.ScenarioRunner  : skenario aman ter-scope (T1046/T1071/T1547/
                             T1078) + cleanup + audit — sisi RED (sintetis).
  - netmon.evaluasi_detektor: precision/recall/FPR terhadap fixture
                             berlabel — sisi BLUE.
  - forensics.EventStore   : jejak bukti.

Menyediakan: definisi skenario + prasyarat, hasil diharapkan vs aktual,
referensi bukti, verifikasi cleanup, matriks coverage deteksi, analisis
FP, dan perbandingan konfigurasi baseline vs improved (jujur: yang tidak
diukur TIDAK diklaim membaik).
"""
from __future__ import annotations

import json
import time


def definisi_evaluasi():
    """Definisi skenario evaluasi RED (semuanya aman/sintetis/ter-scope)."""
    return [
        {"id": "RB-01", "skenario": "Recon port-scan loopback",
         "mitre": "T1046", "sintetis": True,
         "prasyarat": "scope lab berisi host lab; loopback",
         "deteksi_diharapkan": True,
         "sumber_modul": "redsim.SkenarioRecon"},
        {"id": "RB-02", "skenario": "Beacon C2 berkala loopback",
         "mitre": "T1071", "sintetis": True,
         "prasyarat": "interval berkala ke port terpantau",
         "deteksi_diharapkan": True,
         "sumber_modul": "redsim.SkenarioBeacon"},
        {"id": "RB-03", "skenario": "Persistensi startup (sim)",
         "mitre": "T1547.001", "sintetis": True,
         "prasyarat": "detektor stealth/persistensi aktif",
         "deteksi_diharapkan": True,
         "sumber_modul": "redsim.SkenarioPersistensi"},
        {"id": "RB-04", "skenario": "Privilege abuse RBAC (sim)",
         "mitre": "T1078", "sintetis": True,
         "prasyarat": "audit RBAC aktif",
         "deteksi_diharapkan": True,
         "sumber_modul": "redsim.SkenarioPrivilege"},
    ]


def jalankan_red(scope_path="lab_scope.json", events_path="lab_events.jsonl",
                 audit_path="lab_audit.jsonl"):
    """Sisi RED: jalankan skenario aman via ScenarioRunner (modul lama,
    menegakkan scope lab_scope.json sendiri — di luar scope DITOLAK).

    v4.0: redsim.SkenarioPrivilege menulis audit ke konstanta modulnya
    (AUDIT_FILE), bukan ke audit_path runner. Agar SEMUA jejak audit RED
    jatuh ke audit_path yang diberikan (dan tahan bocoran state modul dari
    test/proses lain), AUDIT_FILE dipinjam sementara lalu dipulihkan.
    """
    import redsim
    from redsim import ScenarioRunner
    audit_asli = redsim.AUDIT_FILE
    redsim.AUDIT_FILE = audit_path
    try:
        hasil = ScenarioRunner(scope_path=scope_path, events_path=events_path,
                               audit_path=audit_path).run()
    finally:
        redsim.AUDIT_FILE = audit_asli
    defn = definisi_evaluasi()
    matriks = []
    for d, h in zip(defn, hasil["hasil"]):
        matriks.append({
            "id": d["id"], "mitre": d["mitre"], "skenario": d["skenario"],
            "sintetis": True,
            "diharapkan": d["deteksi_diharapkan"],
            "aktual_terdeteksi": bool(h.get("detected")),
            "cocok": bool(h.get("detected")) == d["deteksi_diharapkan"],
            "cleanup": h.get("cleanup"),
            "evidence_ref": h.get("evidence"),
        })
    return {"matriks": matriks,
            "detection_rate": hasil["detection_rate"],
            "n_run": hasil["n_run"],
            "integritas_audit": hasil["integritas_audit"],
            "catatan_sintetis": "SEMUA skenario RED aman/sintetis/loopback "
                                "— bukan serangan nyata"}


def jalankan_blue():
    """Sisi BLUE: evaluasi detektor netmon (fixture berlabel)."""
    import netmon
    return netmon.evaluasi_detektor()


def analisis_fp(hasil_blue):
    """Analisis false positive dari rincian evaluasi (jujur + saran)."""
    fps = [r for r in hasil_blue.get("rincian", [])
           if r["hasil"] == "FP"]
    fns = [r for r in hasil_blue.get("rincian", [])
           if r["hasil"] == "FN"]
    saran = []
    if fps:
        saran.append(f"naikkan ambang / whitelist utk: "
                     f"{sorted({r['label'] for r in fps})}")
    if fns:
        saran.append(f"FN diakui, perbaiki detektor utk: "
                     f"{sorted({r['label'] for r in fns})}")
    return {"n_fp": len(fps), "fp": fps, "n_fn": len(fns), "fn": fns,
            "saran": saran or ["tidak ada FP pada fixture ini"]}


def bandingkan_konfigurasi(baseline, improved):
    """Perbandingan baseline vs improved (angka diukur, bukan diklaim)."""
    keluar = {}
    for k in ("precision", "recall", "fpr"):
        b, i = baseline.get(k), improved.get(k)
        if b is None or i is None:
            keluar[k] = {"baseline": b, "improved": i,
                         "catatan": "TIDAK_DIUKUR — tidak dinyatakan"}
        else:
            keluar[k] = {"baseline": b, "improved": i, "delta": round(i - b,
                                                                    3)}
    dp = keluar["precision"].get("delta")
    dr = keluar["recall"].get("delta")
    if dp is None and dr is None:
        keluar["verdict"] = "TIDAK_DIKETAHUI — metrik tidak diukur"
    else:
        keluar["verdict"] = "membaik" if (dp is None or dp >= 0) and \
            (dr is None or dr >= 0) else "perlu investigasi"
    return keluar


def laporan_md(red=None, blue=None, fp=None, cmp_cfg=None, ts=None):
    """Laporan evaluasi human-readable (Markdown)."""
    ts = ts or time.strftime("%Y-%m-%d %H:%M:%S")
    b = ["# Evaluasi Red/Blue — WebCam Guard v4.0 (SLC)", "",
         f"_dihasilkan: {ts} — semua skenario RED sintetis/aman_", ""]
    if red:
        b += ["## Matriks RED (skenario sintetis) vs deteksi BLUE", "",
              "| ID | MITRE | Skenario | Diharapkan | Aktual | Cocok | "
              "Cleanup |", "|---|---|---|---|---|---|---|"]
        for m in red["matriks"]:
            b.append(f"| {m['id']} | {m['mitre']} | {m['skenario']} | "
                     f"{m['diharapkan']} | {m['aktual_terdeteksi']} | "
                     f"{'✓' if m['cocok'] else '✗'} | {m['cleanup']} |")
        b += ["", f"detection_rate={red['detection_rate']} "
              f"(n={red['n_run']}, audit utuh={red['integritas_audit']})", ""]
    if blue:
        b += ["## Detektor (fixture berlabel)", "",
              f"precision={blue['precision']} recall={blue['recall']} "
              f"FPR={blue['fpr']} FNR={blue['fnr']}",
              "", "Catatan jujur:"] + [f"- {c}" for c in blue["catatan"]]
    if fp:
        b += ["", "## Analisis False Positive", "",
              f"FP={fp['n_fp']} FN={fp['n_fn']}",
              f"saran: {'; '.join(fp['saran'])}"]
    if cmp_cfg:
        b += ["", "## Baseline vs Improved", "",
              json.dumps(cmp_cfg, indent=1, ensure_ascii=False)]
    return "\n".join(b)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="slc_redblue v4.0")
    ap.add_argument("--tulis", help="tulis laporan md ke path ini")
    a = ap.parse_args()
    red = jalankan_red()
    blue = jalankan_blue()
    fp = analisis_fp(blue)
    teks = laporan_md(red=red, blue=blue, fp=fp)
    if a.tulis:
        with open(a.tulis, "w") as f:
            f.write(teks)
        print(f"laporan ditulis: {a.tulis}")
    else:
        print(teks)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
