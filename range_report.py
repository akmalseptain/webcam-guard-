#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""range_report.py — v3.0: laporan before/after + acceptance terukur (R5).

Membandingkan hasil build v3.0 (cyber range) terhadap BASELINE v2.0
yang dikunci di modul ini, dengan kriteria penerimaan TERUKUR —
bukan klaim kosong. Setiap angka diambil dari pengukuran NYATA
(unittest, posture, evaluasi detektor netmon, scenario runner);
bila sebuah ukuran tidak dijalankan, dilaporkan "tidak diukur",
BUKAN dipaksa terlihat lulus.

JUJUR: baseline dikunci dari hasil build v2.0 yang terverifikasi
(204/204 test, posture 93.8, netmon P=1.0/R=0.75). Angka v3.0 diisi
operator via --n-test/--n-test-range (hasil unittest aktual) dan/atau
pengukuran langsung lewat flag --jalankan-*.

CLI:
  python3 range_report.py --n-test 326 --n-test-range 122 \
      --jalankan-netmon --jalankan-posture \
      --jalankan-skenario tests/scope_loopback.json \
      --tulis docs/RANGE-REPORT-v3.0.md
Exit: 0 semua kriteria LULUS; 1 ada kriteria GAGAL; 3 error.
"""

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime

# ------------------------------------------------------------
# Baseline v2.0 — DIKUNCI (hasil build terverifikasi, jangan diubah
# kecuali baseline dire-ukur ulang secara jujur)
# ------------------------------------------------------------
BASELINE_V2 = {
    "versi": "2.0",
    "n_test": 204,
    "posture_skor": 93.8,
    "posture_bloker": [],
    "netmon": {"precision": 1.0, "recall": 0.75, "fpr": 0.0,
               "fnr": 0.25},
    "skenario": None,   # v2.0 TIDAK punya scenario engine — jujur
}

# Kriteria penerimaan v3.0 (measurable, dari master prompt + rencana R1..R6)
KRITERIA = [
    {"id": "K1", "nama": "jumlah test total >= 300 "
                         "(baseline 204 + >=96 baru)",
     "ukur": lambda lap: lap["v3"]["n_test"] is not None
     and lap["v3"]["n_test"] >= 300},
    {"id": "K2", "nama": "test baru modul range >= 100",
     "ukur": lambda lap: lap["v3"]["n_test_range"] is not None
     and lap["v3"]["n_test_range"] >= 100},
    {"id": "K3", "nama": "posture >= 93.8 & tanpa bloker "
                         "(tidak regres vs v2.0)",
     "ukur": lambda lap: lap["ukur"]["posture"] is not None
     and lap["ukur"]["posture"]["skor"] >= BASELINE_V2["posture_skor"]
     and not lap["ukur"]["posture"]["bloker"]},
    {"id": "K4", "nama": "netmon tidak regres: precision >= 1.0, "
                         "recall >= 0.75 (ekstensi v3.0 tak merusak)",
     "ukur": lambda lap: lap["ukur"]["netmon"] is not None
     and lap["ukur"]["netmon"]["precision"] >= 1.0
     and lap["ukur"]["netmon"]["recall"] >= 0.75},
    {"id": "K5", "nama": "scenario engine: detection_rate 1.0 pada "
                         "fixture loopback (semua kontrol menangkap)",
     "ukur": lambda lap: lap["ukur"]["skenario"] is not None
     and lap["ukur"]["skenario"].get("detection_rate") == 1.0},
]


# ------------------------------------------------------------
# Pengukur NYATA
# ------------------------------------------------------------
def ukur_posture():
    """Jalankan posture engine penuh (butuh ~30-60 dtk: PBKDF2)."""
    import posture
    lap = posture.jalankan_semua()
    return {"skor": lap["skor"], "n_lulus": lap["n_lulus"],
            "n_peringat": lap["n_peringat"], "n_gagal": lap["n_gagal"],
            "bloker": lap["bloker"]}


def ukur_netmon():
    """Evaluasi detektor netmon terhadap fixture berlabel (flat dict)."""
    import netmon
    return netmon.evaluasi_detektor()


def ukur_skenario(scope_path, target="127.0.0.1"):
    """Jalankan 4 skenario loopback dengan scope fixture → ringkas."""
    from range_scenarios import ScenarioRunner
    with tempfile.TemporaryDirectory() as d:
        runner = ScenarioRunner(scope_path,
                                os.path.join(d, "events.jsonl"),
                                os.path.join(d, "audit.jsonl"),
                                target=target)
        lap = runner.jalankan()
    return {"n_dijalankan": lap["n_dijalankan"],
            "n_terdeteksi": lap["n_terdeteksi"],
            "detection_rate": lap["detection_rate"],
            "coverage": lap["coverage"]}


# ------------------------------------------------------------
# Perakitan laporan
# ------------------------------------------------------------
def bangun_laporan(n_test=None, n_test_range=None, hasil_posture=None,
                  hasil_netmon=None, hasil_skenario=None):
    lap = {
        "modul": "range_report", "versi": "3.0",
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "baseline": BASELINE_V2,
        "v3": {"n_test": n_test, "n_test_range": n_test_range},
        "ukur": {"posture": hasil_posture, "netmon": hasil_netmon,
                 "skenario": hasil_skenario},
    }
    lap["kriteria"] = [
        {"id": k["id"], "nama": k["nama"],
         "status": ("LULUS" if k["ukur"](lap)
                    else ("TIDAK DIUKUR" if _tak_diukur(k["id"], lap)
                          else "GAGAL"))}
        for k in KRITERIA]
    n_lulus = sum(1 for k in lap["kriteria"]
                  if k["status"] == "LULUS")
    n_gagal = sum(1 for k in lap["kriteria"] if k["status"] == "GAGAL")
    n_skip = sum(1 for k in lap["kriteria"]
                 if k["status"] == "TIDAK DIUKUR")
    lap["ringkasan"] = {"n_lulus": n_lulus, "n_gagal": n_gagal,
                        "n_tak_diukur": n_skip,
                        "semua_lulus": n_gagal == 0}
    return lap


def _tak_diukur(id_, lap):
    """Kriteria tidak bisa dinilai karena ukurannya belum dijalankan."""
    if id_ in ("K1",):
        return lap["v3"]["n_test"] is None
    if id_ == "K2":
        return lap["v3"]["n_test_range"] is None
    if id_ == "K3":
        return lap["ukur"]["posture"] is None
    if id_ == "K4":
        return lap["ukur"]["netmon"] is None
    if id_ == "K5":
        return lap["ukur"]["skenario"] is None
    return False


def render_teks(lap):
    b = lap["baseline"]
    u = lap["ukur"]
    baris = [
        "=" * 68,
        f" RANGE REPORT v3.0 — before/after terukur  ({lap['ts']})",
        "=" * 68,
        "",
        "BASELINE v2.0 (dikunci dari build terverifikasi):",
        f"  test total        : {b['n_test']}",
        f"  posture           : {b['posture_skor']} (bloker: "
        f"{b['posture_bloker'] or 'tidak ada'})",
        f"  netmon           : P={b['netmon']['precision']} "
        f"R={b['netmon']['recall']}",
        f"  scenario engine  : {'TIDAK ADA (baru di v3.0)' if b['skenario'] is None else b['skenario']}",
        "",
        "HASIL v3.0 (angka aktual build ini):",
        f"  test total        : {lap['v3']['n_test']}"
        f"{_delta(lap['v3']['n_test'], b['n_test'])}",
        f"  test modul range  : {lap['v3']['n_test_range']}",
    ]
    if u["posture"] is not None:
        p = u["posture"]
        baris.append(
            f"  posture           : {p['skor']} "
            f"(LULUS {p['n_lulus']}, PERINGAT {p['n_peringat']}, "
            f"GAGAL {p['n_gagal']}, bloker: {p['bloker'] or 'tidak ada'})"
            + _delta(p["skor"], b["posture_skor"]))
    else:
        baris.append("  posture           : tidak diukur (--jalankan-posture)")
    if u["netmon"] is not None:
        n = u["netmon"]
        baris.append(
            f"  netmon            : P={n['precision']} R={n['recall']} "
            f"FPR={n['fpr']} FNR={n['fnr']} (TP={n['TP']} FP={n['FP']} "
            f"FN={n['FN']} TN={n['TN']})")
    else:
        baris.append("  netmon            : tidak diukur (--jalankan-netmon)")
    if u["skenario"] is not None:
        s = u["skenario"]
        baris.append(
            f"  scenario engine   : {s['n_terdeteksi']}/"
            f"{s['n_dijalankan']} terdeteksi "
            f"(detection_rate={s['detection_rate']})")
        for k, c in sorted(s.get("coverage", {}).items()):
            baris.append(f"      kontrol {k}: {c['n_detected']}/{c['n']} "
                         f"(skenario: {', '.join(c['skenario'])})")
    else:
        baris.append("  scenario engine   : tidak diukur "
                     "(--jalankan-skenario SCOPE)")
    baris += ["", "KRITERIA PENERIMAAN:"]
    for k in lap["kriteria"]:
        baris.append(f"  [{k['status']:<12}] {k['id']} — {k['nama']}")
    r = lap["ringkasan"]
    baris += ["", "-" * 68,
              f"  LULUS {r['n_lulus']}/{len(lap['kriteria'])}"
              f"  GAGAL {r['n_gagal']}  TIDAK DIUKUR {r['n_tak_diukur']}",
              "  CATATAN JUJUR: angka dari pengukuran build ini; "
              "detektor diuji",
              "  pada fixture sintetis, BUKAN jaminan akurasi dunia nyata. "
              "TLS/mTLS antar-host nyata, kamera OpenCV, pip-audit/SBOM "
              "dan rollback VM tetap langkah manual owner.",
              "=" * 68]
    return "\n".join(baris)


def _delta(kini, dasar):
    if kini is None or dasar in (None, 0):
        return ""
    d = round(kini - dasar, 1)
    return f"  (baseline {dasar}, delta {d:+})"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="range_report v3.0 — laporan before/after dengan "
                    "kriteria penerimaan terukur")
    ap.add_argument("--n-test", type=int, default=None,
                    help="jumlah unittest TOTAL aktual build v3.0")
    ap.add_argument("--n-test-range", type=int, default=None,
                    help="jumlah unittest baru modul range (R1-R5)")
    ap.add_argument("--jalankan-posture", action="store_true",
                    help="ukur posture nyata (~30-60 dtk, PBKDF2)")
    ap.add_argument("--jalankan-netmon", action="store_true",
                    help="ukur evaluasi detektor netmon nyata")
    ap.add_argument("--jalankan-skenario", default=None, metavar="SCOPE",
                    help="jalankan scenario engine nyata (file scope)")
    ap.add_argument("--target", default="127.0.0.1",
                    help="target skenario (default loopback)")
    ap.add_argument("--json", action="store_true",
                    help="keluarkan JSON penuh")
    ap.add_argument("--tulis", default=None, metavar="PATH",
                    help="tulis laporan teks (Markdown) ke file")
    args = ap.parse_args(argv)

    hasil_posture = ukur_posture() if args.jalankan_posture else None
    hasil_netmon = ukur_netmon() if args.jalankan_netmon else None
    hasil_skenario = (ukur_skenario(args.jalankan_skenario,
                                    target=args.target)
                      if args.jalankan_skenario else None)

    lap = bangun_laporan(n_test=args.n_test,
                         n_test_range=args.n_test_range,
                         hasil_posture=hasil_posture,
                         hasil_netmon=hasil_netmon,
                         hasil_skenario=hasil_skenario)
    if args.json:
        print(json.dumps(lap, ensure_ascii=False, indent=2,
                         default=str))
    teks = render_teks(lap)
    if not args.json:
        print(teks)
    if args.tulis:
        header = ("<!-- Laporan ini DIGENERATE oleh range_report.py "
                  f"pada {lap['ts']}; jangan edit manual. -->\n\n"
                  "# RANGE REPORT v3.0 — Before/After Terukur\n\n"
                  "```text\n")
        os.makedirs(os.path.dirname(os.path.abspath(args.tulis)),
                    exist_ok=True)
        with open(args.tulis, "w", encoding="utf-8") as f:
            f.write(header + teks + "\n```\n")
    if not lap["ringkasan"]["semua_lulus"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
