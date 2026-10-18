"""evidence.py — Tamper-Evident Forensic Evidence Pack (v2.0, BARU).

Alur bukti yang reproducible dan bisa diverifikasi PIHAK KETIGA:
- build_pack(): ekspor event mentah (RAW) + analisis (DERIVED) + manifest
  SHA-256 + laporan Markdown + perintah reproduksi.
- verify_pack(): verifikasi READ-ONLY — tidak pernah menulis/merapikan
  bukti; hanya membandingkan ulang hash file terhadap manifest dan
  status rantai/anchor.

Pemisahan JUJUR antara RAW dan DERIVED:
- RAW    : event persis seperti tersimpan (events.json) — tidak diubah.
- DERIVED: timeline, korelasi, laporan — hasil analisis, BUKAN bukti asli.
Manifest mencatat kelas setiap file + ukuran + SHA-256.

Batasan yang diakui:
- Manifest disimpan di lokasi yang sama dengan bukti — penyerang yang
  menguasai host bisa merekayasa keduanya. Untuk jaminan lebih kuat,
  simpan hash manifest di lokasi terpisah/eksternal (lihat docs).
"""

import argparse
import csv
import hashlib
import json
import os
import sys
import zipfile
from datetime import datetime

import forensics

CLASSES = ("raw", "derived", "meta")


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _tulis(path, data):
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode,
             **({} if isinstance(data, bytes)
                else {"encoding": "utf-8"})) as f:
        f.write(data)


def build_pack(events_path="lab_events.jsonl",
               audit_path="lab_audit.jsonl",
               out_dir="evidence_pack", versi="2.0"):
    """Bangun paket bukti dari event (RAW) + analisis (DERIVED)."""
    store = forensics.EventStore(events_path)
    entries = store.load()
    status_rantai = store.verify()          # None = utuh / idx = rusak
    status_anchor = store.verify_terhadap_anchor()

    os.makedirs(out_dir, exist_ok=True)
    p_events = os.path.join(out_dir, "events.json")
    p_analisis = os.path.join(out_dir, "analysis.json")
    p_csv = os.path.join(out_dir, "events.csv")
    p_report = os.path.join(out_dir, "report.md")

    # ---- RAW: event apa adanya ----
    raw = json.dumps({"kelas": "raw", "n": len(entries),
                      "events": entries}, ensure_ascii=False, indent=2)
    _tulis(p_events, raw)

    # ---- DERIVED: timeline, korelasi, laporan ----
    analisis = {
        "kelas": "derived",
        "rantai_utuh": status_rantai is None,
        "baris_masalah": status_rantai,
        "anchor": status_anchor,
        "timeline": store.timeline(),
        "korelasi": [{k: v for k, v in g.items() if k != "events"}
                     for g in store.correlate()],
    }
    _tulis(p_analisis, json.dumps(analisis, ensure_ascii=False, indent=2))

    with open(p_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ts", "kind", "host", "event", "detail", "hash"])
        for e in entries:
            w.writerow([e["ts"], e["kind"], e["host"],
                        e["event"], e["detail"], e.get("hash", "")])

    baris = ["# Evidence Pack — WebCam Guard Lab", "",
             f"- Dibuat: {datetime.now().isoformat(timespec='seconds')}",
             f"- Software: webcam-guard v{versi} (Python {sys.version.split()[0]})",
             f"- Sumber event (RAW): {events_path}",
             f"- Sumber audit (RAW): {audit_path}",
             f"- Jumlah event: {len(entries)}",
             f"- Rantai hash: {'UTUH' if status_rantai is None else 'RUSAK di baris ' + str(status_rantai)}",
             f"- Anchor: {status_anchor['masalah'] or 'OK (utuh terhadap checkpoint)'}",
             "", "## Timeline (DERIVED)", ""]
    for e in store.timeline():
        baris.append(f"- `{e['ts']}` [{e['kind']}/{e['host']}] "
                      f"{e['event']} — {e['detail']}")
    baris += ["", "## Korelasi / kandidat insiden (DERIVED)", ""]
    for g in store.correlate():
        baris.append(f"- **{g['host']}**: {g['mulai']} → {g['selesai']} "
                     f"({g['n_event']} event)")
    baris += ["", "## Reproduksi", "",
              "```",
              "python3 forensics.py --events " + events_path,
              "python3 evidence.py --verify --dir " + out_dir,
              "```", "",
              "> RAW = bukti asli (tidak diubah). DERIVED = analisis.",
              "> Verifikasi TIDAK pernah menulis ulang bukti."]
    _tulis(p_report, "\n".join(baris))

    # ---- META: manifest + reproduce ----
    manifest = {
        "versi_paket": 1,
        "software": f"webcam-guard v{versi}",
        "python": sys.version.split()[0],
        "dibuat": datetime.now().isoformat(timespec="seconds"),
        "sumber": {"events": events_path, "audit": audit_path},
        "file": {},
    }
    for nama, kelas in (("events.json", "raw"),
                        ("analysis.json", "derived"),
                        ("events.csv", "raw"),
                        ("report.md", "derived")):
        p = os.path.join(out_dir, nama)
        with open(p, "rb") as f:
            data = f.read()
        manifest["file"][nama] = {
            "bytes": len(data),
            "sha256": _sha256_bytes(data),
            "kelas": kelas,
        }
    p_manifest = os.path.join(out_dir, "manifest.json")
    _tulis(p_manifest, json.dumps(manifest, ensure_ascii=False, indent=2))

    reproduce = (
        "# Reproduksi evidence pack\n"
        "1. python3 evidence.py --build --dir " + out_dir + "\n"
        "2. python3 evidence.py --verify --dir " + out_dir + "\n"
        "# bandingkan manifest.json dengan salinan yang Anda terima\n")
    _tulis(os.path.join(out_dir, "reproduce.txt"), reproduce)

    return {"out_dir": out_dir, "n_event": len(entries),
            "n_file": len(manifest["file"]),
            "rantai_utuh": status_rantai is None,
            "manifest": manifest}


def verify_pack(out_dir="evidence_pack"):
    """Verifikasi READ-ONLY: hash tiap file vs manifest + status rantai.

    TIDAK ADA file yang ditulis/diubah di sini (bukti tidak dirapikan
    diam-diam) — perbaikan bukti harus dilakukan eksplisit oleh manusia.
    """
    p_manifest = os.path.join(out_dir, "manifest.json")
    hasil = {"utuh": False, "masalah": [], "n_file": 0}
    if not os.path.exists(p_manifest):
        hasil["masalah"].append("manifest tidak ditemukan")
        return hasil
    try:
        with open(p_manifest, encoding="utf-8") as f:
            manifest = json.load(f)
    except ValueError:
        hasil["masalah"].append("manifest rusak (bukan JSON valid)")
        return hasil
    if not isinstance(manifest.get("file"), dict) or not manifest["file"]:
        hasil["masalah"].append("manifest tanpa daftar file")
        return hasil
    n = 0
    for nama, info in manifest["file"].items():
        p = os.path.join(out_dir, nama)
        n += 1
        if not os.path.exists(p):
            hasil["masalah"].append(f"{nama}: hilang")
            continue
        with open(p, "rb") as f:
            data = f.read()
        if len(data) != info.get("bytes"):
            hasil["masalah"].append(
                f"{nama}: ukuran berubah "
                f"({len(data)} != {info.get('bytes')})")
        if _sha256_bytes(data) != info.get("sha256"):
            hasil["masalah"].append(f"{nama}: SHA-256 TIDAK cocok")
    hasil["n_file"] = n
    # verifikasi ulang rantai event bila ada (read-only)
    p_events = os.path.join(out_dir, "events.json")
    if os.path.exists(p_events):
        try:
            with open(p_events, encoding="utf-8") as f:
                doc = json.load(f)
            for e in doc.get("events", []):
                pass  # event RAW diverifikasi via forensics di bawah
            src = manifest.get("sumber", {}).get("events")
            if src and os.path.exists(src):
                st = forensics.EventStore(src).verify()
                if st is not None:
                    hasil["masalah"].append(
                        f"rantai sumber {src} rusak di baris {st}")
        except ValueError:
            hasil["masalah"].append("events.json rusak (bukan JSON valid)")
    hasil["utuh"] = not hasil["masalah"]
    return hasil


def laporan_md(hasil):
    baris = ["# Verifikasi Evidence Pack", "",
             f"- Status: {'UTUH' if hasil['utuh'] else 'MASALAH DITEMUKAN'}",
             f"- File diverifikasi: {hasil['n_file']}"]
    for m in hasil["masalah"]:
        baris.append(f"- !! {m}")
    return "\n".join(baris) + "\n"


def main():
    ap = argparse.ArgumentParser(
        description="evidence v2.0 — paket bukti tamper-evident: "
                    "build/verify/zip (RAW vs DERIVED eksplisit).")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--zip", action="store_true",
                    help="arsipkan evidence pack ke evidence_pack.zip")
    ap.add_argument("--events", default="lab_events.jsonl")
    ap.add_argument("--audit", default="lab_audit.jsonl")
    ap.add_argument("--dir", default="evidence_pack")
    args = ap.parse_args()

    if args.build:
        hasil = build_pack(args.events, args.audit, args.dir)
        print(f"[evidence] pack dibuat: {args.dir} "
              f"({hasil['n_event']} event, {hasil['n_file']} file)")
        print(f"[evidence] rantai sumber: "
              f"{'UTUH' if hasil['rantai_utuh'] else 'RUSAK'}")
    if args.verify:
        hasil = verify_pack(args.dir)
        print(f"[evidence] verifikasi: "
              f"{'UTUH' if hasil['utuh'] else 'MASALAH'} "
              f"({hasil['n_file']} file)")
        for m in hasil["masalah"]:
            print(f"  !! {m}")
        _tulis(os.path.join(args.dir, "verify_report.md"), laporan_md(hasil))
        if not hasil["utuh"]:
            return 1
    if args.zip:
        zpath = args.dir.rstrip("/") + ".zip"
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            for nama in sorted(os.listdir(args.dir)):
                z.write(os.path.join(args.dir, nama), arcname=nama)
        print(f"[evidence] arsip: {zpath}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
