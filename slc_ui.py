#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_ui.py — v4.0: HORROR COMMAND CENTER (TUI, data-driven).

Identitas horror lab "SANG PENJAGA" (the Warden — penjaga lab) YANG JUJUR:
  - tampilan TIDAK menyamar sebagai produk lain dan SELALU menampilkan
    bahwa ini konsol administrasi jarak jauh resmi lab.
  - animasi hanya merespons EVENT NYATA (bukan hiasan): severity event
    menentukan frame.
  - kontrol: gerak_minim (reduced motion), bisu (mute), mode_polos
    (accessibility — tanpa warna/emoji), TOMBOL EMERGENCY STOP selalu
    tampil, dan tampilan tidak pernah menyembunyikan status administrasi.
"""
from __future__ import annotations

PALET = {"KRITIS": "☠", "PERINGATAN": "⚠", "INFO": "•",
         "SINTETIS": "◇", "SEHAT": "◆", "EMERGENCY": "■"}

# frame entity persona per severity — event-driven, bukan dekorasi
FRAME_HOROR = {
    "KRITIS": [
        r"   /\_/\   ",
        r"  ( o.o )  SANG PENJAGA MENGINTAI DARI KELAM",
        r"   > ^ <   ",
    ],
    "PERINGATAN": [
        r"   /\_/\   ",
        r"  ( -.- )  penjaga memperhatikan...",
        r"   > ^ <   ",
    ],
    "INFO": [
        r"   /\_/\   ",
        r"  ( ^.^ )  lab damai, penjaga berjaga.",
        r"   > ^ <   ",
    ],
}


def render_banner(mode="FISIK", gerak=True, bisu=False, mode_polos=False):
    """Banner command center — selalu menyatakan identitas administrasi."""
    animasi = "⚡" if gerak and not mode_polos else ""
    suara = "" if bisu else "🔊"
    return (
        f"{animasi}{suara} ╔════════════════════════════════════════╗\n"
        f"  ║  CYBER WAR ROOM — SANG PENJAGA  v4.0    ║\n"
        f"  ║  KONSOL ADMINISTRASI JARAK JAUH LAB     ║\n"
        f"  ║  (remote administration — BUKAN tersembunyi)║\n"
        f"  ╚════════════════════════════════════════╝\n"
        f"  mode: {mode}   [CTRL-E: EMERGENCY STOP] "
        f"[M: bisu] [R: gerak minim] [P: mode polos]")


def render_frame_horor(event, gerak=True, mode_polos=False):
    """Frame animasi ENTITY hanya dari event nyata (severity-driven)."""
    sev = (event or {}).get("severity", "INFO")
    frame = FRAME_HOROR.get(sev, FRAME_HOROR["INFO"])
    label = f"[{PALET.get(sev, '•')} {sev}] "
    if event.get("asal") == "sintetis":
        label = f"[{PALET['SINTETIS']} SINTETIS] "
    teks = frame[1].replace("SANG PENJAGA MENGINTAI DARI KELAM", "PENJAGA")
    if mode_polos:
        # mode aksesibilitas: tanpa glyph/emoji, teks saja
        label = (label.replace(PALET["KRITIS"], "")
                    .replace(PALET["PERINGATAN"], "")
                    .replace(PALET["INFO"], "")
                    .replace(PALET["SINTETIS"], ""))
        return f"{label}({sev}) {teks}  ({event.get('event', '')})"
    baris = [label + f for f in frame]
    if not gerak:  # reduced motion: frame tunggal, tanpa animasi lanjut
        baris.append(f"    (gerak minim: {event.get('event', '')})")
    return "\n".join(baris)


def render_peta_lab(inventaris, label=None):
    """Peta lab interaktif (TUI) — status per perangkat."""
    baris = ["── PETA LAB ─────────────────────────────"]
    for i, dev in enumerate(inventaris):
        glyph = PALET["EMERGENCY"] if dev.get("emergency") else \
            (PALET["SEHAT"] if dev.get("last_seen") else "?")
        baris.append(f"  [{glyph}] {dev.get('nama', dev['id']):16s} "
                     f"grup={dev.get('grup')} "
                     f"tertunda={dev.get('tertunda', 0)}")
    baris.append("  ? = belum pernah terhubung (TIDAK berarti sehat)")
    if label:
        baris.append(f"  label: {label}")
    return "\n".join(baris)


def render_grafik_aktivitas(deret, mode_polos=False):
    """Sparkline aktivitas agent (deret angka)."""
    if not deret:
        return "grafik aktivitas: TIDAK ADA DATA"
    mak = max(deret) or 1
    blok = "█" if not mode_polos else "#"
    baris = ["── GRAFIK AKTIVITAS AGENT ──────────────"]
    for n in deret[-20:]:
        baris.append(f"  {blok * max(1, int(8 * n / mak))} {n}")
    return "\n".join(baris)


def render_timeline(events, maks=12):
    """Timeline eksekusi live / sejarah event."""
    baris = ["── TIMELINE (terbaru ke bawah) ─────────"]
    if not events:
        baris.append("  (kosong — TIDAK ADA DATA, bukan 'tidak ada insiden')")
    for e in events[:maks]:
        asal = e.get("asal", "telemetri")
        tag = "SINTETIS" if asal == "sintetis" else asal.upper()
        baris.append(f"  {e.get('ts', '?')} [{e.get('severity', '?'):9s}]"
                     f" [{tag:8s}] {e.get('event', '')} "
                     f"({e.get('dev', '')})")
    return "\n".join(baris)


def render_misi_replay(misi, gerak=True):
    """Replay misi — langkah demi langkah dari data misi NYATA."""
    baris = [f"── REPLAY MISI: {getattr(misi, 'nama', '?')} "
             f"[{getattr(misi, 'state', '?')}] ───"]
    for l in getattr(misi, "urutan", []):
        ikon = {"SELESAI_TERVERIFIKASI": "✓", "GAGAL": "✗",
                "DIBATALKAN": "⏹", "DILEWATKAN": "⤼"}.get(l.get("status"),
                                                          "…")
        baris.append(f"  {ikon} {l['id']} {l.get('aksi')} → "
                     f"{l.get('dev')} [{l.get('status')}]")
        if not gerak:
            baris.append("    (gerak minim: tanpa animasi langkah)")
    return "\n".join(baris)


def render_investigasi(korelasi, alert, catatan_data=""):
    """Tampilan investigasi insiden: korelasi + alert + kejujuran."""
    baris = ["── INVESTIGASI INSIDEN ─────────────────"]
    for dev, n in sorted(korelasi.get("per_dev", {}).items(),
                         key=lambda x: -x[1]):
        baris.append(f"  perangkat {dev}: {n} event")
    if not korelasi.get("per_dev"):
        baris.append("  (TIDAK ADA DATA — tidak dapat disimpulkan aman)")
    if alert:
        baris.append(f"  ALERT TERPICU: {len(alert)}")
    else:
        baris.append("  alert: tidak ada (threshold tidak terlampaui)")
    if catatan_data:
        baris.append(f"  catatan: {catatan_data}")
    return "\n".join(baris)


def render_dasbor(misi_ringkas=None, inventaris=None, events=None,
                  gerak=True, bisu=False, mode_polos=False, label=None):
    """Dasbor gabungan: banner + frame horor + peta + grafik + timeline."""
    ev = events[0] if events else {}
    bagian = [render_banner(gerak=gerak, bisu=bisu, mode_polos=mode_polos),
              render_frame_horor(ev, gerak=gerak, mode_polos=mode_polos)]
    if inventaris:
        bagian.append(render_peta_lab(inventaris, label=label))
    if misi_ringkas:
        bagian.append(f"misi aktif: {misi_ringkas.get('nama')} "
                      f"[{misi_ringkas.get('state')}]")
    if events:
        bagian.append(render_timeline(events))
    return "\n".join(bagian)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="slc_ui v4.0 — command center")
    ap.add_argument("--demo-dasbor", action="store_true")
    ap.add_argument("--gerak-minim", action="store_true")
    ap.add_argument("--bisu", action="store_true")
    ap.add_argument("--mode-polos", action="store_true")
    a = ap.parse_args()
    if a.demo_dasbor:
        from slc_demo import data_sintetis_inventaris
        inv = [{"id": d["id"], "nama": d["nama"], "grup": d["grup"],
                "tags": d["tags"], "last_seen": None, "emergency": False,
                "tertunda": 0} for d in data_sintetis_inventaris()]
        print(render_dasbor(inventaris=inv,
                           events=[{"ts": "…", "kind": "slc",
                                    "event": "demo mulai",
                                    "severity": "INFO", "asal": "sintetis",
                                    "dev": "dev-demo-01"}],
                           gerak=not a.gerak_minim, bisu=a.bisu,
                           mode_polos=a.mode_polos,
                           label="SINTETIS-DEMO"))
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
