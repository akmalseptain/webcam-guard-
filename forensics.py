"""forensics.py — Mesin forensik & korelasi event lab (v2.0, STDLIB-ONLY).

Skema event normalisasi (8 jenis/kind):
  netmon, credcheck, redsim, stealth, mirror, audit, process, config
Setiap event: {"ts", "kind", "host", "event", "detail"} + integritas
hash-chain (prev, seq, hash) yang bisa diverifikasi.

v2.0 — perubahan dari v1.3 (motivasi: audit A-01/A-07/A-15 + bug fuzz F2):
- flock lintas proses + baca baris terakhir (append O(1), aman konkuren).
- field `seq` monotonik.
- checkpoint()/verify_terhadap_anchor(): anchor eksternal atomik →
  truncation baris EKOR terdeteksi. TANPA anchor, penghapusan baris
  terakhir tetap TIDAK terdeteksi (blind spot yang diakui).
- verify() toleran baris malformed (JSON rusak / bukan dict) → indeks,
  bukan AttributeError (bug ditemukan fuzz F2, diikat regresi).
- CLI --checkpoint untuk membuat anchor dari file event.

Formula hash TIDAK berubah dari v1.3:
  sha256("{prev}|{ts}|{kind}|{host}|{event}|{detail}")
"""

import csv
import hashlib
import json
import os
from datetime import datetime

from audit_core import _kunci_file, _sha256_file, tulis_anchor_atomik, \
    _entry_terakhir

KINDS = ("netmon", "credcheck", "redsim", "stealth", "mirror",
         "audit", "process", "config", "slc")


def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize(kind, event, detail="", host="lab-01", ts=None):
    """Normalisasi satu event mentah ke skema umum."""
    if kind not in KINDS:
        raise ValueError(f"kind tidak dikenal: {kind}")
    return {
        "ts": ts or now_ts(),
        "kind": kind,
        "host": host,
        "event": str(event),
        "detail": str(detail),
    }


class EventStore:
    """Penyimpanan event JSONL dengan hash-chain (tamper-evident)."""

    def __init__(self, path="lab_events.jsonl", anchor_path=None):
        self.path = path
        self.anchor_path = anchor_path or f"{path}.anchor.json"

    def _hash(self, e, prev):
        bahan = (f"{prev}|{e['ts']}|{e['kind']}|{e['host']}|"
                 f"{e['event']}|{e['detail']}").encode("utf-8")
        return hashlib.sha256(bahan).hexdigest()

    def _seq_baru(self, terakhir):
        if terakhir is None:
            return 1
        if isinstance(terakhir.get("seq"), int):
            return terakhir["seq"] + 1
        return len(self.load()) + 1  # file legacy tanpa seq

    def append(self, event, emit=True):
        """Tambah event (dict hasil normalize); kembalikan event + hash.

        emit=False hanya menghitung hash tanpa menulis (dipakai test).
        """
        e = dict(event)
        if emit:
            with _kunci_file(self.path):
                terakhir = _entry_terakhir(self.path)
                prev = terakhir.get("hash") if terakhir else "GENESIS"
                e["prev"] = prev
                e["seq"] = self._seq_baru(terakhir)
                e["hash"] = self._hash(e, prev)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
        else:
            entries = self.load()
            prev = entries[-1]["hash"] if entries else "GENESIS"
            e["prev"] = prev
            e["seq"] = (entries[-1].get("seq", len(entries)) + 1) if entries else 1
            e["hash"] = self._hash(e, prev)
        return e

    def load(self):
        """Semua baris valid; baris kosong/korup dilewati (verify() melapor)."""
        if not os.path.exists(self.path):
            return []
        hasil = []
        with open(self.path, encoding="utf-8") as f:
            for baris in f:
                baris = baris.strip()
                if not baris:
                    continue
                try:
                    e = json.loads(baris)
                    if isinstance(e, dict):
                        hasil.append(e)
                except ValueError:
                    continue
        return hasil

    def _baris_mentah(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as f:
            return [b.strip() for b in f if b.strip()]

    def verify(self):
        """None bila utuh; selain itu indeks baris bermasalah (toleran)."""
        prev = "GENESIS"
        for i, mentah in enumerate(self._baris_mentah()):
            try:
                e = json.loads(mentah)
            except ValueError:
                return i
            if not isinstance(e, dict):
                return i
            if e.get("prev") != prev:
                return i
            try:
                if self._hash(e, prev) != e.get("hash"):
                    return i
            except (KeyError, TypeError):
                return i
            prev = e["hash"]
        return None

    # ---------------- anchor (checkpoint eksternal) ----------------
    def checkpoint(self, anchor_path=None):
        """Catat anchor (n, seq/hash terakhir, SHA-256 file) atomik."""
        anchor_path = anchor_path or self.anchor_path
        with _kunci_file(self.path):
            entries = self.load()
            n = len(entries)
            terakhir = entries[-1] if entries else None
            data = {
                "versi": 1,
                "n": n,
                "anchor_seq": terakhir.get("seq") if terakhir else None,
                "anchor_hash": terakhir.get("hash") if terakhir else "GENESIS",
                "ts": now_ts(),
                "file_sha256": _sha256_file(self.path) if n else "",
            }
        tulis_anchor_atomik(anchor_path, data)
        return data

    def verify_terhadap_anchor(self, anchor_path=None):
        """Verifikasi rantai terhadap anchor tepercaya (deteksi truncation)."""
        anchor_path = anchor_path or self.anchor_path
        hasil = {"utuh": False, "masalah": "anchor tidak ditemukan",
                 "n": 0, "anchor": None}
        if not os.path.exists(anchor_path):
            hasil["n"] = len(self.load())
            return hasil
        try:
            with open(anchor_path, encoding="utf-8") as f:
                anchor = json.load(f)
        except (ValueError, OSError):
            hasil["n"] = len(self.load())
            return hasil
        if not isinstance(anchor, dict):
            hasil["n"] = len(self.load())
            return hasil
        hasil["anchor"] = anchor

        idx = self.verify()
        if idx is not None:
            hasil["masalah"] = f"rantai rusak di baris {idx}"
            hasil["n"] = len(self.load())
            return hasil
        entries = self.load()
        hasil["n"] = len(entries)
        try:
            n_anchor = int(anchor.get("n", 0))
        except (ValueError, TypeError):
            n_anchor = 0
        if len(entries) < n_anchor:
            hasil["masalah"] = f"TERPANGKAS: {len(entries)} < {n_anchor}"
            return hasil
        if n_anchor == 0:
            hasil["utuh"] = True
            hasil["masalah"] = None
            return hasil
        e = entries[n_anchor - 1]
        if e.get("hash") != anchor.get("anchor_hash"):
            hasil["masalah"] = "baris pada posisi anchor berubah/dihapus"
            return hasil
        aseq = anchor.get("anchor_seq")
        if aseq is not None and e.get("seq") is not None \
                and e.get("seq") != aseq:
            hasil["masalah"] = "baris pada posisi anchor berubah/dihapus"
            return hasil
        hasil["utuh"] = True
        hasil["masalah"] = None
        return hasil

    # ---------------- query / timeline / korelasi ----------------
    def query(self, kind=None, host=None, since=None, until=None):
        """Filter event (since/until = 'YYYY-MM-DD HH:MM:SS')."""
        hasil = self.load()
        if kind:
            hasil = [e for e in hasil if e["kind"] == kind]
        if host:
            hasil = [e for e in hasil if e["host"] == host]
        if since:
            hasil = [e for e in hasil if e["ts"] >= since]
        if until:
            hasil = [e for e in hasil if e["ts"] <= until]
        return hasil

    def timeline(self):
        """Event terurut kronologis (untuk rekonstruksi kejadian)."""
        return sorted(self.load(), key=lambda e: e["ts"])

    def correlate(self, jendela_detik=300):
        """Kelompokkan event bermuatan anomali menjadi kandidat insiden.

        Aturan (sederhana dan eksplisit): event 'penting' (dengan kata
        kunci anomali) dikelompokkan per host bila terjadi dalam jendela
        waktu yang sama.
        """
        kunci_anomali = ("anomali", "TINGGI", "REFUSED", "deteksi",
                         "beacon", "scan", "VULNERABLE")
        penting = [e for e in self.load()
                   if any(k in e["event"] or k in e["detail"]
                          for k in kunci_anomali)]
        penting.sort(key=lambda e: (e["host"], e["ts"]))
        grup = []
        for e in penting:
            ditempatkan = False
            for g in grup:
                if (g["host"] == e["host"]
                        and self._selisih(g["events"][-1]["ts"], e["ts"])
                        <= jendela_detik):
                    g["events"].append(e)
                    ditempatkan = True
                    break
            if not ditempatkan:
                grup.append({"host": e["host"], "events": [e]})
        return [{"host": g["host"],
                 "mulai": g["events"][0]["ts"],
                 "selesai": g["events"][-1]["ts"],
                 "n_event": len(g["events"]),
                 "events": g["events"]}
                for g in grup]

    @staticmethod
    def _selisih(ts1, ts2):
        f = "%Y-%m-%d %H:%M:%S"
        try:
            return abs((datetime.strptime(ts2, f)
                        - datetime.strptime(ts1, f)).total_seconds())
        except ValueError:
            return 1e9


def export_csv(events, path="events_export.csv"):
    """Ekspor event ke CSV (paket bukti yang mudah diperiksa)."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ts", "kind", "host", "event", "detail", "hash"])
        for e in events:
            w.writerow([e["ts"], e["kind"], e["host"],
                        e["event"], e["detail"], e.get("hash", "")])
    return path


def build_report(store, judul="Laporan Forensik Lab"):
    """Laporan teks: integritas, anchor, distribusi, timeline, insiden."""
    baris = ["=" * 64]
    baris.append(f" {judul}")
    baris.append("=" * 64)
    rusak = store.verify()
    if rusak is None:
        baris.append(" Integritas rantai event: OK (hash-chain utuh)")
    else:
        baris.append(f" !! INTEGRITAS: rantai putus di baris {rusak}")
    status_anchor = store.verify_terhadap_anchor()
    if status_anchor.get("anchor") is None:
        baris.append(" Anchor: belum ada — truncation baris ekor TIDAK "
                     "dapat terdeteksi (jalankan --checkpoint)")
    elif status_anchor["utuh"]:
        baris.append(f" Anchor: OK (n={status_anchor['n']} vs anchor "
                     f"n={status_anchor['anchor']['n']})")
    else:
        baris.append(f" !! ANCHOR: {status_anchor['masalah']}")
    entries = store.load()
    baris.append(f" Total event: {len(entries)}")
    per_kind = {}
    for e in entries:
        per_kind[e["kind"]] = per_kind.get(e["kind"], 0) + 1
    baris.append(" Distribusi jenis event:")
    for k, n in sorted(per_kind.items()):
        baris.append(f"   - {k:<10} {n}")
    insiden = store.correlate()
    baris.append(f" Kandidat insiden (korelasi): {len(insiden)}")
    for g in insiden:
        baris.append(f"   [{g['host']}] {g['mulai']} -> {g['selesai']} "
                     f"({g['n_event']} event)")
    baris.append("")
    baris.append(" Timeline kronologis:")
    for e in store.timeline():
        baris.append(f"   {e['ts']} [{e['kind']}/{e['host']}] "
                     f"{e['event']} — {e['detail']}")
    baris.append("=" * 64)
    baris.append(" Provenance: event dikumpulkan dari modul lab lokal;")
    baris.append(" metadata jaringan hanya dari sumber lab yang diotorisasi.")
    return "\n".join(baris)


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="Forensics engine v2.0 (lab) — timeline, korelasi, "
                    "integritas hash-chain + anchor, ekspor bukti.")
    ap.add_argument("--events", default="lab_events.jsonl")
    ap.add_argument("--export", help="ekspor event ke file CSV")
    ap.add_argument("--checkpoint", action="store_true",
                    help="tulis anchor/checkpoint tepercaya (file terpisah)")
    args = ap.parse_args()

    store = EventStore(args.events)
    if args.checkpoint:
        anchor = store.checkpoint()
        print(f"Checkpoint ditulis: {store.anchor_path} (n={anchor['n']})")
    if args.export:
        export_csv(store.load(), args.export)
        print(f"Ekspor {len(store.load())} event -> {args.export}")
    print(build_report(store))


if __name__ == "__main__":
    main()
