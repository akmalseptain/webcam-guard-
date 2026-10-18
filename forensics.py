"""forensics.py — Mesin forensik & korelasi event lab (STDLIB-ONLY).

Skema event normalisasi (8 jenis/kind):
  netmon, credcheck, redsim, stealth, mirror, audit, process, config
Setiap event: {"ts", "kind", "host", "event", "detail"} + integritas
hash-chain (id, prev, hash) yang bisa diverifikasi.

Kemampuan:
- EventStore: append + load + verify (tamper-evident, seperti audit_core).
- query(): filter kind/host/waktu. timeline(): urut kronologis.
- correlate(): kelompokkan event terkait menjadi kandidat insiden
  (berdasarkan host + kedekatan waktu + jenis bermuatan anomali).
- export_csv() dan build_report() untuk paket bukti.
"""

import csv
import hashlib
import json
import os
from datetime import datetime

KINDS = ("netmon", "credcheck", "redsim", "stealth", "mirror",
         "audit", "process", "config")


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

    def __init__(self, path="lab_events.jsonl"):
        self.path = path

    def _hash(self, e, prev):
        bahan = (f"{prev}|{e['ts']}|{e['kind']}|{e['host']}|"
                 f"{e['event']}|{e['detail']}").encode("utf-8")
        return hashlib.sha256(bahan).hexdigest()

    def append(self, event, emit=True):
        """Tambah event (dict hasil normalize); kembalikan event + hash."""
        entries = self.load()
        prev = entries[-1]["hash"] if entries else "GENESIS"
        e = dict(event)
        e["prev"] = prev
        e["hash"] = self._hash(e, prev)
        if emit:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        return e

    def load(self):
        if not os.path.exists(self.path):
            return []
        hasil = []
        with open(self.path, encoding="utf-8") as f:
            for baris in f:
                baris = baris.strip()
                if baris:
                    hasil.append(json.loads(baris))
        return hasil

    def verify(self):
        """None bila utuh; selain itu indeks baris bermasalah."""
        prev = "GENESIS"
        for i, e in enumerate(self.load()):
            if e.get("prev") != prev or self._hash(e, prev) != e.get("hash"):
                return i
            prev = e["hash"]
        return None

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

        Aturan (sederhana dan eksplisit): event 'penting' (kind netmon/
        redsim/stealth/credcheck dengan kata kunci anomali) dikelompokkan
        per host bila terjadi dalam jendela waktu yang sama.
        """
        kunci_anomali = ("anomali", "TINGGI", "REFUSED", "deteksi",
                         "beacon", "scan", "VULNERABLE")
        penting = [e for e in self.load()
                   if any(k in e["event"] or k in e["detail"]
                          for k in kunci_anomali)]
        # urut per host + waktu
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
    """Laporan teks: integritas, distribusi kind, timeline, kandidat insiden."""
    baris = ["=" * 64]
    baris.append(f" {judul}")
    baris.append("=" * 64)
    rusak = store.verify()
    if rusak is None:
        baris.append(" Integritas rantai event: OK (hash-chain utuh)")
    else:
        baris.append(f" !! INTEGRITAS: rantai putus di baris {rusak}")
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
        description="Forensics engine v1.3 (lab) — timeline, korelasi, "
                    "integritas hash-chain, ekspor bukti.")
    ap.add_argument("--events", default="lab_events.jsonl")
    ap.add_argument("--export", help="ekspor event ke file CSV")
    args = ap.parse_args()

    store = EventStore(args.events)
    if args.export:
        export_csv(store.load(), args.export)
        print(f"Ekspor {len(store.load())} event -> {args.export}")
    print(build_report(store))


if __name__ == "__main__":
    main()
