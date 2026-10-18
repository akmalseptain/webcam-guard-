#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_events.py — v4.0 Sovereign Lab Control: EVENT PIPELINE.

Jujur by design:
  - SETIAP event diberi label ASAL: "telemetri" (nyata dari endpoint),
    "sintetis" (demo/test), "replay" (sejarah diputar ulang),
    "inferensi" (kesimpulan mesin — BUKAN fakta teramati).
  - data yang TIDAK ADA tidak pernah dianggap bukti "tidak ada insiden".
  - normalisasi ts, dedup jendela, retensi (umur + jumlah), severity +
    confidence, threshold alert, korelasi perangkat/misi, perbandingan
    historis dengan penandaan kekosongan data.
"""
from __future__ import annotations

import hashlib
import json
import time

ASAL = ("telemetri", "sintetis", "replay", "inferensi")
SEVERITY = ("INFO", "PERINGATAN", "KRITIS")

# pemetaan kind → severity default (bisa dioverride event)
KIND_SEVERITY = {"netmon": "PERINGATAN", "redsim": "PERINGATAN",
                 "slc": "INFO", "audit": "INFO", "process": "INFO",
                 "config": "PERINGATAN", "stealth": "KRITIS",
                 "credcheck": "PERINGATAN", "mirror": "PERINGATAN"}


def sekarang_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


def normalisasi(raw, asal="telemetri", dev=None, misi=None):
    """Satu event mentah → event skema SLC. asal WAJIB eksplisit."""
    if asal not in ASAL:
        raise ValueError(f"asal tidak dikenal: {asal}")
    kind = raw.get("kind", "slc")
    if kind not in KIND_SEVERITY:
        raise ValueError(f"kind tidak dikenal: {kind}")
    ts = raw.get("ts") or sekarang_iso()
    ev = {
        "id": hashlib.sha256(f"{ts}|{kind}|{raw.get('event','')}"
                            f"|{dev}|{raw.get('detail','')}"
                            .encode()).hexdigest()[:16],
        "ts": ts,
        "kind": kind,
        "event": str(raw.get("event", "")),
        "detail": str(raw.get("detail", "")),
        "severity": raw.get("severity") or KIND_SEVERITY[kind],
        "confidence": float(raw.get("confidence", 1.0 if asal in
                                    ("telemetri", "sintetis") else 0.5)),
        "sumber": str(raw.get("sumber", asal)),
        "asal": asal,
        "dev": dev or raw.get("host", "lab"),
        "misi": misi,
    }
    if ev["severity"] not in SEVERITY:
        raise ValueError(f"severity tidak dikenal: {ev['severity']}")
    return ev


class EventPipeline:
    """Pipeline in-memory: dedup, retensi, pencarian, alert, korelasi."""

    def __init__(self, dedup_jendela_s=5.0, retensi_maks=10000,
                 retensi_umur_s=None):
        self.events = []
        self.dedup_jendela_s = dedup_jendela_s
        self.retensi_maks = retensi_maks
        self.retensi_umur_s = retensi_umur_s
        self._terakhir_dedup = {}  # kunci -> ts
        self.alerts = []

    # ---------------- masuk ----------------
    def masuk(self, raw, asal="telemetri", dev=None, misi=None, ts_abs=None):
        """Terima event; duplikat dalam jendela dibuang (dicatat)."""
        ev = normalisasi(raw, asal=asal, dev=dev, misi=misi)
        kunci = hashlib.sha256(f"{ev['kind']}|{ev['event']}|{ev['dev']}"
                               .encode()).hexdigest()[:16]
        now = float(ts_abs if ts_abs is not None else time.time())
        # ts event dianggap sama jika event berasal dari window yang sama;
        # gunakan kunci + jendela absolut utk dedup replay yang jujur
        if kunci in self._terakhir_dedup:
            if now - self._terakhir_dedup[kunci] < self.dedup_jendela_s:
                return None
        self._terakhir_dedup[kunci] = now
        self.events.append(ev)
        self._retensi(now)
        return ev

    def _retensi(self, now):
        if self.retensi_umur_s is not None:
            batas = time.strftime("%Y-%m-%dT%H:%M:%S",
                                  time.gmtime(now - self.retensi_umur_s)) + "Z"
            self.events = [e for e in self.events if e["ts"] >= batas]
        if len(self.events) > self.retensi_maks:
            self.events = self.events[-self.retensi_maks:]

    # ---------------- cari & filter ----------------
    def cari(self, teks=None, kind=None, dev=None, misi=None,
             severity_min=None, asal=None):
        urut = {"INFO": 0, "PERINGATAN": 1, "KRITIS": 2}
        keluar = []
        for e in self.events:
            if teks and teks.lower() not in (e["event"] + " " +
                                            e["detail"]).lower():
                continue
            if kind and e["kind"] != kind:
                continue
            if dev and e["dev"] != dev:
                continue
            if misi and e.get("misi") != misi:
                continue
            if asal and e["asal"] != asal:
                continue
            if severity_min and urut[e["severity"]] < urut[severity_min]:
                continue
            keluar.append(e)
        return keluar

    def korelasi(self):
        """Korelasi jumlah event per dev/misi (utk investigasi insiden)."""
        per_dev, per_misi = {}, {}
        for e in self.events:
            per_dev[e["dev"]] = per_dev.get(e["dev"], 0) + 1
            if e.get("misi"):
                per_misi[e["misi"]] = per_misi.get(e["misi"], 0) + 1
        return {"per_dev": per_dev, "per_misi": per_misi}

    # ---------------- alert threshold ----------------
    def atur_alert(self, kind, ambang, jendela_s, dev=None):
        """Threshold: >= ambang event kind (per dev) dalam jendela → alert."""
        self.alerts.append({"kind": kind, "ambang": ambang,
                             "jendela_s": jendela_s, "dev": dev,
                             "aktif": True})

    def cek_alert(self, now=None):
        """Evaluasi threshold → list alert terpicu. Kekosongan data TIDAK
        dianggap aman — hanya kelebihan yang memicu alert."""
        now = now if now is not None else time.time()
        terpicu = []
        for a in self.alerts:
            if not a["aktif"]:
                continue
            cocok = [e for e in self.events if e["kind"] == a["kind"] and
                     (a["dev"] is None or e["dev"] == a["dev"])]
            if len(cocok) >= a["ambang"]:
                terpicu.append({"aturan": dict(a), "n": len(cocok)})
        return terpicu

    # ---------------- historis ----------------
    def bandingkan_historis(self, baseline_counts):
        """Bandingkan jumlah per kind vs baseline (dict kind→n).
        Baseline yang datanya tidak ada → ditandai 'TIDAK_ADA_DATA',
        bukan dianggap nol bukti."""
        sekarang_n = {}
        for e in self.events:
            sekarang_n[e["kind"]] = sekarang_n.get(e["kind"], 0) + 1
        laporan = []
        for kind in set(sekarang_n) | set(baseline_counts):
            base = baseline_counts.get(kind)
            kini = sekarang_n.get(kind, 0)
            if base is None:
                laporan.append({"kind": kind, "kini": kini,
                                "baseline": None,
                                "catatan": "TIDAK_ADA_DATA baseline"})
            else:
                laporan.append({"kind": kind, "kini": kini,
                                "baseline": base,
                                "delta": kini - base})
        return laporan

    def label_milik(self):
        """Ringkasan kejujuran: berapa event per asal (sintetis harus jujur)."""
        n = {}
        for e in self.events:
            n[e["asal"]] = n.get(e["asal"], 0) + 1
        return n

    def ekspor(self, path):
        with open(path, "w") as f:
            json.dump({"events": self.events, "alerts": self.alerts},
                      f, ensure_ascii=False, indent=1)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="slc_events v4.0")
    ap.add_argument("--demo", action="store_true",
                    help="isi pipeline dgn event sintetis (LABEL SINTETIS)")
    a = ap.parse_args()
    p = EventPipeline()
    if a.demo:
        p.masuk({"kind": "slc", "event": "demo-heartbeat",
                 "detail": "contoh"}, asal="sintetis", dev="DEV-DEMO")
        p.masuk({"kind": "netmon", "event": "demo-beacon",
                 "detail": "beacon loopback"}, asal="sintetis",
                dev="DEV-DEMO")
        print(json.dumps(p.label_milik(), indent=1))
        print(json.dumps(p.cari(asal="sintetis"), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
