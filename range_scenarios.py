#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""range_scenarios.py — v3.0: Scenario engine untuk cyber range (R4).

Emulasi adversary BERSCOP untuk lab yang diotorisasi. Empat skenario
berlabel MITRE ATT&CK dieksekusi NYATA di loopback (bukan pura-pura):

  R-RECON      T1046   koneksi loopback nyata ke 12 port → detektor
                       netmon harus menandai port_scan.
  R-C2-BEACON  T1071   koneksi teratur ke listener loopback → netmon
                       harus menandai beacon (ambang interval
                       DISESUAIKAN untuk loopback, dilaporkan jujur).
  R-FIM-TAMPER T1565.001 baseline FIM direktori uji → tamper file →
                       range_agent.kumpul_fim harus mendeteksi.
  R-PRIVILEGE  T1078   operator non-admin mencoba beri_tugas →
                       RangeController harus menolak (PermissionError +
                       audit TUGAS_DITOLAK); admin diterima (kontrol +).

Setiap skenario MENGEMBALIKAN bukti (evidence) dan status detected.
Coverage per kontrol: berapa skenario dijalankan vs terdeteksi.

JUJUR:
- Scope divalidasi SEBELUM eksekusi (redsim.ScopeGuard); di luar scope →
  DITOLAK_SCOPE + audit SKENARIO_DITOLAK, tidak ada yang dieksekusi.
- Rollback VM snapshot TIDAK dieksekusi oleh modul ini (status NOT RUN);
  perintah rollback hanya DICATAT bila diberikan, eksekusinya keputusan
  manual owner di hipervisor.
- Ambang beacon loopback disesuaikan (interval 50 ms, bukan 0.5 s jaringan
  nyata) — dicatat eksplisit di evidence.

CLI:
  python3 range_scenarios.py --scope tests/scope_loopback.json --json
  python3 range_scenarios.py --scope lab_scope.json --target 127.0.0.1
  (lab_scope.json TIDAK memuat 127.0.0.1 → semua DITOLAK_SCOPE)
Exit: 0 semua skenario dijalankan & terdeteksi; 1 ada yang tidak
terdeteksi; 2 ditolak scope; 3 error.
"""

import argparse
import json
import os
import secrets
import socket
import sys
import tempfile
import time
from datetime import datetime

import audit_core
import forensics
import netmon
from redsim import ScopeGuard

from range_agent import kumpul_fim
from range_controller import OperatorStore, RangeController
from range_registry import DeviceRegistry

TARGET_DEFAULT = "127.0.0.1"
JUMLAH_PORT_RECON = 12        # >= scan_min_port (10)
BEACON_N_KONEKSI = 10         # >= beacon_min_packets (8)
BEACON_INTERVAL = 0.05         # detik, khusus uji loopback (dilaporkan)
BEACON_AMBANG_LOOPBACK = {"beacon_rata_min": 0.02}
HOST_EVENT = "range-loopback"


# ------------------------------------------------------------
# Fungsi skenario — masing-masing koneksi/bukti NYATA
# ------------------------------------------------------------
def _skenario_recon(runner):
    """R-RECON (T1046): koneksi loopback nyata ke 12 port → port_scan."""
    ports, listeners = [], []
    try:
        for _ in range(JUMLAH_PORT_RECON):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((runner.target, 0))
            s.listen(1)
            listeners.append(s)
            ports.append(s.getsockname()[1])
        tabel = netmon.FlowTable()
        for port in ports:
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.settimeout(1.0)
            try:
                c.connect((runner.target, port))
                sport = c.getsockname()[1]
            finally:
                c.close()
            tabel.add({"src": runner.target, "sport": sport,
                       "dst": runner.target, "dport": port,
                       "proto": "TCP", "ts": time.time(), "bytes": 60,
                       "app": "", "detail": ""})
        temuan = netmon.detect_anomalies(tabel.daftar())
        detected = any(t["tipe"] == "port_scan" for t in temuan)
        return {
            "nama": "R-RECON", "mitre": "T1046",
            "kontrol": "netmon_port_scan", "detected": detected,
            "evidence": [
                f"{len(ports)} koneksi loopback nyata ke "
                f"{len(set(ports))} port berbeda",
                f"port tersentuh: {sorted(ports)[:15]}",
                f"temuan netmon: {[t['tipe'] for t in temuan]}",
            ],
        }
    finally:
        for s in listeners:
            s.close()


def _skenario_c2(runner):
    """R-C2-BEACON (T1071): beacon pada SATU koneksi persisten loopback.

    C2 nyata sering memakai koneksi TCP persisten yang sama (satu
    5-tuple) dengan kirim data berkala — pola ini direkam sebagai SATU
    flow berinterval teratur, sesuai model detektor netmon.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((runner.target, 0))
    listener.listen(1)
    dport = listener.getsockname()[1]
    tabel = netmon.FlowTable()
    klien = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    klien.settimeout(2.0)
    try:
        klien.connect((runner.target, dport))
        sport = klien.getsockname()[1]
        for _ in range(BEACON_N_KONEKSI):
            klien.send(b"BEACON-LAB\n")   # kirim nyata, interval teratur
            tabel.add({"src": runner.target, "sport": sport,
                       "dst": runner.target, "dport": dport,
                       "proto": "TCP", "ts": time.time(), "bytes": 120,
                       "app": "", "detail": ""})
            time.sleep(BEACON_INTERVAL)
        flows = tabel.daftar()
        temuan = netmon.detect_anomalies(
            flows, ambang=dict(BEACON_AMBANG_LOOPBACK))
        detected = any(t["tipe"] == "beacon" for t in temuan)
        return {
            "nama": "R-C2-BEACON", "mitre": "T1071",
            "kontrol": "netmon_beacon", "detected": detected,
            "evidence": [
                f"{BEACON_N_KONEKSI} kirim berkala interval "
                f"{BEACON_INTERVAL}s pada SATU koneksi persisten ke "
                f"{runner.target}:{dport} (sport={sport})",
                "CATATAN JUJUR: ambang beacon_rata_min disesuaikan "
                f"{BEACON_AMBANG_LOOPBACK} (uji loopback 50 ms; default "
                "0.5s mengasumsikan jaringan nyata)",
                f"temuan netmon: {[t['tipe'] for t in temuan]}",
            ],
        }
    finally:
        klien.close()
        listener.close()


def _skenario_fim(runner):
    """R-FIM-TAMPER (T1565.001): baseline FIM → tamper → terdeteksi."""
    with tempfile.TemporaryDirectory() as d:
        for nama, isi in (("a.txt", "alpha"), ("b.txt", "beta"),
                          ("c.txt", "gamma")):
            with open(os.path.join(d, nama), "w", encoding="utf-8") as f:
                f.write(isi)
        cfg = {"fim_dir": d, "fim_baseline": None}
        baseline = kumpul_fim(cfg)
        cfg["fim_baseline"] = baseline["baseline"]
        # tamper: ubah isi, tambah file baru, hapus satu
        with open(os.path.join(d, "b.txt"), "a", encoding="utf-8") as f:
            f.write("-DITAMPER")
        with open(os.path.join(d, "baru.txt"), "w",
                  encoding="utf-8") as f:
            f.write("file baru")
        os.remove(os.path.join(d, "c.txt"))
        hasil = kumpul_fim(cfg)
        detected = (bool(hasil["berubah"]) and bool(hasil["baru"])
                    and bool(hasil["hilang"]))
        return {
            "nama": "R-FIM-TAMPER", "mitre": "T1565.001",
            "kontrol": "fim", "detected": detected,
            "evidence": [
                f"baseline {baseline['n']} file di {d}",
                f"berubah: {[os.path.basename(p) for p in hasil['berubah']]}",
                f"baru: {[os.path.basename(p) for p in hasil['baru']]}",
                f"hilang: {[os.path.basename(p) for p in hasil['hilang']]}",
            ],
        }


def _skenario_privilege(runner):
    """R-PRIVILEGE (T1078): RBAC controller menolak non-admin."""
    with tempfile.TemporaryDirectory() as d:
        operators_path = os.path.join(d, "operators.json")
        devices_path = os.path.join(d, "devices.json")
        events_path = os.path.join(d, "events.jsonl")
        audit_path = os.path.join(d, "audit.jsonl")
        reg = DeviceRegistry(devices_path, audit_path)
        dev_id = reg.enroll("range-fim-01", "operator")["id"]
        ops = OperatorStore(operators_path, audit_path, iterasi=1000)
        ops.add_user("admin-lab", "kunci-admin-lab", "admin")
        ops.add_user("op-lab", "kunci-op-lab", "operator")
        ctrl = RangeController(reg, ops, events_path, audit_path)
        ditolak = False
        try:
            ctrl.beri_tugas("operator", dev_id, "fim", {"fim_dir": d})
        except PermissionError:
            ditolak = True
        admin_ok = ctrl.beri_tugas("admin", dev_id, "fim",
                                   {"fim_dir": d})
        # verifikasi audit TUGAS_DITOLAK benar-benar tercatat
        tolak_tercatat = False
        if os.path.exists(audit_path):
            with open(audit_path, encoding="utf-8") as f:
                for baris in f:
                    if "TUGAS_DITOLAK" in baris:
                        tolak_tercatat = True
                        break
        detected = ditolak and admin_ok is not None and tolak_tercatat
        return {
            "nama": "R-PRIVILEGE", "mitre": "T1078",
            "kontrol": "rbac", "detected": detected,
            "evidence": [
                f"non-admin beri_tugas → PermissionError: {ditolak}",
                f"audit TUGAS_DITOLAK tercatat: {tolak_tercatat}",
                f"admin beri_tugas OK: {admin_ok['tugas_id']}",
            ],
        }


KATALOG = [
    {"nama": "R-RECON", "mitre": "T1046", "kontrol": "netmon_port_scan",
     "deskripsi": "Pemindaian port loopback nyata; deteksi netmon port_scan.",
     "fungsi": _skenario_recon},
    {"nama": "R-C2-BEACON", "mitre": "T1071", "kontrol": "netmon_beacon",
     "deskripsi": "Beacon interval teratur ke listener loopback; "
                  "deteksi netmon beacon.",
     "fungsi": _skenario_c2},
    {"nama": "R-FIM-TAMPER", "mitre": "T1565.001", "kontrol": "fim",
     "deskripsi": "Tamper file di direktori uji FIM; deteksi "
                  "range_agent.kumpul_fim.",
     "fungsi": _skenario_fim},
    {"nama": "R-PRIVILEGE", "mitre": "T1078", "kontrol": "rbac",
     "deskripsi": "Operator non-admin mencoba memberi tugas; RBAC "
                  "controller harus menolak.",
     "fungsi": _skenario_privilege},
]


# ------------------------------------------------------------
# Runner
# ------------------------------------------------------------
class ScenarioRunner:
    """Eksekusi skenario berlabel dengan scope check + audit + coverage."""

    def __init__(self, scope_path, events_path, audit_path,
                 rollback_cmd=None, target=TARGET_DEFAULT):
        self.guard = ScopeGuard(scope_path)
        self.events = forensics.EventStore(events_path)
        self.audit = audit_core.AuditLog(audit_path)
        self.rollback_cmd = rollback_cmd
        self.target = target
        self.hasil = []

    def _tolak(self, s):
        self.audit.append("range", "SKENARIO_DITOLAK",
                          f"{s['nama']} target {self.target} di luar scope")
        return {"nama": s["nama"], "mitre": s["mitre"],
                "kontrol": s["kontrol"], "status": "DITOLAK_SCOPE",
                "detected": False, "evidence": [
                    f"target {self.target} di luar scope "
                    f"{self.guard.path}"]}

    def jalankan(self, nama=None):
        """Jalankan (subset) katalog → laporan dict dengan coverage."""
        daftar = [s for s in KATALOG
                  if nama is None or s["nama"] == nama]
        if nama is not None and not daftar:
            raise ValueError(f"skenario tidak dikenal: {nama}")
        hasil = []
        for s in daftar:
            if not self.guard.in_scope(self.target):
                hasil.append(self._tolak(s))
                continue
            self.audit.append("range", "SKENARIO_MULAI",
                              f"{s['nama']} ({s['mitre']}) target "
                              f"{self.target}")
            res = s["fungsi"](self)
            res["status"] = "SELESAI"
            self.events.append(forensics.normalize(
                "redsim", f"skenario {res['nama']}",
                json.dumps({"mitre": res["mitre"],
                            "kontrol": res["kontrol"],
                            "detected": res["detected"]}),
                host=HOST_EVENT))
            self.audit.append("range", "SKENARIO_SELESAI",
                              f"{res['nama']} detected={res['detected']}")
            hasil.append(res)
        self.hasil = hasil
        return self._laporan()

    def _coverage(self):
        cov = {}
        for h in self.hasil:
            if h.get("status") != "SELESAI":
                continue
            c = cov.setdefault(h["kontrol"],
                               {"n": 0, "n_detected": 0,
                                "skenario": []})
            c["n"] += 1
            c["skenario"].append(h["nama"])
            if h["detected"]:
                c["n_detected"] += 1
        return cov

    def _laporan(self):
        n_run = sum(1 for h in self.hasil if h.get("status") == "SELESAI")
        n_det = sum(1 for h in self.hasil if h.get("detected"))
        return {
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target,
            "n_skenario": len(self.hasil),
            "n_dijalankan": n_run,
            "n_terdeteksi": n_det,
            "detection_rate": round(n_det / n_run, 3) if n_run else None,
            "skenario": self.hasil,
            "coverage": self._coverage(),
            "rollback": {"status": "NOT RUN",
                         "cmd": self.rollback_cmd,
                         "catatan": "rollback VM snapshot adalah langkah "
                                    "manual owner di hipervisor; modul "
                                    "ini hanya mencatat, tidak "
                                    "mengeksekusi"},
        }


def render_teks(lap):
    baris = [f"== RANGE SCENARIOS {lap['ts']} ==",
             f"target  : {lap['target']}",
             f"jalankan: {lap['n_dijalankan']}/{lap['n_skenario']} "
             f"terdeteksi {lap['n_terdeteksi']}",
             f"detection_rate: {lap['detection_rate']}", ""]
    for h in lap["skenario"]:
        baris.append(f"[{h['status']}] {h['nama']} ({h['mitre']}) "
                      f"kontrol={h['kontrol']} "
                      f"detected={h['detected']}")
        for e in h["evidence"]:
            baris.append(f"    - {e}")
    baris.append("")
    baris.append("coverage per kontrol:")
    for k, c in sorted(lap["coverage"].items()):
        baris.append(f"    {k}: {c['n_detected']}/{c['n']} "
                     f"skenario={c['skenario']}")
    baris.append(f"rollback: {lap['rollback']['status']} "
                 f"({lap['rollback']['catatan']})")
    return "\n".join(baris)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Scenario engine cyber range v3.0 (berscope, "
                    "loopback, coverage jujur)")
    p.add_argument("--scope", default="lab_scope.json",
                   help="file scope JSON (hosts+cidrs)")
    p.add_argument("--events", default="lab_events.jsonl")
    p.add_argument("--audit", default="lab_audit.jsonl")
    p.add_argument("--target", default=TARGET_DEFAULT,
                   help="target skenario (default 127.0.0.1 loopback)")
    p.add_argument("--skenario", default=None,
                   help="jalankan hanya satu skenario (nama R-*)")
    p.add_argument("--rollback-cmd", default=None,
                   help="perintah rollback DICATAT saja (NOT RUN)")
    p.add_argument("--json", action="store_true",
                   help="keluarkan laporan JSON")
    args = p.parse_args(argv)

    runner = ScenarioRunner(args.scope, args.events, args.audit,
                            rollback_cmd=args.rollback_cmd,
                            target=args.target)
    try:
        lap = runner.jalankan(args.skenario)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(lap, ensure_ascii=False, indent=2))
    else:
        print(render_teks(lap))
    if lap["n_dijalankan"] < lap["n_skenario"]:
        return 2                      # ditolak scope
    if lap["n_terdeteksi"] < lap["n_dijalankan"]:
        return 1                      # kontrol tidak menangkap
    return 0


if __name__ == "__main__":
    sys.exit(main())
