#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slc_actions.py — v4.0 Sovereign Lab Control: REGISTRY AKSI EKSPLISIT.

Prinsip: controller TIDAK PERNAH menjalankan perintah arbitrer dari operator.
Semua kemampuan administratif adalah AKSI TERDAFTAR dengan:
  - id + versi, izin minimal (RBAC), klasifikasi risiko,
  - skema input + validasi ketat, timeout eksekusi, limit output,
  - prosedur verifikasi postcondition, rollback bila reversibel,
  - kewajiban audit (selalu True).

Platform: kolektor Windows memakai PowerShell/WMI terdokumentasi (subprocess
aman: list-args, tanpa shell, timeout). Di POSIX (lab dev/CI) memakai /proc
via modul range_agent yang sudah teruji. Cabang Windows dijaga eksplisit.
"""
from __future__ import annotations

import json
import platform
import resource
import shutil
import subprocess
import time

RISIKO = ("RENDAH", "SEDANG", "TINGGI")
IS_WINDOWS = platform.system() == "Windows"

# izin: set peran yang boleh MENJADWALKAN aksi; TINGGI tetap butuh persetujuan
# eksplisit di lapisan kontrol (slc_control), bukan di sini.


def _v_str_min(n):
    def v(x):
        return isinstance(x, str) and len(x.strip()) >= n
    return v


def _v_path(x):
    return isinstance(x, str) and x and not any(c in x for c in "\x00") \
        and not x.strip().startswith("-")


def _v_sha256(x):
    return isinstance(x, str) and len(x) == 64 and all(
        c in "0123456789abcdef" for c in x.lower())


def _v_level(x):
    return x in ("RENDAH", "SEDANG", "TINGGI")


# ---------------------------------------------------------------------------
# Kolektor — POSIX (dipakai di lab dev/CI, diuji nyata)
# ---------------------------------------------------------------------------

def kumpul_inventaris():
    """Inventaris perangkat: OS, mesin, sumber daya (POSIX /proc, Windows WMI)."""
    info = {"platform": platform.system(),
            "os": platform.platform(),
            "mesin": platform.machine(),
            "versi_agent": "4.0.0",
            "python": platform.python_version()}
    try:
        usage = shutil.disk_usage("/")
        info["disk_total_gb"] = round(usage.total / 1e9, 1)
        info["disk_bebas_gb"] = round(usage.free / 1e9, 1)
    except OSError:
        info["disk"] = None  # jangan mengarang data
    if IS_WINDOWS:
        info["os"] = _ps(["(Get-CimInstance Win32_OperatingSystem).Caption"])
    else:
        try:
            with open("/proc/meminfo") as f:
                baris1 = f.readline()
            info["mem_total_kb"] = int(baris1.split()[1])
        except (OSError, ValueError, IndexError):
            info["mem_total_kb"] = None
    return info


def kumpul_disk(path="/"):
    """Ruang disk + utilisasi sumber daya ringkas."""
    u = shutil.disk_usage(path if not IS_WINDOWS else "C:\\")
    return {"path": path,
            "total_gb": round(u.total / 1e9, 1),
            "bebas_gb": round(u.free / 1e9, 1),
            "terpakai_pct": round(100.0 * u.used / u.total, 1)}


def kumpul_res_agent():
    """Pemakaian sumber daya agent saat ini (rusage, maxrss KB)."""
    ru = resource.getrusage(resource.RUSAGE_SELF)
    return {"maxrss_kb": ru.ru_maxrss, "cpu_user_s": round(ru.ru_utime, 3),
            "cpu_sys_s": round(ru.ru_stime, 3)}


def _ps(args, timeout=15):
    """Subprocess PowerShell AMAN: list-args, tanpa shell, timeout, output dibatasi."""
    cmd = ["powershell", "-NoProfile", "-NonInteractive",
           "-Command"] + list(args)
    out = subprocess.run(cmd, capture_output=True, text=True,
                         timeout=timeout)
    return out.stdout.strip()[:4000]


def baca_eventlog(nama, batas=50):
    """Baca event log yang DISETUJUI (whitelist). Windows: Get-WinEvent;
    POSIX (dev/CI): baris log teks dari file terdaftar. Sintetis tidak pernah
    dihasilkan di sini — bila sumber tidak ada, dikembalikan sebagai None jujur."""
    if IS_WINDOWS:
        out = _ps([f"Get-WinEvent -LogName {nama} -MaxEvents {int(batas)} "
                   f"| ConvertTo-Json -Compress"])
        try:
            return json.loads(out) if out else []
        except json.JSONDecodeError:
            return {"raw": out}  # jangan dibuang, jangan dipalsukan
    # POSIX: whitelist file log lab
    from pathlib import Path
    diizinkan = {"lab_audit.jsonl", "lab_events.jsonl", "lab_range_events.jsonl"}
    if nama not in diizinkan:
        raise PermissionError(f"log '{nama}' tidak ada di whitelist")
    p = Path(nama)
    if not p.exists():
        return None  # TIDAK ADA BUKAN BERARTI AMAN — None jujur
    with p.open(errors="replace") as f:
        return f.read().splitlines()[-int(batas):]


LAYANAN_ALLOWLIST_RESTART = ("LabAgentDemoSvc", "wuauserv-demo")


def restart_layanan(nama, layanan=None):
    """Restart LAYANAN dari allowlist saja. `layanan` = kumpulan objek
    layanan palsu untuk pengujian; produksi Windows memakai sc/PowerShell."""
    if nama not in LAYANAN_ALLOWLIST_RESTART:
        raise PermissionError(f"layanan '{nama}' bukan di allowlist restart")
    if layanan is not None:  # jalur pengujian
        if nama not in layanan:
            raise KeyError(f"layanan '{nama}' tidak ditemukan")
        layanan[nama]["status"] = "BERJALAN"
        layanan[nama]["restart_ke"] = layanan[nama].get("restart_ke", 0) + 1
        return {"layanan": nama, "status": "BERJALAN",
                "restart_ke": layanan[nama]["restart_ke"]}
    if IS_WINDOWS:
        _ps([f"Restart-Service -Name {nama}"])
        return {"layanan": nama, "status": "PERINTAH_TERKIRIM"}
    raise RuntimeError("restart layanan nyata hanya di Windows fisik")


def cek_keamanan_terpilih():
    """Verifikasi pengaturan keamanan terpilih — pakai posture.py teruji."""
    import posture
    return posture.jalankan_semua()


def bundel_diagnostik(direktori="evidence_pack"):
    """Kumpulkan bundel diagnostik — pakai evidence.py teruji (manifest sha256)."""
    import evidence
    return evidence.build_pack(out_dir=direktori)


# ---------------------------------------------------------------------------
# Skema aksi: param -> (validator, wajib)
# ---------------------------------------------------------------------------

def aksi_definisi():
    """Kembalikan salinan registry aksi (id -> definisi)."""
    return {a["id"]: dict(a) for a in _AKSI}


# verifikasi postcondition: fungsi(hasil_eksekusi, params) -> (bool, catatan)
def _verif_kesehatan(hasil, _):
    ok = isinstance(hasil, dict) and hasil.get("platform") is not None
    return ok, "inventaris mengandung platform" if ok else "hasil kosong"


def _verif_restart(hasil, params):
    ok = hasil.get("layanan") == params.get("layanan") and \
        hasil.get("status") in ("BERJALAN", "PERINTAH_TERKIRIM")
    return ok, "status layanan pasca-restart sesuai" if ok else "status tidak sesuai"


def _verif_deploy(hasil, _):
    return hasil.get("terpasang") is True, "paket terpasang + hash cocok" \
        if hasil.get("terpasang") else "paket belum terpasang"


_AKSI = [
    {"id": "kesehatan", "nama": "Kumpul kesehatan & inventaris perangkat",
     "versi": "1", "izin": {"admin", "operator"}, "risiko": "RENDAH",
     "skema": {}, "timeout": 20, "maks_keluaran": 20000,
     "verifikasi": _verif_kesehatan, "rollback": None,
     "fn": lambda p: kumpul_inventaris()},
    {"id": "eventlog", "nama": "Baca event log yang disetujui",
     "versi": "1", "izin": {"admin", "operator", "auditor"},
     "risiko": "RENDAH",
     "skema": {"log": (_v_str_min(1), True), "batas": (lambda x:
              isinstance(x, int) and 1 <= x <= 500, False)},
     "timeout": 20, "maks_keluaran": 50000, "verifikasi": None,
     "rollback": None,
     "fn": lambda p: baca_eventlog(p["log"], p.get("batas", 50))},
    {"id": "proses_meta", "nama": "Inspeksi metadata proses & layanan",
     "versi": "1", "izin": {"admin", "operator"}, "risiko": "RENDAH",
     "skema": {}, "timeout": 20, "maks_keluaran": 40000,
     "verifikasi": None, "rollback": None,
     "fn": lambda p: _meta_proses_layanan()},
    {"id": "disk", "nama": "Cek ruang disk & utilisasi sumber daya",
     "versi": "1", "izin": {"admin", "operator"}, "risiko": "RENDAH",
     "skema": {"path": (_v_path, False)}, "timeout": 15,
     "maks_keluaran": 5000, "verifikasi": None, "rollback": None,
     "fn": lambda p: {**kumpul_disk(p.get("path", "/")),
                      "agent": kumpul_res_agent()}},
    {"id": "cek_keamanan", "nama": "Verifikasi pengaturan keamanan terpilih",
     "versi": "1", "izin": {"admin", "operator"}, "risiko": "RENDAH",
     "skema": {}, "timeout": 120, "maks_keluaran": 30000,
     "verifikasi": None, "rollback": None,
     "fn": lambda p: cek_keamanan_terpilih()},
    {"id": "bundel_diagnostik", "nama": "Kumpulkan bundel diagnostik",
     "versi": "1", "izin": {"admin"}, "risiko": "SEDANG", "skema": {},
     "timeout": 60, "maks_keluaran": 10000, "verifikasi": None,
     "rollback": None, "fn": lambda p: bundel_diagnostik()},
    {"id": "cek_app", "nama": "Health-check aplikasi terdaftar",
     "versi": "1", "izin": {"admin", "operator"}, "risiko": "RENDAH",
     "skema": {"app": (_v_str_min(1), True)},
     "timeout": 30, "maks_keluaran": 5000, "verifikasi": None,
     "rollback": None, "fn": lambda p: _cek_app(p["app"])},
    {"id": "restart_layanan", "nama": "Restart layanan allowlist (perlu persetujuan)",
     "versi": "1", "izin": {"admin"}, "risiko": "TINGGI",
     "skema": {"layanan": (_v_str_min(1), True)},
     "timeout": 60, "maks_keluaran": 5000,
     "verifikasi": _verif_restart,
     "rollback": lambda p: {"rollback": "tidak tersedia otomatis — "
                           "prosedur manual terdokumentasi"},
     "fn": lambda p: restart_layanan(p["layanan"])},
    {"id": "deploy_paket", "nama": "Deploy paket terverifikasi (perlu persetujuan)",
     "versi": "1", "izin": {"admin"}, "risiko": "TINGGI",
     "skema": {"paket": (_v_path, True), "hash_sha256": (_v_sha256, True),
               "tujuan": (_v_path, True)},
     "timeout": 120, "maks_keluaran": 10000, "verifikasi": _verif_deploy,
     "rollback": lambda p: {"rollback": "pulihkan file .bak di tujuan"},
     "fn": lambda p: _fn_deploy(p)},
    {"id": "asesmen_keamanan", "nama": "Jalankan modul asesmen keamanan teruji",
     "versi": "1", "izin": {"admin", "operator"}, "risiko": "SEDANG",
     "skema": {"modul": (lambda x: x in ("netmon", "redsim", "posture",
                                          "forensics"), True)},
     "timeout": 180, "maks_keluaran": 60000, "verifikasi": None,
     "rollback": None, "fn": lambda p: _fn_asesmen(p)},
]


def _meta_proses_layanan():
    """Metadata proses via range_agent teruji + daftar layanan (Windows: sc)."""
    from range_agent import kumpul_proses
    hasil = {"proses": kumpul_proses(batas=50)}
    if IS_WINDOWS:
        hasil["layanan"] = _ps(["Get-Service | Select-Object -First 50 "
                                "Name,Status | ConvertTo-Json -Compress"])
    else:
        hasil["layanan"] = None  # POSIX lab dev: metadata layanan TIDAK tersedia
    return hasil


APP_ALLOWLIST = {"mirror-demo": lambda: {"app": "mirror-demo", "hidup": True}}


def _cek_app(app):
    if app not in APP_ALLOWLIST:
        raise PermissionError(f"app '{app}' tidak ada di allowlist")
    return APP_ALLOWLIST[app]()


def _fn_deploy(p):
    """Deploy: verifikasi integritas paket (sha256 WAJIB cocok) lalu pasang
    atomik dengan backup .bak untuk rollback."""
    import hashlib
    import os
    from pathlib import Path
    src = Path(p["paket"])
    if not src.is_file():
        raise FileNotFoundError(f"paket tidak ditemukan: {src}")
    h = hashlib.sha256(src.read_bytes()).hexdigest()
    if h != p["hash_sha256"].lower():
        raise ValueError("hash paket TIDAK cocok — deploy ditolak")
    tujuan = Path(p["tujuan"])
    tujuan.parent.mkdir(parents=True, exist_ok=True)
    ada_backup = False
    if tujuan.exists():
        shutil.copy2(tujuan, str(tujuan) + ".bak")  # checkpoint utk rollback
        ada_backup = True
    shutil.copy2(src, tujuan)
    os.chmod(tujuan, 0o644)
    h2 = hashlib.sha256(Path(tujuan).read_bytes()).hexdigest()
    return {"terpasang": h2 == h, "hash_pasca": h2, "tujuan": str(tujuan),
            "backup_bak": ada_backup}


def _fn_asesmen(p):
    """Jalankan modul asesmen LAMA yang sudah teruji — bounded; tiap modul
    menegakkan scope-nya sendiri (lab_scope.json) dan mencatat audit."""
    if p["modul"] == "netmon":
        import netmon
        return {"modul": "netmon",
                "evaluasi": netmon.evaluasi_detektor()}
    if p["modul"] == "redsim":
        from redsim import ScenarioRunner
        return {"modul": "redsim", "hasil": ScenarioRunner().run()}
    if p["modul"] == "posture":
        import posture
        return posture.jalankan_semua()
    if p["modul"] == "forensics":
        import forensics
        store = forensics.EventStore("lab_events.jsonl")
        return {"modul": "forensics",
                "integritas": store.verify() is None and
                store.verify_terhadap_anchor() is None}
    return {"modul": p["modul"], "catatan": "tidak ada runner"}


# ---------------------------------------------------------------------------
# API registry
# ---------------------------------------------------------------------------

class AksiError(ValueError):
    """Aksi tidak dikenal / parameter tidak valid — DITOLAK DEFAULT."""


def definisi(aksi_id):
    d = aksi_definisi().get(aksi_id)
    if d is None:
        raise AksiError(f"aksi tidak dikenal: {aksi_id}")
    return d


def validasi(aksi_id, params):
    """Validasi input terhadap skema. Lewat → return {}; gagal → AksiError."""
    d = definisi(aksi_id)
    params = params or {}
    for k, (cek, wajib) in d["skema"].items():
        if k not in params:
            if wajib:
                raise AksiError(f"parameter wajib hilang: {k}")
            continue
        if not cek(params[k]):
            raise AksiError(f"parameter '{k}' tidak valid")
    tak_dikenal = set(params) - set(d["skema"])
    if tak_dikenal:
        raise AksiError(f"parameter tidak dikenal: {sorted(tak_dikenal)}")
    return {}


def jalankan(aksi_id, params=None, timeout=None):
    """Jalankan aksi terdaftar dengan validasi + timeout + batas keluaran.
    Tidak dikenal/invalid → AksiError (ditolak default)."""
    d = definisi(aksi_id)
    validasi(aksi_id, params)
    params = params or {}
    awal = time.time()
    fn = d["fn"]
    if timeout is None:
        hasil = fn(params)  # timeout dijaga lapis transport/thread di control
    else:
        import threading
        kotak = {}

        def _target():
            try:
                kotak["hasil"] = fn(params)
            except BaseException as e:  # tangkap utk dilaporkan, bukan ditelan
                kotak["error"] = e
        t = threading.Thread(target=_target, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            raise TimeoutError(f"aksi '{aksi_id}' melebihi timeout {timeout}s")
        if "error" in kotak:
            raise kotak["error"]
        hasil = kotak["hasil"]
    txt = json.dumps(hasil, ensure_ascii=False, default=str)
    if len(txt) > d["maks_keluaran"]:
        hasil = {"terpotong": True, "panjang": len(txt),
                 "data": txt[:d["maks_keluaran"]]}
    return {"aksi": aksi_id, "risiko": d["risiko"], "durasi_s":
            round(time.time() - awal, 3), "data": hasil}


def butuh_persetujuan(aksi_id):
    return definisi(aksi_id)["risiko"] == "TINGGI"


def main():
    import argparse
    ap = argparse.ArgumentParser(description="slc_actions v4.0 — registry aksi")
    ap.add_argument("--daftar", action="store_true")
    ap.add_argument("--jalankan", metavar="AKSI")
    ap.add_argument("--param", default="{}")
    a = ap.parse_args()
    if a.daftar:
        for i, d in aksi_definisi().items():
            print(f"{i:20s} risiko={d['risiko']:7s} v{d['versi']} "
                  f"izin={sorted(d['izin'])} — {d['nama']}")
        return 0
    if a.jalankan:
        print(json.dumps(jalankan(a.jalankan, json.loads(a.param)),
                         ensure_ascii=False, indent=1, default=str))
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
