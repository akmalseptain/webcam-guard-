"""lab_status.py — Dashboard teks status laboratorium (STDLIB-ONLY).

Membaca artefak modul lain (read-only):
- lab_scope.json        : aset lab yang diotorisasi
- lab_events.jsonl      : event normalisasi (forensics, hash-chain)
- lab_audit.jsonl       : audit operasi istimewa (audit_core, hash-chain)
- cred_report.json      : hasil credcheck
- captures/             : file PCAP hasil capture
Integritas kedua rantai diverifikasi ulang setiap kali dashboard dibuka.
"""

import argparse
import json
import os

import audit_core
import forensics


def _muat_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def render(scope_path="lab_scope.json", events_path="lab_events.jsonl",
           audit_path="lab_audit.jsonl", cred_path="cred_report.json",
           captures_dir="captures", devices_path="devices.json",
           operators_path="operators.json"):
    # fallback: file konfigurasi scope juga dicari di sebelah modul ini
    if not os.path.exists(scope_path):
        kandidat = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.path.basename(scope_path))
        if os.path.exists(kandidat):
            scope_path = kandidat
    baris = []
    baris.append("=" * 64)
    baris.append(" LAB STATUS — Dashboard Laboratorium (read-only)")
    baris.append("=" * 64)

    # 1) aset lab
    scope = _muat_json(scope_path)
    if scope:
        baris.append(f" Aset diotorisasi : {', '.join(scope.get('hosts', []))} "
                     f"| CIDR {', '.join(scope.get('cidrs', []))}")
    else:
        baris.append(" Aset diotorisasi : (lab_scope.json tidak ada)")

    # 2) integritas event & audit
    store = forensics.EventStore(events_path)
    rusak_event = store.verify()
    n_event = len(store.load())
    audit = audit_core.AuditLog(audit_path)
    rusak_audit = audit.verify()
    n_audit = len(audit.entries())
    baris.append(f" Event  : {n_event:3d} — rantai "
                 f"{'UTUH ✓' if rusak_event is None else 'RUSAK di baris ' + str(rusak_event)}")
    baris.append(f" Audit  : {n_audit:3d} — rantai "
                 f"{'UTUH ✓' if rusak_audit is None else 'RUSAK di baris ' + str(rusak_audit)}")

    # 3) distribusi event
    if n_event:
        per_kind = {}
        per_host = {}
        for e in store.load():
            per_kind[e["kind"]] = per_kind.get(e["kind"], 0) + 1
            per_host[e["host"]] = per_host.get(e["host"], 0) + 1
        baris.append(" Event per jenis : " + ", ".join(
            f"{k}={v}" for k, v in sorted(per_kind.items())))
        baris.append(" Event per host  : " + ", ".join(
            f"{k}={v}" for k, v in sorted(per_host.items())))
        insiden = store.correlate()
        baris.append(f" Kandidat insiden (korelasi): {len(insiden)}")
        for g in insiden[:5]:
            baris.append(f"   [{g['host']}] {g['mulai']} -> {g['selesai']} "
                         f"({g['n_event']} event)")

    # 4) temuan credcheck
    cred = _muat_json(cred_path)
    if cred:
        r = cred.get("ringkasan", {})
        baris.append(f" Credcheck       : {r.get('total', '?')} temuan "
                     f"{r.get('per_severity', {})} | "
                     f"no-leak={r.get('no_secret_leak_verified', '?')}")
    else:
        baris.append(" Credcheck       : (belum dijalankan — python credcheck.py)")

    # 5) capture
    if os.path.isdir(captures_dir):
        files = sorted(os.listdir(captures_dir))
        total = sum(os.path.getsize(os.path.join(captures_dir, f))
                    for f in files)
        baris.append(f" Capture         : {len(files)} file, "
                     f"{total / 1024:.1f} KB di {captures_dir}/")
    else:
        baris.append(" Capture         : (folder captures/ belum ada)")

    # 6) range v3.0 — perangkat ter-enroll & operator (read-only JSON)
    devs = _muat_json(devices_path)
    if devs and isinstance(devs.get("devices"), dict):
        semua = devs["devices"]
        aktif = [d for d, r in semua.items() if not r.get("revoked")]
        lock = "AKTIF — semua perangkat ditolak" if devs.get("lockdown") \
            else "tidak"
        baris.append(f" Range devices  : {len(semua)} ter-enroll "
                     f"({len(aktif)} aktif) | lockdown: {lock}")
        rev = [d for d, r in semua.items() if r.get("revoked")]
        if rev:
            baris.append(f"   revoked       : {', '.join(sorted(rev))}")
    else:
        baris.append(" Range devices  : (belum ada — "
                     "python3 range_registry.py --enroll <nama>)")
    ops = _muat_json(operators_path)
    if ops and isinstance(ops.get("users"), dict):
        baris.append(f" Range operators : {len(ops['users'])} akun "
                     f"({', '.join(sorted(ops['users']))})")
    else:
        baris.append(" Range operators : (belum ada — "
                     "python3 range_controller.py --init-admin <pw>)")

    # 7) audit terakhir
    if n_audit:
        terakhir = audit.entries()[-3:]
        baris.append(" Audit terakhir:")
        for e in terakhir:
            baris.append(f"   {e['ts']} [{e['aktor']}] {e['aksi']} — {e['detail']}")

    baris.append("=" * 64)
    baris.append(" Catatan: dashboard read-only; seluruh data berasal dari "
                 "modul lab lokal.")
    return "\n".join(baris)


def main():
    ap = argparse.ArgumentParser(
        description="lab_status v3.0 (lab) — dashboard teks status lab "
                    "(+ baris range: devices/operators).")
    args = ap.parse_args()
    print(render())


if __name__ == "__main__":
    main()
