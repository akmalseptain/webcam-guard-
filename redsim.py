"""redsim.py — Emulasi adversary (red team) TERKUNCI SCOPE untuk lab.

KEAMANAN:
- Semua skenario memeriksa `lab_scope.json`; target di luar scope
  DITOLAK (REFUSED_OUT_OF_SCOPE) dan penolakan ter-audit.
- Tidak ada payload nyata: skenario mensimulasikan POLA (recon, beacon,
  persistensi, uji batas privilege) dan memvalidasi bahwa detektor lab
  (netmon/stealth_sim/audit_core) MENANGKAP pola tersebut.

Skenario (dengan pemetaan MITRE ATT&CK):
  S1 recon        T1046  : port scan simulasi -> netmon deteksi port_scan
  S2 beacon C2    T1071  : trafik beacon simulasi -> netmon deteksi beacon/port_c2
  S3 persistensi  T1547  : entri startup sintetis -> stealth_sim deteksi
  S4 privilege    T1078  : aksi tanpa otorisasi -> RBAC menolak + audit

Hasil skenario + event normalisasi ditulis ke lab_events.jsonl
(via forensics) dan operasi istimewa ke lab_audit.jsonl (via audit_core).
"""

import argparse
import ipaddress
import json
import os

import audit_core
import forensics
import netmon
import stealth_sim

SCOPE_FILE = "lab_scope.json"
EVENTS_FILE = "lab_events.jsonl"
AUDIT_FILE = "lab_audit.jsonl"


# ------------------------------------------------------------
# Scope guard — batas keras emulasi
# ------------------------------------------------------------
class ScopeError(Exception):
    pass


class ScopeGuard:
    """Muat scope (hosts + CIDR) dan validasi setiap target."""

    def __init__(self, path=SCOPE_FILE):
        self.path = path
        # fallback: bila tidak ada di CWD, cek di sebelah file modul ini
        if not os.path.exists(path):
            kandidat = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    os.path.basename(path))
            if os.path.exists(kandidat):
                self.path = kandidat
        with open(self.path, encoding="utf-8") as f:
            data = json.load(f)
        self.hosts = set(data.get("hosts", []))
        self.cidrs = [ipaddress.ip_network(c, strict=False)
                      for c in data.get("cidrs", [])]
        self.raw = data

    def in_scope(self, target):
        """True bila target host/IP berada dalam scope lab."""
        if target in self.hosts:
            return True
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return False
        return any(addr in net for net in self.cidrs)

    def assert_in_scope(self, target, aktor="operator"):
        """Raise ScopeError bila di luar scope + audit penolakan."""
        if self.in_scope(target):
            return True
        audit = audit_core.AuditLog(AUDIT_FILE)
        audit.append(aktor, "REFUSED_OUT_OF_SCOPE",
                     f"target {target} di luar lab_scope.json")
        raise ScopeError(
            f"DITOLAK: target '{target}' di luar scope lab yang diotorisasi")


# ------------------------------------------------------------
# Skenario
# ------------------------------------------------------------
class Skenario:
    nama = "?"
    mitre = "?"
    deskripsi = ""

    def __init__(self, guard, host="lab-01.local"):
        self.guard = guard
        self.host = host
        self.evidence = []

    def prerequisites(self):
        return {"scope_ok": self.guard.in_scope(self.host)}

    def execute(self):
        raise NotImplementedError

    def cleanup(self):
        """Skenario simulasi tidak menulis ke sistem — cleanup no-op jujur."""
        return "tidak ada artefak sistem yang ditulis (simulasi murni)"


class SkenarioRecon(Skenario):
    """S1 — T1046: simulasi pemindaian port di dalam scope."""
    nama = "S1-recon"
    mitre = "T1046"
    deskripsi = "Simulasi port scan terhadap host lab (pola T1046); " \
                "detektor netmon harus menandainya."

    def execute(self):
        self.guard.assert_in_scope(self.host, "redsim")
        target_ip = "192.168.56.99"
        self.guard.assert_in_scope(target_ip, "redsim")
        # bangun 12 paket SYN ke 12 port berbeda (pola scan)
        pkts = []
        for i, dport in enumerate(range(2000, 2012)):
            seg = netmon.build_tcp_seg(60000 + i, dport, b"", flags=0x02)
            frame = netmon.build_ethernet(
                "02:00:00:00:00:02", "02:00:00:00:00:01", 0x0800,
                netmon.build_ipv4("192.168.56.77", target_ip, 6, seg))
            pkts.append((1000.0 + i * 0.01, frame))
        ft = netmon.FlowTable()
        for p in pkts:
            meta = netmon.ekstrak_metadata(p)
            if meta:
                ft.add(meta)
        flows = ft.daftar()
        anomali = netmon.detect_anomalies(flows)
        self.evidence = [a["temuan"] for a in anomali]
        return {
            "status": "OK",
            "detected": any(a["tipe"] == "port_scan" for a in anomali),
            "deteksi": [a["tipe"] for a in anomali],
            "evidence": self.evidence,
        }


class SkenarioBeacon(Skenario):
    """S2 — T1071: pola C2 beaconing (interval reguler, port khas)."""
    nama = "S2-beacon"
    mitre = "T1071"
    deskripsi = "Simulasi beacon C2 (interval reguler + port 4444); " \
                "netmon harus menandai port_c2/beacon."

    def execute(self):
        c2_ip = "203.0.113.66"
        # catatan: C2 eksternal simulasi TIDAK di-scope-check (tidak ada
        # koneksi nyata); host lab yang memancarkan pola yang dijamin scope.
        self.guard.assert_in_scope(self.host, "redsim")
        pkts = []
        for i in range(10):
            seg = netmon.build_tcp_seg(33333, 4444, b"ping", seq=i + 1)
            frame = netmon.build_ethernet(
                "02:00:00:00:00:02", "02:00:00:00:00:01", 0x0800,
                netmon.build_ipv4("192.168.56.10", c2_ip, 6, seg))
            pkts.append((2000.0 + i * 10.0, frame))
        ft = netmon.FlowTable()
        for p in pkts:
            meta = netmon.ekstrak_metadata(p)
            if meta:
                ft.add(meta)
        flows = ft.daftar()
        anomali = netmon.detect_anomalies(flows)
        self.evidence = [a["temuan"] for a in anomali]
        return {
            "status": "OK",
            "detected": any(a["tipe"] in ("port_c2", "beacon")
                            for a in anomali),
            "deteksi": [a["tipe"] for a in anomali],
            "evidence": self.evidence,
        }


class SkenarioPersistensi(Skenario):
    """S3 — T1547: indikator persistensi startup (dataset sintetis)."""
    nama = "S3-persistensi"
    mitre = "T1547"
    deskripsi = "Simulasi entri startup otomatis (pola T1547); " \
                "stealth_sim harus mendeteksinya."

    def execute(self):
        self.guard.assert_in_scope(self.host, "redsim")
        entri = [
            {"nama": "evil_update.exe",
             "lokasi": "C:\\Users\\lab\\AppData\\Roaming\\Microsoft\\"
                       "Windows\\Start Menu\\Programs\\Startup\\evil.exe"},
            {"nama": "beacon_agent.desktop",
             "lokasi": "/home/lab/.config/autostart/beacon_agent.desktop"},
        ]
        # lolos ke detektor stealth (nama mengandung pola kunci)
        entri_deteksi = [
            {"nama": "keylog_svc.exe", "lokasi": "HKCU\\...\\Run"},
        ]
        temuan = stealth_sim.analisa_persistensi(entri + entri_deteksi)
        self.evidence = [t["temuan"] for t in temuan]
        return {
            "status": "OK",
            "detected": len(temuan) > 0,
            "deteksi": [t["sev"] for t in temuan],
            "evidence": self.evidence,
        }


class SkenarioPrivilege(Skenario):
    """S4 — T1078: coba aksi istimewa tanpa kredensial/role."""
    nama = "S4-privilege"
    mitre = "T1078"
    deskripsi = "Uji batas privilege: user tanpa role mencoba aksi admin; " \
                "RBAC harus MENOLAK dan audit mencatat."

    def execute(self):
        self.guard.assert_in_scope(self.host, "redsim")
        rbac = audit_core.RBAC()
        rbac.add_user("lab-admin", "Admin-Synth-1", "admin")
        rbac.add_user("lab-operator", "Op-Synth-1", "operator")
        rbac.add_user("lab-auditor", "Audit-Synth-1", "auditor")

        # auditor mencoba aksi istimewa 'jalankan_skenario'
        boleh = rbac.authorize("auditor", "jalankan_skenario")
        # viewer tidak dikenal mencoba 'kelola_pengguna'
        role_salah = rbac.authenticate("lab-auditor", "password-salah")
        audit = audit_core.AuditLog(AUDIT_FILE)
        audit.append("lab-auditor", "PRIV_TEST",
                     f"authorize(jalankan_skenario)={boleh}, "
                     f"auth-bad-pwd={'DENIED' if role_salah is None else 'OK'}")
        self.evidence = [
            f"auditor -> jalankan_skenario: "
            f"{'DIIZINKAN' if boleh else 'DITOLAK'}",
            f"login password salah: "
            f"{'DITOLAK' if role_salah is None else 'DIIZINKAN'}",
        ]
        # deteksi = kontrol BEKERJA (penolakan terjadi + audit utuh)
        kontrol_bekerja = (boleh is False) and (role_salah is None) \
            and (audit.verify() is None)
        return {
            "status": "OK",
            "detected": kontrol_bekerja,
            "deteksi": ["RBAC-deny", "audit-ok"] if kontrol_bekerja else [],
            "evidence": self.evidence,
        }


# ------------------------------------------------------------
# Runner
# ------------------------------------------------------------
class ScenarioRunner:
    def __init__(self, scope_path=SCOPE_FILE, events_path=EVENTS_FILE,
                 audit_path=AUDIT_FILE):
        self.guard = ScopeGuard(scope_path)
        self.events_path = events_path
        self.audit_path = audit_path
        self.skenario = [
            SkenarioRecon(self.guard),
            SkenarioBeacon(self.guard),
            SkenarioPersistensi(self.guard),
            SkenarioPrivilege(self.guard),
        ]

    def run(self, aktor="operator"):
        store = forensics.EventStore(self.events_path)
        audit = audit_core.AuditLog(self.audit_path)
        hasil = []
        for s in self.skenario:
            prasyarat = s.prerequisites()
            if not prasyarat["scope_ok"]:
                audit.append(aktor, "SKENARIO_SKIP",
                             f"{s.nama}: prasyarat scope gagal")
                hasil.append({"skenario": s.nama, "mitre": s.mitre,
                              "status": "SKIP", "detected": False})
                continue
            audit.append(aktor, "SKENARIO_MULAI", s.nama)
            r = s.execute()
            cleanup = s.cleanup()
            audit.append(aktor, "SKENARIO_SELESAI",
                         f"{s.nama}: detected={r['detected']}")
            baris = {
                "skenario": s.nama, "mitre": s.mitre,
                "status": r["status"], "detected": r["detected"],
                "deteksi": r["deteksi"], "evidence": r["evidence"],
                "cleanup": cleanup,
            }
            hasil.append(baris)
            event = forensics.normalize(
                "redsim", f"skenario {s.nama} ({s.mitre})",
                f"detected={r['detected']}; {'; '.join(r['deteksi'])}",
                host=self.guard.hosts and sorted(self.guard.hosts)[0] or "lab")
            store.append(event)
        n_det = sum(1 for h in hasil if h["detected"])
        return {
            "hasil": hasil,
            "n_run": len(hasil),
            "n_detected": n_det,
            "detection_rate": round(n_det / max(1, len(hasil)), 2),
            "integritas_audit": audit.verify() is None,
        }


def main():
    ap = argparse.ArgumentParser(
        description="redsim v1.3 (lab) — emulasi adversary TERKUNCI scope "
                    "(recon/beacon/persistensi/privilege, MITRE ATT&CK).")
    ap.add_argument("--scope", default=SCOPE_FILE)
    ap.add_argument("--events", default=EVENTS_FILE)
    ap.add_argument("--audit", default=AUDIT_FILE)
    args = ap.parse_args()

    runner = ScenarioRunner(args.scope, args.events, args.audit)
    try:
        laporan = runner.run()
    except ScopeError as e:
        print(f"[redsim] {e}")
        return

    print("=" * 62)
    print(" RED SIM — Hasil Emulasi (scope-enforced)")
    print("=" * 62)
    for h in laporan["hasil"]:
        status = "TERDETEKSI ✓" if h["detected"] else "TIDAK terdeteksi ✗"
        print(f"  {h['skenario']:<16} [{h['mitre']}] {status}")
        for ev in h["evidence"][:3]:
            print(f"      - {ev}")
    print(f"  Skenario jalan : {laporan['n_run']}")
    print(f"  Terdeteksi     : {laporan['n_detected']}"
          f" (detection_rate={laporan['detection_rate']})")
    print(f"  Audit utuh     : {laporan['integritas_audit']}")
    print("=" * 62)
    print(f"  Event -> {args.events} | Audit -> {args.audit}")


if __name__ == "__main__":
    main()
