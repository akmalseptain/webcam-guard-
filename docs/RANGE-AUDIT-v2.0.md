# RANGE-AUDIT v2.0 — Audit Baseline sebelum Upgrade Cyber Range (v3.0)

> Catatan jujur: dokumen audit asli hilang pada insiden reset
> lingkungan kerja (env ke-9/ke-10); dokumen ini ditulis ulang dari
> catatan audit yang tersimpan di knowledge. Temuan inti
> (B-01..B-10) dan pemetaan kapabilitas tidak berubah.

## Metode

Audit dilakukan atas `main` @ `53402d2` (v2.0, 204/204 test hijau)
dengan baseline terverifikasi ulang: compileall OK, fuzz seed 42 & 7
crash=0, posture 93.8 (exit 0), netmon precision=1.0 recall=0.75,
redsim out-of-scope exit 2. Pemetaan 20 kapabilitas master prompt vs
kode nyata:

**Sudah ada (v2.0):** credential testing sintetis (credcheck), PCAP
offline + live scope-checked (netmon), deteksi anomali explainable +
evaluasi berlabel, emulasi red team scope-enforced (redsim), forensik +
audit hash-chain, posture engine, evidence pack, privacy guard,
fuzz lab, CI gate.

**TIDAK ada (gap utama):** device enrollment & identitas kriptografis,
lab controller ter-autentikasi, endpoint agent (inventory proses/
koneksi/FIM/privilege), inspeksi sertifikat TLS, ukur kualitas capture
(loss/reorder), korelasi DNS↔flow, jalur C2 network nyata, hook
rollback VM, dan laporan perbandingan before/after.

## Temuan B-01..B-10

| ID | Temuan | Severity | Status |
|---|---|---|---|
| B-01 | Matriks IZIN RBAC (`audit_core`) tidak dipakai runtime mana pun | Tinggi (desain) | **DITUTUP v3.0** — `range_controller` whitelist perintah per-jenis klien (device: HELLO/HEARTBEAT/POLL/HASIL; operator: TUGAS admin-only / LIHAT) benar-benar dieksekusi + audit; teruji 42 test |
| B-02 | RBAC in-memory, tidak persisten antar-proses | Tinggi | **DITUTUP v3.0** — `OperatorStore` (operators.json, hash PBKDF2 200k, 0600, persisten; teruji) |
| B-03 | Jalur legacy token HMAC (mirror_auth) masih aktif tanpa password operator | Sedang | **DITUTUP v3.0** — jalur controller baru memakai OperatorStore PBKDF2; jalur mirror v1.2 tetap ada sebagai fitur terpisah (consent SETUJU + pin SHA-256 wajib + lockout), risikonya dibatasi & didokumentasikan |
| B-04 | `lab_status.py` basi — tidak menampilkan status range | Sedang | **DIPERBAIKI v3.0** — baris Range devices/operators + lockdown |
| B-05 | README v2.0 salah klaim "15 file test" (faktual 13) | Ringan (dokumentasi) | **DIPERBAIKI v3.0** — README v3.0 memakai angka aktual (18 file, 345 test) |
| B-06 | Tidak ada identitas perangkat / enrollment kriptografis | Tinggi (gap) | **DITUTUP R1** — `range_registry` (kunci 256-bit, devices.json 0600, revoke, lockdown, anti-replay nonce+ts, MAC HMAC; 31 test) |
| B-07 | Tidak ada controller/agent — endpoint visibility nihil | Tinggi (gap) | **DITUTUP R2** — `range_controller` + `range_agent` (whitelist tugas read-only, FIM, inventory /proc, heartbeat; 42 test) |
| B-08 | `Screenshot_20261018-120829.jpg` (±719 KB) masih ter-commit di repo | Ringan (hygiene) | **DITUTUP v3.0** — dihapus dari repo dengan persetujuan owner (2026-10-18) |
| B-09 | `flock` POSIX-only; Windows belum diuji | Sedang (portabilitas) | **TERBUKA** — didokumentasikan (README roadmap) |
| B-10 | `pip-audit`/SBOM tidak dijalankan (sandbox tanpa pip/network) | Sedang (supply chain) | **TERBUKA** — manual di laptop owner; posture P-15 jujur melaporkan NOT RUN |

## Rencana implementasi (dengan kriteria penerimaan)

- **R1 Enrollment** — `range_registry.py`: enroll/revoke/lockdown,
  identitas 256-bit, anti-replay; kriteria: ≥20 test. → HASIL: 31 test.
- **R2 Controller + Agent** — TCP stdlib, RBAC persisten (PBKDF2),
  whitelist tugas, FIM, inventory proses/koneksi/privilege, heartbeat;
  kriteria: ≥40 test. → HASIL: 42 test.
- **R3 Ekstensi netmon** — inspeksi sertifikat TLS (fingerprint
  SHA-256 + metadata), ukur kualitas capture (duplikat/reorder/gap),
  korelasi DNS↔SNI/Host; kriteria: ≥15 test. → HASIL: 25 test.
- **R4 Scenario engine** — katalog R-RECON/R-C2-BEACON/R-FIM-TAMPER/
  R-PRIVILEGE (T1046/T1071/T1565.001/T1078), scope-enforced, coverage
  report, hook rollback VM (hanya dicatat, NOT RUN — jujur); kriteria:
  ≥15 test. → HASIL: 24 test.
- **R5 Laporan before/after** — `range_report.py` (§7 master prompt,
  kriteria K1..K5 terukur); kriteria: struktur laporan + acceptance
  teruji. → HASIL: 19 test.
- **R6 Integrasi** — README v3.0, lab_status baris range, .gitignore
  (devices.json/operators.json), ci.yml (compile 20 modul + smoke
  range), docs RANGE-SECURITY/RANGE-AUDIT/RANGE-REPORT, fixture
  `tests/scope_loopback.json` untuk CI. → HASIL: verifikasi penuh.

Semua angka hasil berasal dari eksekusi nyata (lihat
`docs/RANGE-REPORT-v3.0.md`): **345/345 unittest OK** (204 baseline +
141 range), posture 93.8 tanpa bloker, netmon P=1.0/R=0.75, skenario
fixture loopback 4/4 terdeteksi (detection_rate 1.0), scope produksi
0/4 DITOLAK.
