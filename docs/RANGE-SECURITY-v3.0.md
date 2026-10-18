# RANGE-SECURITY v3.0 — Desain Keamanan Cyber Range

Dokumen ini mendeskripsikan desain keamanan lapisan range v3.0:
`range_registry.py`, `range_controller.py`, `range_agent.py`,
`range_scenarios.py`, `range_report.py`, dan ekstensi `netmon.py`.

Prinsip proyek tetap: **stdlib-only**, semua eksplisit, semua diaudit,
tidak ada klaim tanpa test. Hanya untuk perangkat lab yang DI-ENROLL
DAN diotorisasi owner (`lab_scope.json` + `devices.json`).

## 1. Model ancaman & batas

Yang DIANCAM: (a) perangkat lab palsu mencoba masuk controller;
(b) operator tidak berwenang memberi tugas; (c) pesan di-replay atau
diubah di jalur; (d) agent dimanfaatkan jadi eksekutor arbitrer;
(e) skenario menyasar aset di luar lab.

Yang BUKAN tujuan (jujur): tahan terhadap adversary dengan akses root
di mesin agent (endpoint compromised = game over untuk host itu —
mitigasi adalah revoke + lockdown), dan enkripsi jalur controller
(TCP plaintext loopback; TLS/mTLS antar-2-host = kerja manual owner).

## 2. Identitas perangkat (range_registry)

- Enrollment menghasilkan `dev-XXXXXXXX` + **kunci rahasia 256-bit**
  (`secrets.token_hex(32)`), ditampilkan SEKALI saat enroll (out-of-band).
  `devices.json` (0600) menyimpan kunci + fingerprint SHA-256-nya;
  CLI `--list`/`daftar()` TIDAK pernah mencetak kunci.
- **Revoke darurat** per perangkat dan **lockdown global** (semua
  perangkat ditolak) — switch darurat operator; keduanya dipersist.
- **Anti-replay**: setiap pesan device membawa nonce sekali-pakai +
  timestamp dalam jendela ±60 dtk (`JENDELA_NONCE`); nonce yang sudah
  terlihat DITOLAK; nonce kedaluwarsa dibersihkan.
- **MAC HMAC-SHA256 kanonik** (`buat_mac`, `sort_keys=True`) atas
  id/nonce/ts/cmd/payload — payload dict urutan berbeda menghasilkan
  MAC sama (teruji), verifikasi pakai `hmac.compare_digest`.
- Urutan cek di `verify_pesan`: lockdown → enrolled → jendela waktu →
  nonce → MAC (kegagalan paling murah dicek dulu).
- `last_seen` TIDAK dipersist (in-memory) — keterbatasan yang
  diketahui dan jujur didokumentasikan; bukan klaim tracking.

## 3. Controller (range_controller)

- **OperatorStore**: akun operator persisten (`operators.json`, 0600),
  hash PBKDF2 200.000 iterasi (dalam batas 1.000–400.000 audit_core).
- **Anti-enumeration**: login ke user tak dikenal menjalankan PBKDF2
  dummy (waktu respons setara login valid) — keberadaan akun tidak
  membocorkan.
- **Whitelist perintah yang dieksekusi nyata** (menutup temuan audit
  B-01): perangkat HANYA `HELLO/HEARTBEAT/POLL/HASIL`; operator hanya
  `TUGAS` (admin) / `LIHAT` (semua peran). Perintah lain →
  `PERINTAH_DITOLAK`/`TUGAS_DITOLAK` di audit (teruji).
- **Rate limit login operator** (RateLimiter 10/60 dtk per username) —
  setelah itu password benar pun ditolak (teruji).
- **Antrean tugas FIFO per perangkat**; `POLL` mengonsumsi (pop) —
  tugas tidak bisa dijalankan dua kali; hasil → event hash-chain
  (`lab_events.jsonl`) dengan kind `process`.
- Server HANYA loopback (`127.0.0.1`) secara default; JSON malformed
  dijawab santun (`{"ok": false, "alasan": "JSON tidak valid"}`),
  tidak crash (teruji via socket nyata).

## 4. Agent (range_agent)

- **Read-only + whitelist**: tugas yang didukung HANYA
  `proses / pohon_proses / koneksi / fim / priv / health`
  (`TUGAS_JENIS`). TIDAK ada jalur eksekusi perintah arbitrer —
  `jalankan_tugas` raise ValueError untuk jenis lain (teruji).
- Sumber data: `/proc` (Linux) — inventori via `/proc/<pid>/stat`
  (parse aman terhadap kurung di nama proses), ps-tree via parent PID,
  koneksi via `/proc/net/tcp` (kolom 9 = **inode**, bukan PID —
  keterbatasan mapping koneksi→proses dijujuri di docstring & hasil),
  FIM = SHA-256 baseline vs kondisi kini pada direktori uji, priv =
  file SUID di path umum (dilabeli "bukan audit privilege penuh").
- **Tidak ada persistensi/service/autostart** — uninstalasi =
  hapus file agent + `--revoke` perangkat + hapus
  `devices.json`/`operators.json`.

## 5. Scenario engine (range_scenarios)

- **Scope validation SEBELUM eksekusi** (`redsim.ScopeGuard`):
  target di luar scope → `DITOLAK_SCOPE` + audit `SKENARIO_DITOLAK`,
  TIDAK ADA yang dieksekusi (lab_scope.json produksi → 0/4, exit 2;
  teruji). Kunci `--scope` eksplisit; fixture uji =
  `tests/scope_loopback.json` (127.0.0.1; JANGAN untuk produksi).
- Katalog: R-RECON (T1046, 12 koneksi loopback nyata → netmon
  port_scan), R-C2-BEACON (T1071, SATU koneksi persisten berkala
  interval teratur → netmon beacon; ambang `beacon_rata_min`
  DISESUAIKAN untuk loopback 50 ms dan DILAPORKAN JUJUR di evidence),
  R-FIM-TAMPER (T1565.001, ubah/tambah/hapus file → FIM), R-PRIVILEGE
  (T1078, non-admin beri tugas → PermissionError + audit TUGAS_DITOLAK;
  kontrol positif admin diizinkan).
- **Coverage report per kontrol** (n, n_detected) + `detection_rate`;
  exit code: 0 semua terdeteksi, 1 kontrol meleset, 2 ditolak scope,
  3 error — jujur dan eksplisit.
- **Rollback VM = hook yang HANYA DICATAT** (status NOT RUN):
  eksekusi snapshot/rollback adalah keputusan manual owner di
  hipervisor; modul ini tidak pernah meng-eksekusi mekanisme
  tersembunyi (master prompt §6 — tanpa persistensi covert, tanpa
  mekanisme mengalahkan kemampuan operator menghentikan uji).

## 6. Ekstensi netmon (R3)

- `inspeksi_sertifikat()`: fingerprint SHA-256 DER + metadata
  (subject/issuer/validitas) via `ssl._ssl._test_decode_cert` —
  guarded; error dilaporkan jujur ("bukan file PEM", "tidak bisa
  dibaca"), bukan pura-pura sukses. Diverifikasi terhadap cert nyata
  di bundle CA sistem (fingerprint dihitung independen oleh test).
- `ukur_kualitas()`: duplikat/reorder/gap + estimasi drop —
  DILABELI JUJUR "BUKAN pengukuran loss nyata" (tanpa akses tap);
  ambang gap bisa diatur.
- `korelasi_dns()`: DNS ↔ SNI/HTTP-Host (match/subdomain, jendela
  waktu, src sama/beda) — hanya korelasi metadata; dilabeli
  "bukan bukti sebab-akibat".

## 7. Laporan & pengukuran (range_report)

- Baseline v2.0 DIKUNCI di modul (204 test, posture 93.8,
  netmon P=1.0/R=0.75, tanpa scenario engine) dan dibandingkan dengan
  hasil ukur v3.0 **metode yang sama**.
- Kriteria penerimaan K1..K5 eksplisit (≥300 test, ≥100 test range,
  posture tanpa regresi, netmon tanpa regresi, detection_rate 1.0);
  ukuran yang tidak dijalankan dilaporkan **TIDAK DIUKUR**, bukan
  dipaksa lulus.
- Hasil nyata build ini: 5/5 LULUS — `docs/RANGE-REPORT-v3.0.md`
  (345 test, posture 93.8, netmon P=1.0/R=0.75, skenario 4/4).

## 8. Yang TIDAK diklaim (status NOT RUN / terbuka)

- TLS/mTLS handshake nyata antar-2 host untuk jalur controller —
  manual owner (jalur build ini TCP plaintext loopback).
- Fitur kamera OpenCV (cv2) — manual owner (sandbox tanpa display).
- `pip-audit` + SBOM (CycloneDX/SPDX) — manual owner (sandbox
  tanpa pip/network); posture P-15 jujur melaporkan NOT RUN.
- CI first-run di GitHub Actions — smoke range ditambahkan di ci.yml,
  run pertama tetap harus diverifikasi owner.
- `flock` di Windows — POSIX-only.
- Rollback VM / snapshot — hook dicatat, dieksekusi manual owner.
- Trafik VM nyata (192.168.56.0/24) — skenario build ini memakai
  loopback sebagai stand-in; uji VM = kerja manual owner
  (contoh konfigurasi scope: `tests/scope_loopback.json`).
