# SLC-ARCHITECTURE — v4.0 Sovereign Lab Control

Dokumen arsitektur upgrade v4.0 "Sovereign Lab Control" (SLC) di atas repo
WebCam Guard. Ini kelanjutan, bukan penggantian: seluruh modul v1.x–v3.0
(audit_core, forensics, netmon, posture, redsim, evidence, range_*) dipakai
ulang apa adanya dan dirangkai oleh modul `slc_*` baru.

## 1. Peta Modul

| Modul | Peran | Seksi prompt |
|---|---|---|
| `slc_control.py` | Control plane terpusat: enroll/revoke, grup/tag/policy, antrean tugas per-perangkat, idempotensi, kedaluwarsa, persetujuan TINGGI, emergency stop, audit tiap operasi admin | §1 |
| `slc_server.py` | Transport TCP (default 127.0.0.1:9443, TLS opsional): whitelist pesan `HEARTBEAT/POLL/HASIL/BYE`, HMAC+nonce via `range_registry` | §1, §2 |
| `slc_endpoint.py` | Agent endpoint: enrollment eksplisit, heartbeat backoff terbatas (0,5→30 s), graceful shutdown, limit memori, pasang paket dengan cek sha256, layanan Windows `SLCAgent` identitas jelas, TLS pin sha256 + CERT_REQUIRED | §2 |
| `slc_actions.py` | Action registry eksplisit 10 aksi (`kesehatan`, `eventlog`, `proses_meta`, `disk`, `cek_keamanan`, `bundel_diagnostik`, `cek_app`, `restart_layanan`, `deploy_paket`, `asesmen_keamanan`): skema input, timeout, limit keluaran, verifikasi postcondition, rollback metadata; tolak tak dikenal secara default | §3 |
| `slc_mission.py` | Mission engine: `REQUESTED → AUTHORIZATION_CHECK → PLANNED → APPROVAL → EXECUTING → VERIFYING → REPORTING`; APPROVAL hanya dilewati bila semua aksi RENDAH + persetujuan kebijakan; gelombang DAG paralel, retry terbatas, deadline, budget, checkpoint, verifikasi dependensi sukses (bukan sekadar exit 0), rollback, analisis kegagalan, laporan teks+JSON | §4 |
| `slc_events.py` | Event pipeline: normalisasi dengan label `ASAL` wajib (`telemetri`/`sintetis`/`replay`/`inferensi`), dedup, retensi, cari/filter, threshold alert, korelasi, perbandingan historis (`TIDAK_ADA_DATA` ≠ aman) | §5 |
| `slc_redblue.py` | Evaluasi RED/BLUE: matriks RB-01..RB-04 (T1046/T1071/T1547.001/T1078, semua sintetis) via `redsim.ScenarioRunner`; sisi BLUE via `netmon.evaluasi_detektor` (precision/recall/FPR); analisis FP; perbandingan konfigurasi baseline-improved (yang tak diukur TIDAK diklaim) | §6 |
| `slc_twin.py` | Digital twin: endpoint/layanan/dependensi (dependensi WAJIB bukti, asumsi dilabeli), temuan + confidence 0..1, sejarah, `what_if("matikan_layanan", ...)` → dampak/asumsi/informasi-kurang/usulan-uji | §7 |
| `slc_remediation.py` | Remediasi 12 langkah: temuan→bukti→proposal→risiko→inspeksi diff→tes→persetujuan→checkpoint→terapkan→verifikasi→rollback (bila tersedia)→catat; zona larangan (kebijakan keamanan/akun/firewall/konfigurasi kritis) butuh `recovery_plan` tertulis | §8 |
| `slc_ui.py` | Horror Command Center TUI: banner "SANG PENJAGA" yang SELALU menyatakan "administrasi jarak jauh — BUKAN tersembunyi", tombol EMERGENCY STOP, frame horor severity-driven, peta lab, grafik aktivitas, timeline, misi replay, investigasi insiden, dasbor; kontrol gerak-minim/bisu/mode-polos (aksesibilitas) | §9 |
| `slc_demo.py` | Mode DEMO: 3 perangkat sintetis berlabel `SINTETIS-DEMO (bukan perangkat nyata)`, misi inventaris end-to-end, `--evaluasi` menghasilkan laporan acceptance | §11, §12 |

## 2. Alur Pesan (mode FISIK)

```
Operator ──jadwalkan(aksi dari registry)──▶ SLCControl (antrean per-dev)
Controller (slc_server, :9443, TLS opsional) ◀──HEARTBEAT (HMAC+nonce)── Agent
Controller ──POLL (tugas utk dev ini, cek idempotensi/kedaluwarsa/emergency)──▶ Agent
Agent ──eksekusi (timeout, limit keluaran) + verifikasi postcondition──▶
Agent ──HASIL──▶ Controller (terima_hasil → audit + event pipeline)
Agent ──BYE (graceful shutdown)──▶
```

- Tiap pesan diverifikasi HMAC (`range_registry.verify_pesan`) dengan nonce —
  perangkat yang sekadar *reachable* di jaringan TIDAK dianggap berizin.
- Perintah di luar whitelist, nonce ulang, atau MAC salah → ditolak + diaudit.
- Emergency stop per-perangkat menghentikan pemberian tugas baru; batalkan
  tingkat operator membatalkan misi/misi-wide.

## 3. Batas Keamanan (security boundaries)

1. **Tolak default**: aksi tak terdaftar atau parameter tak lolos validasi
   skema ditolak; aksi RISIKO TINGGI (`restart_layanan`, `deploy_paket`)
   menunggu `setujui()` oleh admin.
2. **Idempotensi + kedaluwarsa**: tugas duplikat ditolak; tugas kedaluwarsa
   di-skip dan dicatat.
3. **Agent jujur**: `SLCAgent` memakai nama jelas, tidak menyamar komponen
   Windows, tidak menonaktifkan Defender/keamanan, tidak menghalangi
   uninstall (`CARA_INSTALL` terdokumentasi di modul & docs install).
4. **Integritas**: paket deploy dicek sha256; bukti (`evidence.build_pack`)
   ber-hash; audit log ber-hash berantai (`audit_core`).
5. **Tanpa stealth**: tidak ada AV-evasion/credential theft/persistensi
   senyap — selaras batasan §6 dan §10 prompt.
6. **Label data**: setiap event membawa `ASAL`; data DEMO selalu diberi label
   `SINTETIS-DEMO (bukan perangkat nyata)`; tidak ada perangkat/hasil/alert
   yang dipalsukan.

## 4. Integrasi modul lama (tanpa duplikasi)

| Modul lama | Dipakai oleh |
|---|---|
| `range_registry.DeviceRegistry` | identitas + HMAC device (slc_control/slc_server/slc_endpoint) |
| `range_controller.OperatorStore` | operator + RBAC controller |
| `audit_core.AuditLog/RBAC/RateLimiter` | audit semua operasi admin |
| `forensics.EventStore/normalize` | event pipeline & bukti |
| `posture.jalankan_semua()` | aksi `cek_keamanan` |
| `evidence.build_pack()` | aksi `bundel_diagnostik` + evaluasi RED |
| `netmon.evaluasi_detektor()` | sisi BLUE evaluasi |
| `redsim.ScenarioRunner/ScopeGuard` | sisi RED evaluasi + scope enforcement |

## 5. Riwayat perbaikan v4.0 pada kode lama

- `forensics.py`: `KINDS` ditambah `"slc"` (8→9) untuk event SLC.
- `tests/test_redsim.py`: dulu menimpa `redsim.AUDIT_FILE` global tanpa
  restore — bocor ke test lain (tmpdir sudah terhapus → FileNotFoundError).
  v4.0 menyimpan dan memulihkan nilai asli di `tearDown`.
- `slc_redblue.jalankan_red()`: meminjam `redsim.AUDIT_FILE` sementara agar
  seluruh jejak audit skenario jatuh ke `audit_path` yang diberikan, lalu
  dipulihkan (tahan bocoran state modul).

## 6. Angka terukur

- Test: **486 test, 483 lulus, 3 skip** (TLS pinning butuh sertifikat nyata —
  dijujurkan, tidak dipalsukan). 345 test warisan v1–v3 tetap hijau.
- Aksi registry: 10 aksi eksplisit; 2 berisiko TINGGI (butuh persetujuan).
- Skenario evaluasi RED: 4 (RB-01..RB-04), semua sintetis/ter-scope.

Detail install & demo: `docs/SLC-INSTALL-DEMO.md`.
Hasil acceptance: `docs/SLC-ACCEPTANCE-v4.0.md`.
