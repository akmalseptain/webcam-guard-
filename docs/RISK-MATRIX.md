# RISK-MATRIX v2.0 — Pemetaan Risiko → Kode → Test → Hasil → Sisa

> Format: setiap kebutuhan keamanan berprioritas tinggi dipetakan ke
> (1) ancaman/kegagalan, (2) jalur kode, (3) test otomatis, (4) hasil
> yang DIAWASI (observed), (5) batas yang tersisa. Cakupan baris ≠
> jaminan keamanan — baris TANPA test otomatis ditandai "MANUAL".

| # | Ancaman / kegagalan | Jalur kode | Test otomatis | Hasil (build ini) | Sisa risiko |
|---|---|---|---|---|---|
| R01 | Tulis konkuren merusak rantai audit | `audit_core._kunci_file` (flock) + `_entry_terakhir` tail | `test_audit_fixes` (2×30 thread ×60 append) | PASS — rantai utuh, seq 1..60 | Windows tanpa flock — MANUAL |
| R02 | Truncation log tak terdeteksi | `checkpoint()` + `verify_terhadap_anchor()` | `test_audit_fixes` + `test_posture` | PASS — "TERPANGKAS: 3 < 5" | Anchor di host sama bisa direkayasa penyerang penuh |
| R03 | Baris log dimodifikasi/diurut ulang/diduplikasi | hash-chain + seq | `test_audit_fixes` (reorder, duplikasi, posisi anchor) | PASS — terdeteksi | — |
| R04 | Baris malformed membuat verify crash | `AuditLog.verify` / `EventStore.verify` toleran | `test_audit_fixes` + `fuzz_lab` F2 | PASS — baris dilaporkan | — |
| R05 | Append membaca SELURUH file (DoS waktu) | `_entry_terakhir` tail-8192 | `test_audit_fixes` (append 500) | PASS | — |
| R06 | Anchor ditulis separuh (crash saat write) | `tulis_anchor_atomik` (temp+rename) | `test_audit_fixes` | PASS | — |
| R07 | PBKDF2 dilemahkan/dipompakan via parameter stored | `verify_password` validasi [1000, 400000] | `test_audit_fixes` + `fuzz_lab` F6b/c | PASS — ditolak <0.05ms | — |
| R08 | Brute force password | `RBAC.authenticate` + dummy-hash anti-enum | `test_audit_core` + `fuzz_lab` F6a | PASS | Lockout per-user tidak diuji (user-level, bukan IP) |
| R09 | Rate limit bisa di-reset penyerang | `RateLimiter.reset` hanya dipanggil internal | `test_audit_fixes` (hitung/reset) | PASS | reset() tidak dibatasi ACL — dipakai operator terpercaya |
| R10 | Brute force token mirroring | `MirrorServer._autentikasi` lockout per-IP 5/60s | `test_mirror_stream` + `fuzz_lab` F4 | PASS — token benar pun ditolak saat terkunci | IP-spoofing di luar model (lab LAN) |
| R11 | Lockout jadi DoS global | limiter per-key (IP) | `test_mirror_stream` + posture P-07 | PASS — IP lain bebas | — |
| R12 | Viewer menstop sesi global | `STOP_REQ` admin-only | `test_mirror_stream` + posture P-08 | PASS — STOP_DENIED | — |
| R13 | Klien klaim role admin | role dari `token_map` sisi server | `test_mirror_stream` (klaim admin + token viewer → viewer) | PASS | — |
| R14 | Token bisa dihitung dari kode pairing | `buat_token_acak` = secrets 256-bit | `test_mirror_stream` (64 hex, unik) | PASS | — |
| R15 | TLS MITM / cert self-signed dipercaya buta | viewer `--pin` wajib + verifikasi sebelum HELLO | posture P-09 (subprocess exit 2) + pin_cocok unit | PASS (behavioral) | Handshake TLS 2 host nyata + fingerprint cert NYATA — MANUAL |
| R16 | Payload raksasa wire → memori | `terima_payload` cap 10 MiB | `test_mirror_stream` + `fuzz_lab` F3a | PASS — ValueError | — |
| R17 | Klien lambat memblok semua penonton | writer thread + antrian bounded 4 | `test_mirror_stream` + kode di-review | PASS (desain) | Antrian penuh meng-DROP klien — didokumentasi |
| R18 | PCAP korup → crash/MemoryError | `baca_pcap` guard incl_len | `test_netmon` + `fuzz_lab` F1c + `test_fuzz_lab` | PASS — ValueError | — |
| R19 | Live capture tanpa otorisasi | `capture_live(setuju_scope)` + menu prompt y/T | CLI smoke (exit 3 tanpa confirm) | PASS | Kamera antarmuka nyata — MANUAL |
| R20 | Beacon polling wajar → false positive | beacon butuh cv≤0.25 + port tidak wajar; `PORT_WAJAR` | `test_audit_fixes` + posture P-10 | PASS — polling 8080 bersih | Beacon jitter tinggi = FN (recall 0.75) |
| R21 | Port mencurigakan dianggap bukti keras | bukti menulis "port saja TIDAK membuktikan" | `test_netmon` (temuan berisi bukti) | PASS | — |
| R22 | Target out-of-scope dijalankan | `redsim --target` + `ScopeGuard` | `test_redsim` + posture P-11 (exit 2) | PASS | Skenario default masih pakai host scope tetap |
| R23 | Secret bocor via bukti/laporan | `credcheck.mask` ketat + `no_secret_leak` | `test_credcheck` + posture P-12 | PASS | Hanya pola dikenal; format baru bisa lolos |
| R24 | Rekaman menumpuk tanpa batas / dibaca orang lain | `privacy.bersihkan` umur+kuota, `perketatizin` 0600 | `test_privacy` + posture P-13 | PASS | Tidak ada enkripsi at-rest |
| R25 | Blur gagal → wajah tetap tampil | `keputusan_frame_blur` fail-closed | `test_privacy` + posture P-13 | PASS — TOLAK_FRAME | Deteksi wajah nyata (cv2) — MANUAL |
| R26 | Bukti dirapikan diam-diam saat verify | `evidence.verify_pack` read-only | `test_evidence` (hash snapshot) + posture P-16 | PASS | — |
| R27 | Paket bukti dimodifikasi pasca-ekspor | manifest SHA-256 + kelas raw/derived | `test_evidence` (tamper) | PASS | Manifest tidak bertanda tangan kunci |
| R28 | Dependensi pihak ketiga rentan | `requirements.txt` + `constraints.txt` | posture P-15 (deteksi alat) | NOT RUN di lab (jujur) | Jalankan `pip-audit` — MANUAL |
| R29 | Release naik dengan regresi keamanan | `.github/workflows/ci.yml` (compile, suite, fuzz, posture) | CI first-run | NOT RUN (CI baru) | Verifikasi run pertama di GitHub — MANUAL |
| R30 | Fuzz menemukan crash baru | `fuzz_lab` F1–F6 | `test_fuzz_lab` (0 crash, deterministik) | PASS | Cakupan fuzz terbatas 6 kelas input |

**Pengujian TANPA test otomatis (wajib manual di laptop owner):**
TLS handshake nyata 2 host dengan cert + pin, fitur kamera OpenCV
(motion/blur/rekam), `pip-audit` + SBOM, first-run CI GitHub, perilaku
`flock` di Windows.
