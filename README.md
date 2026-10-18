# WebCam Guard v3.0 — Cyber Range & Security Lab Edition

Proyek pembelajaran keamanan siber (diawasi dosen, Universitas Indonesia).
**Hanya untuk perangkat milik sendiri / lab yang diotorisasi.**

v3.0 menambahkan lapisan **cyber range** di atas v2.0: enrollment perangkat
kriptografis, controller ter-autentikasi, endpoint agent read-only, scenario
engine scope-enforced, dan laporan before/after. Dokumentasi utama:

- [`docs/RANGE-SECURITY-v3.0.md`](docs/RANGE-SECURITY-v3.0.md) — desain keamanan range v3.0: identitas perangkat 256-bit, RBAC persisten, whitelist perintah, anti-replay, batas model ancaman.
- [`docs/RANGE-AUDIT-v2.0.md`](docs/RANGE-AUDIT-v2.0.md) — audit baseline v2.0 sebelum range (temuan B-01..B-10, pemetaan 20 kapabilitas vs master prompt).
- [`docs/RANGE-REPORT-v3.0.md`](docs/RANGE-REPORT-v3.0.md) — laporan perbandingan SEBELUM vs SESUDAH (angka hasil ukur nyata, kriteria K1..K5).
- [`docs/V2.0-SECURITY.md`](docs/V2.0-SECURITY.md) — desain keamanan v2.0: hash-chain berbasis `flock` + sequence + anchor, throttling autentikasi & lockout, pinning sertifikat SHA-256, masking secret ketat, aturan fail-safe.
- [`docs/RISK-MATRIX.md`](docs/RISK-MATRIX.md) — pemetaan risiko → kontrol → test (test-to-risk mapping), perilaku yang belum diuji, risiko sisa.
- [`docs/AUDIT-v1.3.md`](docs/AUDIT-v1.3.md) — audit teknis v1.3 (temuan K-01..K-10, hasil uji nyata, batasan, roadmap).

## Fitur v3.0 (baru — lapisan cyber range)

| Fitur | File | Inti |
|---|---|---|
| Device enrollment & registry | `range_registry.py` | Identitas perangkat 256-bit (`secrets.token_hex(32)`), `devices.json` 0600, revoke darurat per perangkat, lockdown global, anti-replay nonce sekali-pakai + jendela ±60 dtk, MAC HMAC-SHA256 kanonik; kunci perangkat ditampilkan SEKALI saat enroll, tidak pernah dicetak ulang |
| Lab controller ter-autentikasi | `range_controller.py` | `OperatorStore` persisten (`operators.json` 0600, hash PBKDF2 200k iter, anti-enumeration via PBKDF2 dummy), whitelist perintah per jenis klien yang dieksekusi nyata (device: HELLO/HEARTBEAT/POLL/HASIL; operator: TUGAS admin-only / LIHAT), rate limit login, antrean tugas FIFO (POLL konsumsi), server loopback default — menutup temuan audit B-01/B-02 |
| Endpoint agent (visibility) | `range_agent.py` | Read-only + whitelist tugas (`proses/pohon_proses/koneksi/fim/priv/health`) — TIDAK ada eksekusi perintah arbitrer; inventory proses & ps-tree dari `/proc`, koneksi `/proc/net/tcp` (kolom 9 = inode — keterbatasan dijujuri), FIM SHA-256 baseline, audit privilege, heartbeat; tanpa persistensi/service/autostart |
| Scenario engine (adversary emulation) | `range_scenarios.py` | Katalog R-RECON (T1046) / R-C2-BEACON (T1071) / R-FIM-TAMPER (T1565.001) / R-PRIVILEGE (T1078) dieksekusi NYATA di loopback; scope validation WAJIB sebelum eksekusi (out-of-scope → DITOLAK_SCOPE + audit, exit 2), coverage report per kontrol + detection_rate, exit code jujur (0/1/2/3), hook rollback VM hanya DICATAT (NOT RUN), MITRE ATT&CK mapping |
| Ekstensi network analysis | `netmon.py` (upgrade) | `inspeksi_sertifikat()` — fingerprint SHA-256 DER + metadata cert (guarded, fallback jujur, CLI `--inspeksi-sert`), `ukur_kualitas()` — duplikat/reorder/gap (estimasi drop dilabeli jujur "BUKAN pengukuran nyata"), `korelasi_dns()` — DNS ↔ SNI/HTTP-Host (match/subdomain/jendela/src) |
| Laporan before/after | `range_report.py` | Baseline v2.0 DIKUNCI vs hasil ukur v3.0 (metode sama), kriteria penerimaan terukur K1..K5 + status LULUS/GAGAL/TIDAK DIUKUR, exit 1 bila ada kriteria GAGAL, `--tulis docs/RANGE-REPORT-v3.0.md` |
| Integrasi | `lab_status.py` (upgrade), `.github/workflows/ci.yml`, `tests/scope_loopback.json` | Baris range di dashboard (devices/operators/lockdown); CI: compile 20 modul + smoke range (registry, skenario fixture 4/4 vs produksi DITOLAK_SCOPE exit 2, report) |

## Fitur v2.0 (tetap)

| Fitur | File | Inti |
|---|---|---|
| Security Posture Engine | `posture.py` | 16 cek perilaku (P-01..P-16) — integritas rantai audit, anti-enumeration, batas iterasi PBKDF2, throttling, RBAC, scope, pinning, mask, retention — dengan skor, status LULUS/PERINGAT/GAGAL, dan exit code (1 bila ada GAGAL kritis); output JSON (`--json`) |
| Tamper-Evident Evidence Pack | `evidence.py` | Ekspor bukti (`--build`): `events.json` + `events.csv` (RAW), `analysis.json` + `report.md` (DERIVED), `manifest.json` (path/size/SHA-256/kelas), `reproduce.txt`; verifikasi `--verify` READ-ONLY — tidak pernah menulis ulang bukti |
| Webcam Privacy Guard | `privacy.py` | Log peristiwa privasi, retensi (umur maks + kuota MB, dry-run default, `--bersihkan` untuk eksekusi), `chmod 0600` file media, keputusan blur fail-closed (blur gagal → frame ditolak + TOLAK_FRAME) |
| Protocol & Input Fuzz Lab | `fuzz_lab.py` | 16 kasus fuzz deterministik (seed default 42): PCAP korup, JSONL malformed, wire protokol via socketpair, brute-force lockout, record invalid, anti-enumeration; catat crash apa pun sebagai regresi |
| Explainable anomaly detection | `netmon.py` (upgrade) | Skor keyakinan + bukti per anomali (bukan kepastian), CV interval beacon + port wajar untuk menekan false-positive polling, `--evaluasi` (dataset berlabel: precision/recall/FPR/FNR), guard packet raksasa di parser |
| Hardened audit chain | `audit_core.py`, `forensics.py` (rewrite) | `flock` lintas-proses (POSIX) + sequence number + baca ekor file (append linier, tidak O(n²)), anchor/checkpoint terpercaya + `verify_terhadap_anchor()`, batas iterasi PBKDF2 1.000–400.000, verify toleran terhadap baris malformed |
| Hardened mirroring | `mirror_stream.py` + server/viewer (rewrite) | Rate limiter per-IP + lockout bounded, token acak 256-bit (`secrets`), STOP_REQ khusus admin (viewer ditolak), pin sertifikat SHA-256 WAJIB (`--pin`, klien tanpa pin exit 3 / mismatch exit 2), TLSv1.2 minimum, timeout baca, bounded queue + payload maksimum |
| Secret masking ketat | `credcheck.py` (upgrade) | `mask()` default "ketat": hanya jumlah karakter (tanpa potongan awal/akhir yang bisa ditebak), kebijakan "ringan" tetap tersedia untuk kompatibilitas |
| Supply chain & CI | `constraints.txt`, `.github/workflows/ci.yml` | Pin versi dependensi (opencv-python, cryptography), CI: compile + unittest + fuzz (2 seed) + smoke CLI + gate posture di Python 3.11/3.12, `permissions: contents: read` |
| RBAC runtime + scope CLI | `redsim.py`, `webcam_guard.py` (upgrade) | `redsim --target` (in-scope lanjut, out-of-scope DITOLAK + audit + exit 2); menu utama opsional tanpa OpenCV (graceful), guard scope untuk capture, jalur aman dari luar root repo |

## Fitur v1.3 (tetap)

`netmon.py` (PCAP parse/write, metadata DNS/SNI/HTTP, flow, anomali), `forensics.py`
(normalisasi 8 jenis, timeline, korelasi, hash-chain), `credcheck.py` (100% sintetis,
IDOR/session/authz by-design, bukti masked), `redsim.py` (4 skenario MITRE ATT&CK,
scope-enforced), `audit_core.py` (RBAC admin/operator/auditor, PBKDF2, rate limiter),
`lab_status.py` (dashboard teks), `lab_scope.json` (batas keras scope).

## Fitur v1.2 & v1.1 (tetap)

Mirroring dengan persetujuan eksplisit (`SETUJU`), TLS, audit `sessions.csv`;
Stealth Detector defensif (read-only) + dataset sintetis; live view, deteksi gerakan +
zona ROI + auto rekam, Face Guard (blur wajah), rekam manual, statistik `events.csv`.

## Jaminan keamanan & privasi

- ❌ TIDAK mengumpulkan kata sandi, cookie, token, atau private key — milik siapa pun.
- ❌ TIDAK memotong sesi terenkripsi aplikasi lain; netmon hanya menganalisis **metadata** paket.
- ✅ Emulasi red team terkunci pada `lab_scope.json`; target di luar scope DITOLAK + diaudit (`--target 8.8.8.8` → exit 2).
- ✅ Credcheck 100% kredensial **sintetis**; masking "ketat" tidak membocorkan potongan secret.
- ✅ Mirroring TIDAK bisa dimulai tanpa `SETUJU`; viewer WAJIB `--pin` (SHA-256 sertifikat) — self-signed TIDAK otomatis dipercaya.
- ✅ STOP sesi global hanya oleh admin; autentikasi dibatasi rate limit per-IP + lockout.
- ✅ Rantai audit/event lintas-proses aman (`flock`), sequence + hash-chain, anchor/checkpoint opsional; verifikasi anchor membedakan "utuh" vs "utuh-terhadap-anchor".
- ✅ Privacy Guard: retensi + izin file 0600 + kebijakan fail-closed bila blur gagal.
- ✅ Range: perangkat TANPA enrollment ditolak controller; tugas agent read-only whitelist (tanpa eksekusi arbitrer); operator non-admin DITOLAK + diaudit; pesan di-replay DITOLAK (nonce sekali-pakai); lockdown darurat satu switch.
- ✅ Skenario range terkunci scope (`tests/scope_loopback.json` untuk uji loopback; `lab_scope.json` untuk lab sungguhan) — out-of-scope → DITOLAK_SCOPE + audit + exit 2.
- ✅ Semua klaim keamanan punya test regresi otomatis (lihat `docs/RISK-MATRIX.md` dan `docs/RANGE-SECURITY-v3.0.md`).

## Instalasi

```bash
pip install -r requirements.txt        # opencv-python, cryptography (ter-pin di constraints.txt)
```

Modul lab (netmon, forensics, credcheck, redsim, audit_core, posture, evidence,
privacy, fuzz_lab, lab_status) hanya memakai **stdlib Python** — tanpa OpenCV pun
menu utama tetap jalan (fitur kamera dinonaktifkan dengan pesan jelas).
Live capture butuh `tcpdump`/`tshark`/`dumpcap` (dicek saat runtime).

## Pemakaian

```bash
# Menu utama (v1.1–v2.0, submenu "A. Lab Lanjutan" 1-9):
python webcam_guard.py

# --- Range v3.0 (enrollment → controller → agent → skenario → laporan) ---
python3 range_registry.py --enroll lab-vm-01      # kunci 256-bit ditampilkan SEKALI
python3 range_registry.py --list                 # inventaris perangkat
python3 range_registry.py --revoke dev-XXXX      # revokasi darurat
python3 range_registry.py --lockdown             # tolak SEMUA perangkat
python3 range_controller.py --init-admin <pw>     # sekali; buat operators.json
python3 range_controller.py                       # controller loopback :9443
python3 range_agent.py --id dev-XXXX --kunci <kunci-enroll> --fim-dir <dir-uji>
python3 range_scenarios.py --scope tests/scope_loopback.json   # 4 skenario loopback, exit 0
python3 range_scenarios.py --scope lab_scope.json             # → 0/4 DITOLAK_SCOPE, exit 2
python3 range_report.py --n-test 345 --n-test-range 141 \
  --jalankan-netmon --tulis docs/RANGE-REPORT-v3.0.md          # before/after (K1..K5)

# --- Baru v2.0 ---
python posture.py                                # security posture (16 cek, exit 1 bila ada GAGAL)
python posture.py --json > posture_report.json   # output machine-readable
python evidence.py --build                       # evidence pack → evidence_pack/
python evidence.py --verify --dir evidence_pack  # verifikasi read-only manifest + hash
python privacy.py                                # ringkasan retensi recordings (dry-run)
python privacy.py --bersihkan                    # eksekusi cleanup retensi
python fuzz_lab.py --seed 42                     # fuzz harness (16 kasus, cari crash)
python netmon.py --evaluasi                      # metrik detektor pada dataset berlabel

# --- Lab Lanjutan (v1.3) ---
python netmon.py --demo                          # 25 paket sintetis → flow + anomali + skor
python netmon.py --analyze captures/lab.pcap      # analisis PCAP offline
python netmon.py --capture-iface eth0 --confirm-scope --minutes 5   # live (scope wajib)
python credcheck.py                              # asesmen kredensial sintetis
python redsim.py --target 192.168.56.10          # in-scope; out-of-scope → DITOLAK
python forensics.py --checkpoint                 # timeline + korelasi + anchor
python lab_status.py                             # dashboard teks

# --- Mirroring (v2.0: WAJIB --pin) ---
python mirror_server.py                          # pengirim: kode pairing + ketik SETUJU
python mirror_viewer.py XXXX-XXXX --host <ip> --role viewer --token <token> \
  --pin <sha256-cert-yang-dicetak-server>
```

## Pengujian

```bash
python -m compileall -q .                        # sintaks seluruh modul
python -m unittest discover -s tests            # suite penuh
python fuzz_lab.py --seed 42 && python fuzz_lab.py --seed 7
python posture.py                                # gate rilis (exit 0/1)
```

Cakupan **345 test** (18 file test): semua cakupan v1.3 (pairing/token, consent,
sesi, wire protokol, RBAC + PBKDF2 + rate limiter + hash-chain, PCAP + anomali,
forensik, credcheck, redsim) **plus** regresi hardening v2.0 (append lintas-proses
utuh, truncation/reorder/duplikasi terdeteksi, lockout + anti-enumeration,
batas iterasi PBKDF2, STOP admin-only, pin mismatch exit 2, mask ketat,
evidence pack + manifest, retention privacy, fail-closed blur, 16 kasus fuzz
crash=0, cek posture) **plus** range v3.0: enrollment + revoke + lockdown +
anti-replay + MAC HMAC (31 test), controller RBAC persisten + whitelist +
agent read-only via socket loopback nyata (42 test), ekstensi netmon
sertifikat/kualitas/korelasi DNS (25 test), scenario engine scope-enforced
in-scope vs out-of-scope (24 test), laporan before/after K1..K5 (19 test).

> Catatan jujur: test protokol memakai socket polos (`ssl_ctx=None`); sandbox
> tidak punya antarmuka jaringan fisik, kamera, atau pip — jadi handshake TLS
> antar-2-host nyata, fitur kamera OpenCV, dan `pip-audit`/SBOM diverifikasi
> manual di laptop owner (lihat `docs/RISK-MATRIX.md`, status NOT RUN).

### Benchmark (metode: `time.monotonic`, 1 warm-up + 3 run, median, sandbox bersama)

- Append rantai audit: n=500 median 0,432 dtk; n=2000 median 1,694 dtk
  (≈0,85 ms/append — linear; biaya `flock` open/close per append adalah trade-off
  kesengajaan demi keamanan lintas-proses).
- Append event forensik: n=500 median 0,425 dtk; n=2000 median 1,749 dtk.
- Detektor netmon (dataset berlabel): TP=3 FP=0 FN=1 TN=5 → precision 1,00,
  recall 0,75, FPR 0,00, FNR 0,25 (1 FN = beacon ber-jitter — dibahas jujur).
- Posture run terakhir: skor 93,8 — LULUS 14, PERINGAT 2 (P-09 TLS nyata,
  P-15 pip-audit = NOT RUN di sandbox), GAGAL 0, exit 0.
- Range v3.0: katalog skenario penuh (4 skenario, socket loopback nyata)
  ≈5–15 dtk per run; hasil ukur build ini — **345/345 test** (204 baseline +
  141 range), scenario engine 4/4 terdeteksi (detection_rate 1.0) pada
  fixture loopback, scope produksi 0/4 DITOLAK_SCOPE, seluruh kriteria
  penerimaan range LULUS 5/5 (lihat `docs/RANGE-REPORT-v3.0.md`).

Angka di atas berasal dari lingkungan sandbox bersama (bukan benchmark isolasi
multi-run statistik); reproduksi di mesin lain dapat berbeda.

## Struktur

```
webcam_guard.py        Menu utama (v1.1–v2.0 + submenu Lab Lanjutan 1-9)
audit_core.py         RBAC, PBKDF2, rate limiter, audit hash-chain + flock + anchor
forensics.py          Korelasi event, timeline, hash-chain + anchor, laporan
netmon.py             PCAP parse/write, flow, anomali explainable, evaluasi berlabel
credcheck.py          Asesmen kredensial sintetis + mask ketat
redsim.py             Emulasi red team scope-enforced (--target)
lab_status.py         Dashboard teks status lab
lab_scope.json        Scope aset lab yang diotorisasi (batas keras)
mirror_*.py           Screen mirroring (consent + TLS + pinning + lockout)
stealth_sim.py        Detektor defensif + dataset sintetis
posture.py            Security posture engine (16 cek behavioral)
evidence.py           Evidence pack build/verify (manifest SHA-256)
privacy.py            Privacy guard: retensi + izin file + fail-safe blur
fuzz_lab.py           Fuzz harness deterministik (16 kasus)
range_registry.py     Enrollment perangkat lab (identitas 256-bit, revoke, lockdown)
range_controller.py   Lab controller ter-autentikasi (RBAC persisten + whitelist)
range_agent.py        Endpoint agent read-only (proses/koneksi/FIM/priv/health)
range_scenarios.py    Scenario engine scope-enforced (MITRE, coverage report)
range_report.py       Laporan before/after (kriteria penerimaan K1..K5)
constraints.txt       Pin versi dependensi
requirements.txt      Dependensi runtime
.github/workflows/ci.yml  CI: compile, test, fuzz, smoke, posture gate
docs/RANGE-SECURITY-v3.0.md  Desain keamanan range v3.0
docs/RANGE-AUDIT-v2.0.md    Audit baseline sebelum range (B-01..B-10)
docs/RANGE-REPORT-v3.0.md   Laporan before/after (angka nyata, digenerate range_report.py)
docs/V2.0-SECURITY.md   Desain keamanan v2.0
docs/RISK-MATRIX.md     Pemetaan risiko → kontrol → test
docs/AUDIT-v1.3.md       Audit v1.3 (historis)
tests/                unittest (18 file, 345 test) + scope_loopback.json fixture
```

### Uninstal / pembersihan range

```bash
python3 range_registry.py --revoke dev-XXXX   # cabut tiap perangkat (opsional)
rm devices.json operators.json                # hapus kredensial lab (0600)
rm range_registry.py range_controller.py range_agent.py \
   range_scenarios.py range_report.py         # hapus modul range
```
Agent tidak meninggalkan persistensi (satu file, tanpa service/autostart);
`lab_events.jsonl`/`lab_audit.jsonl` adalah artefak runtime yang sudah
di-gitignore.

## Roadmap

- ~~Phase 3: agent endpoint telemetry~~ — **TERWUJUD di v3.0** sebagai range
  (`range_registry`/`range_controller`/`range_agent`; jalur TCP plaintext
  loopback — upgrade TLS/mTLS antar-host = kerja manual owner).
- Phase 4: proxy HTTPS lab eksplisit untuk aplikasi uji — ditunda.
- Dashboard web — versi teks (`lab_status.py`, kini + baris range) jalan; UI web ditunda.
- SBOM (CycloneDX/SPDX) + `pip-audit` di CI — menunggu lingkungan dengan pip/network.
- `flock` saat ini POSIX-only (Linux/macOS); penguncian file Windows belum diuji.
- `last_seen` perangkat di registry belum dipersist (in-memory saja) — minor, tercatat.

## Disclaimer

Projek edukasi. Penyalahgunaan terhadap perangkat tanpa izin pemiliknya
melanggar hukum (UU ITE). Penulis tidak bertanggung jawab atas penyalahgunaan.
