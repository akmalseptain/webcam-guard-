# WebCam Guard v2.0 — Hardened Security Lab Edition

Proyek pembelajaran keamanan siber (diawasi dosen, Universitas Indonesia).
**Hanya untuk perangkat milik sendiri / lab yang diotorisasi.**

v2.0 adalah hasil audit independen + hardening di atas v1.3. Dokumentasi utama:

- [`docs/V2.0-SECURITY.md`](docs/V2.0-SECURITY.md) — desain keamanan v2.0: hash-chain berbasis `flock` + sequence + anchor, throttling autentikasi & lockout, pinning sertifikat SHA-256, masking secret ketat, aturan fail-safe.
- [`docs/RISK-MATRIX.md`](docs/RISK-MATRIX.md) — pemetaan risiko → kontrol → test (test-to-risk mapping), perilaku yang belum diuji, risiko sisa.
- [`docs/AUDIT-v1.3.md`](docs/AUDIT-v1.3.md) — audit teknis v1.3 (temuan K-01..K-10, hasil uji nyata, batasan, roadmap).

## Fitur v2.0 (baru)

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
- ✅ Semua klaim keamanan punya test regresi otomatis (lihat `docs/RISK-MATRIX.md`).

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

Cakupan **204 test** (15 file test): semua cakupan v1.3 (pairing/token, consent,
sesi, wire protokol, RBAC + PBKDF2 + rate limiter + hash-chain, PCAP + anomali,
forensik, credcheck, redsim) **plus** regresi hardening v2.0: append lintas-proses
utuh, truncation/reorder/duplikasi terdeteksi (dengan & tanpa anchor), lockout +
anti-enumeration, batas iterasi PBKDF2, STOP admin-only, pin mismatch exit 2,
mask ketat tanpa potongan, bukti anchor, evidence pack + manifest, retention
privacy, fail-closed blur, 16 kasus fuzz crash=0, dan cek posture.

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
constraints.txt       Pin versi dependensi
requirements.txt      Dependensi runtime
.github/workflows/ci.yml  CI: compile, test, fuzz, smoke, posture gate
docs/V2.0-SECURITY.md   Desain keamanan v2.0
docs/RISK-MATRIX.md     Pemetaan risiko → kontrol → test
docs/AUDIT-v1.3.md       Audit v1.3 (historis)
tests/                unittest (15 file, 204 test)
```

## Roadmap

- Phase 3: agent endpoint telemetry (enrollment + mTLS) — ditunda.
- Phase 4: proxy HTTPS lab eksplisit untuk aplikasi uji — ditunda.
- Dashboard web — versi teks (`lab_status.py`) jalan; UI web ditunda.
- SBOM (CycloneDX/SPDX) + `pip-audit` di CI — menunggu lingkungan dengan pip/network.
- `flock` saat ini POSIX-only (Linux/macOS); penguncian file Windows belum diuji.

## Disclaimer

Projek edukasi. Penyalahgunaan terhadap perangkat tanpa izin pemiliknya
melanggar hukum (UU ITE). Penulis tidak bertanggung jawab atas penyalahgunaan.
