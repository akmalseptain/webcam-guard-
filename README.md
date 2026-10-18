# WebCam Guard v1.3 — Advanced Cybersecurity Lab Edition

Proyek pembelajaran keamanan siber (diawasi dosen, Universitas Indonesia).
**Hanya untuk perangkat milik sendiri / lab yang diotorisasi.**

Audit teknis lengkap v1.3: lihat [`docs/AUDIT-v1.3.md`](docs/AUDIT-v1.3.md)
(temuan audit K-01..K-10, tabel implementasi, hasil uji nyata, batasan, roadmap).

## Fitur v1.3 (baru — Laboratorium Lanjutan)

| Modul | File | Inti |
|---|---|---|
| Network monitoring (metadata-only) | `netmon.py` | Parse PCAP (Ethernet/IPv4/TCP/UDP), ekstraksi metadata DNS / SNI (ClientHello) / HTTP, FlowTable, deteksi anomali (port C2 T1071, port scan T1046, beaconing), tulis PCAP klasik, live capture via adapter `tcpdump`/`tshark`/`dumpcap` (dicek saat runtime) |
| Forensics & korelasi event | `forensics.py` | Skema event normalisasi (8 jenis), timeline kronologis, korelasi lintas-subsystem, hash-chain integritas bukti, ekspor CSV + laporan |
| Credential security testing (100% sintetis) | `credcheck.py` | Generate kredensial sekali-pakai, deteksi pola secret + entropi, aplikasi uji yang sengaja rentan (IDOR, session TTL, batas otorisasi), bukti dimatikan (masked), verifikasi tidak ada kebocoran nyata, laporan severity |
| Red team emulation (scoped) | `redsim.py` | 4 skenario (recon T1046, beacon C2 T1071, indikator persistensi T1547, uji privilege-boundary T1078) dengan pemetaan MITRE ATT&CK, hanya boleh menyasar aset dalam `lab_scope.json`, target di luar scope OTOMATIS DITOLAK + diaudit |
| Security core | `audit_core.py` | RBAC (admin/operator/auditor), password PBKDF2, rate limiter, audit log hash-chain (tamper-evident + verifikasi) |
| Dashboard teks | `lab_status.py` | Status aset lab, ringkasan anomali jaringan, temuan kredensial, hasil skenario, timeline event, integritas bukti |
| Konfigurasi scope | `lab_scope.json` | Daftar host/CIDR lab yang diotorisasi — batas keras untuk seluruh modul emulasi |

## Fitur v1.2 (tetap)

| Fitur | File | Inti |
|---|---|---|
| Screen mirroring **dengan persetujuan eksplisit** | `mirror_server.py`, `mirror_viewer.py` | Kode pairing + token HMAC, TLS, audit `sessions.csv` |
| Protokol streaming terenkripsi | `mirror_stream.py` | Wire format length-prefixed, self-signed cert via `cryptography`/`openssl` |
| Autentikasi & peran | `mirror_auth.py` | Token HMAC-SHA256 per (kode, role), `ConsentGate`, state machine sesi |
| Stealth Detector **defensif** | `stealth_sim.py`, `stealth_dataset.json` | Kenali jejak pemantauan tersembunyi dari dataset sintetis |

## Fitur v1.1 (tetap)

Live view, deteksi gerakan + zona ROI + auto rekam, Face Guard (blur wajah), rekam manual, statistik `events.csv`, headless mode, HUD FPS.

## Jaminan keamanan & privasi

- ❌ TIDAK mengumpulkan kata sandi, cookie, token, atau private key — milik siapa pun.
- ❌ TIDAK memotong (intercept) sesi terenkripsi aplikasi lain; netmon hanya menganalisis **metadata** paket.
- ❌ TIDAK ada bypass proteksi keamanan; uji HTTPS hanya lewat proxy lab eksplisit (roadmap).
- ✅ Emulasi red team terkunci pada `lab_scope.json`; target di luar scope ditolak + diaudit.
- ✅ Modul credcheck 100% memakai kredensial **sintetis**; bukti dimatikan (masked), ada verifikasi "tidak ada kebocoran nyata".
- ✅ Mirroring TIDAK bisa dimulai tanpa pengguna mengetik `SETUJU` (ConsentGate).
- ✅ Semua operasi istimewa ter-audit dengan hash-chain (tamper-evident).
- ✅ Stealth Detector hanya **membaca** (read-only) — untuk mendeteksi, bukan menyembunyikan.
- ✅ Koneksi mirroring dibungkus TLS (sertifikat lab self-signed).

## Instalasi

```bash
pip install -r requirements.txt
```

Modul lab lanjutan (netmon, forensics, credcheck, redsim, audit_core, lab_status)
hanya memakai **stdlib Python** — tidak butuh dependensi tambahan.
Live capture butuh `tcpdump` / `tshark` / `dumpcap` terpasang (dicek saat runtime).

## Pemakaian

```bash
# Menu utama (semua fitur, termasuk submenu "A. Lab Lanjutan"):
python webcam_guard.py

# --- Lab Lanjutan (v1.3) ---
python netmon.py --demo                          # analisis 25 paket sintetis → flow + anomali
python netmon.py --capture-iface eth0 --minutes 5 --save-pcap captures/lab.pcap
python netmon.py --analyze captures/lab.pcap     # analisis PCAP + metadata + anomali
python credcheck.py                              # asesmen keamanan kredensial (sintetis)
python redsim.py                                 # 4 skenario emulasi (scope-enforced)
python forensics.py                              # timeline + korelasi + laporan forensik
python lab_status.py                             # dashboard teks

# --- Mirroring v1.2 ---
python mirror_server.py                          # pengirim: kode pairing + ketik SETUJU
python mirror_viewer.py XXXX-XXXX --host <ip> --role viewer --token <token>

# --- Stealth Detector v1.2 ---
python stealth_sim.py --lokal
```

## Pengujian

```bash
python -m py_compile *.py
python -m unittest discover -s tests
```

Cakupan **133 test**: pairing/token (HMAC), persetujuan eksplisit, transisi sesi,
audit log, protokol wire (length-prefixed), auth HELLO/WELCOME/DENY, kuota penonton,
pencabutan akses, deteksi stealth, RBAC + PBKDF2 + rate limiter + audit hash-chain
(termasuk bukti deteksi tamper), format PCAP + parser metadata + deteksi anomali,
normalisasi/timeline/korelasi forensik, asesmen kredensial sintetis + masking bukti,
skenario redsim + penolakan out-of-scope.

> Catatan jujur: unit test protokol memakai socket polos (`ssl_ctx=None`) dan
> seluruh test dijalankan di lingkungan sandbox tanpa akses antarmuka jaringan
> fisik — capture nyata diverifikasi manual di lab. Lihat batasan lengkap di
> `docs/AUDIT-v1.3.md`.

## Struktur

```
webcam_guard.py        Menu utama (v1.1–v1.3 + submenu Lab Lanjutan)
netmon.py             Network monitoring: PCAP parse/write, flow, anomali, adapter live
forensics.py          Korelasi event, timeline, hash-chain bukti, laporan
credcheck.py          Asesmen keamanan kredensial (sintetis, masked)
redsim.py             Emulasi red team 4 skenario (scope-enforced, MITRE ATT&CK)
audit_core.py         RBAC, PBKDF2, rate limiter, audit hash-chain
lab_status.py         Dashboard teks status lab
lab_scope.json        Scope aset lab yang diotorisasi (batas keras)
mirror_*.py           Screen mirroring v1.2 (consent + TLS)
stealth_sim.py        Detektor defensif v1.2 + dashboard indikator
stealth_dataset.json  Dataset SINTETIS stealth
docs/AUDIT-v1.3.md    Audit teknis + hasil uji + roadmap
tests/                unittest (8 file, 133 test)
```

## Roadmap

- Phase 3: agent endpoint telemetry (enrollment + mTLS) — ditunda.
- Phase 4: proxy HTTPS lab eksplisit untuk aplikasi uji — ditunda.
- Dashboard web (Phase 8) — versi teks sudah jalan; UI web ditunda.

## Disclaimer

Projek edukasi. Penyalahgunaan terhadap perangkat tanpa izin pemiliknya
melanggar hukum (UU ITE). Penulis tidak bertanggung jawab atas penyalahgunaan.
