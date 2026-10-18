# WebCam Guard v1.2 — Cybersecurity Lab Edition

Proyek pembelajaran keamanan siber (diawasi dosen, Universitas Indonesia).
**Hanya untuk perangkat milik sendiri / lab yang diotorisasi.**

## Fitur v1.2 (baru)

| Fitur | File | Inti |
|---|---|---|
| Screen mirroring **dengan persetujuan eksplisit** | `mirror_server.py`, `mirror_viewer.py` | Kode pairing + token HMAC, TLS, audit `sessions.csv` |
| Protokol streaming terenkripsi | `mirror_stream.py` | Wire format length-prefixed, self-signed cert via `cryptography`/`openssl` |
| Autentikasi & peran | `mirror_auth.py` | Token HMAC-SHA256 per (kode, role), `ConsentGate`, state machine sesi |
| Stealth Detector **defensif** | `stealth_sim.py`, `stealth_dataset.json` | Kenali jejak pemantauan tersembunyi dari dataset sintetis (proses, koneksi, persistensi, izin) |

## Fitur v1.1 (tetap)

Live view, deteksi gerakan + zona ROI + auto rekam, Face Guard (blur wajah), rekam manual, statistik `events.csv`, headless mode, HUD FPS.

## Jaminan keamanan & privasi

- ❌ TIDAK mengumpulkan kata sandi, cookie, token, atau private key.
- ❌ TIDAK mengaktifkan kamera/mikrofon secara tersembunyi, TIDAK keylogging.
- ✅ Mirroring TIDAK bisa dimulai tanpa pengguna mengetik `SETUJU` (ConsentGate).
- ✅ Semua sesi ter-audit (`sessions.csv`); pengirim bisa jeda/stop/cabut penonton kapan saja.
- ✅ Stealth Detector hanya **membaca** (read-only) — untuk mendeteksi, bukan menyembunyikan.
- ✅ Koneksi dibungkus TLS (sertifikat lab self-signed, hanya untuk perangkat lab).

## Instalasi

```bash
pip install -r requirements.txt
```

## Pemakaian

```bash
# Menu utama (semua fitur):
python webcam_guard.py

# 1) Bagikan layar (laptop pengirim):
python mirror_server.py            # tampil kode pairing + token; ketik SETUJU

# 2) Menonton (laptop penonton/dosen):
python mirror_viewer.py XXXX-XXXX --host <ip-pengirim> --role viewer --token <token>

# 3) Stealth Detector (dataset sintetis + folder startup laptop ini, read-only):
python stealth_sim.py
python stealth_sim.py --lokal
```

## Pengujian

```bash
python -m py_compile *.py
python -m unittest discover -s tests
```

Cakupan: format pairing/token (HMAC), persetujuan eksplisit, transisi sesi,
audit log, protokol wire (length-prefixed), auth HELLO/WELCOME/DENY, kuota
penonton, jeda/lanjut/stop, pencabutan akses, dan deteksi stealth.

> Catatan jujur: unit test protokol memakai socket polos (`ssl_ctx=None`)
> untuk menguji logika. Enkripsi TLS asli diuji manual di laptop:
> server dan viewer saling menolak bila salah satu sisi tidak memakai TLS.

## Struktur

```
webcam_guard.py        Menu utama (v1.1 + integrasi v1.2)
mirror_auth.py         Token, role, ConsentGate, audit  (stdlib-only)
mirror_stream.py       Protokol + TLS + server streaming (stdlib-only)
mirror_server.py       Entry point pengirim (tangkap layar: mss+cv2)
mirror_viewer.py       Entry point penonton (tampil frame: cv2)
stealth_sim.py         Detektor defensif + dashboard indikator
stealth_dataset.json   Dataset SINTETIS (bukan data nyata)
tests/                 unittest (auth, stream, stealth)
```

## Disclaimer

Projek edukasi. Penyalahgunaan terhadap perangkat tanpa izin pemiliknya
melanggar hukum (UU ITE). Penulis tidak bertanggung jawab atas penyalahgunaan.
