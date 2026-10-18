# WebCam Guard 🎥

Aplikasi pengawasan webcam **lokal** berbasis Python + OpenCV — project edukasi keamanan siber (di bawah pengawasan dosen).

## ⚠️ Etika & Legalitas
Tool ini HANYA untuk kamera/laptop milik sendiri. Mengakses kamera orang lain tanpa izin adalah ilegal (UU ITE).

## Fitur (v1.1)
1. **Live view** — real-time + HUD FPS, tekan `C` pindah kamera runtime
2. **Deteksi gerakan** — snapshot + rekam otomatis, **zona pantauan (ROI)** dengan mouse (`Z`), sensitivitas realtime (`+`/`-`)
3. **Face Guard** — deteksi wajah (Haar cascade) + **blur otomatis untuk privasi** (`B` toggle)
4. **Rekam manual** — rekam video 10 detik
5. **Statistik kejadian** — semua event tercatat ke `events.csv`, bisa dibaca lewat menu
6. **Tes akses kamera** — bukti program biasa bisa membuka kamera tanpa peringatan
7. **Headless mode** — `python webcam_guard.py --headless`: log gerakan tanpa GUI (untuk server/Raspberry Pi)

## Instalasi
```bash
pip install -r requirements.txt
python webcam_guard.py            # menu interaktif
python webcam_guard.py --headless # tanpa GUI, log ke CSV
python webcam_guard.py -c 1 -t 30 # kamera index 1, sensitivitas 30
```

## Cara pakai
Pilih menu 1-7 di terminal. Di jendela kamera: `Q` keluar, `C` ganti kamera, `Z` pilih zona pantauan, `B` toggle blur wajah, `+`/`-` ubah sensitivitas.
Snapshot → `snapshots/`, rekaman → `recordings/`, log → `events.csv`.

## Konsep yang dipelajari
- **Background subtraction adaptif** — `cv2.absdiff` + blending 90/10
- **Thresholding & kontur** — `cv2.findContours`, filtering `MIN_AREA`
- **Masking ROI (zona pantauan)** — gerakan hanya dihitung dalam zona terpilih
- **Haar cascade** — deteksi wajah klasik (lebih cepat & ringan dari deep learning, tapi lebih rentan false positive — cocok untuk belajar trade-off)
- **Privasi by design** — blur wajah otomatis: pelajaran bahwa pengawasan harus menghormati privasi
- **Event logging & audit** — CSV sebagai audit trail sederhana
- **Pelajaran keamanan** — akses kamera tidak dijaga OS secara default

## Roadmap ide
- Notifikasi Telegram/Discord saat gerakan terdeteksi
- Face recognition (enrollment wajah pemilik → "wajah dikenal/asing")
- Deploy headless di Raspberry Pi

## Lisensi
MIT — © 2026 Akmal Putra Septian
