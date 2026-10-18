# WebCam Guard 🎥

Aplikasi pengawasan webcam **lokal** berbasis Python + OpenCV — dibuat untuk belajar keamanan siber (project edukasi di bawah pengawasan dosen).

## ⚠️ Etika & Legalitas
Tool ini HANYA untuk kamera/laptop milik sendiri. Mengakses kamera orang lain tanpa izin adalah ilegal (UU ITE).

## Fitur
1. **Live view** — pantau kamera real-time dengan timestamp
2. **Deteksi gerakan** — snapshot + rekam video otomatis saat ada gerakan
3. **Rekam manual** — rekam video 10 detik
4. **Tes akses kamera** — cek keamanan: buktikan program biasa bisa membuka kamera tanpa peringatan

## Instalasi
```bash
pip install -r requirements.txt
python webcam_guard.py
```

## Cara pakai
Pilih menu 1-5 di terminal. Tekan `Q` di jendela kamera untuk keluar dari tiap mode.
Snapshot tersimpan di `snapshots/`, rekaman di `recordings/`.

## Konsep yang dipelajari
- **Background subtraction** — membandingkan frame dengan latar adaptif (`cv2.absdiff` + blending 90/10)
- **Thresholding & kontur** — binarisasi perbedaan piksel lalu deteksi objek (`cv2.findContours`)
- **Video I/O** — `VideoCapture` membaca, `VideoWriter` menulis dengan codec mp4v
- **Pelajaran keamanan** — menu 4 membuktikan bahwa akses kamera tidak dijaga OS secara default

## Lisensi
MIT — © 2026 Akmal Putra Septian
