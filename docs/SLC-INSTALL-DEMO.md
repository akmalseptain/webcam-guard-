# SLC-INSTALL-DEMO — v4.0 Sovereign Lab Control

Panduan instalasi, mode operasi, dan langkah demo UTS.

## 1. Persyaratan

- Controller: Python 3.10+ (hanya pustaka standar — tanpa pip install).
- Endpoint (opsional, mode FISIK): PC lab Windows 10/11, hak Administrator,
  Python 3.10+ terpasang, jaringan lab dapat menjangkau controller.
- Port: **TCP 9443** di mesin controller (ubah via `--port`). Sertifikat
  TLS opsional; bila dipakai, sertifikat divalidasi ketat (pin sha256/CN).

## 2. Mode DEMO (tanpa perangkat fisik)

**Cara tercepat melihat seluruh alur NYATA (1 perintah, TCP loopback betulan):**

```
python3 slc_lab.py
```

Menjalankan dalam SATU proses: enroll → server TCP → agent loopback
(socket NYATA) → 3 tugas dieksekusi endpoint-side & terverifikasi →
emergency stop → misi MissionEngine (state penuh + laporan) →
integritas audit hash-chain.

> PENTING (batas arsitektur, jujur): antrean tugas & `last_seen` SLCControl
> hidup **di memori proses server**. Menjadwalkan tugas dari terminal/proses
> TERPISAH tidak pernah sampai ke agent. Demo TCP end-to-end karena itu
> harus dalam satu proses — `slc_lab.py`. (`slc_demo.py --demo` = data
> sintetis berlabel; `slc_lab.py` = telemetri nyata mesin ini.)

Data sintetis berlabel (untuk latihan pemeriksaan UI):

```
python3 slc_demo.py --demo
python3 slc_demo.py --evaluasi --tulis laporan.md   # laporan acceptance
```

- Semua perangkat demo diberi label `SINTETIS-DEMO (bukan perangkat nyata)`
  dan TIDAK pernah dicampur dengan data fisik.
- Cocok untuk latihan dan pemeriksaan UI sebelum demo sebenarnya.

## 3. Mode FISIK — enrol endpoint lab

1. Jalankan controller:
   ```
   python3 slc_server.py --host 0.0.0.0 --port 9443 [--cert cert.pem --key key.pem]
   ```
2. Enroll perangkat dari sisi controller (hasil: id + kunci, simpan aman
   mode 0600; kunci TIDAK pernah ditulis ke repo):
   ```
   python3 -c "from slc_control import SLCControl; \
     c=SLCControl(); print(c.enroll('lab-01', oleh='admin', grup='ruang-a'))"
   ```
3. Di PC Windows lab, jalankan agent dengan id+kunci dari enrollment:
   ```
   python slc_endpoint.py --host <IP-CONTROLLER> --port 9443 --id DEV-XXXX --kunci XXXX
   ```
   TLS: tambahkan `--tls --ca-file ca.pem` atau `--tls --pin <sha256-cert>`.
4. Verifikasi: controller mencatat heartbeat/last-seen per perangkat;
   perangkat tanpa enrollment TIDAK diizinkan meski reachable di jaringan.

## 4. Instalasi sebagai Windows Service (SLCAgent)

Jalankan sekali di PC lab sebagai Administrator (lihat `CARA_INSTALL` pada
`slc_endpoint.py` — `python slc_endpoint.py --install-layanan` untuk mencetak):

```
sc.exe create SLCAgent binPath= "C:\Python312\python.exe C:\lab\slc_endpoint.py --layanan --id DEV-XXXX --kunci XXXX" start= delayed-auto
sc.exe description SLCAgent "SLC Endpoint Agent - lab universitas (administrasi terpusat resmi)"
sc.exe failure SLCAgent reset= 86400 actions= restart/5000
```

- Mulai/stop: `sc.exe start SLCAgent` / `sc.exe stop SLCAgent`.
- Upgrade: hentikan layanan → `slc_endpoint.py --pasang-paket <file>
  <sha256> <tujuan>` (integritas dicek, `.bak` otomatis) → jalankan lagi.
- **Uninstall** (agent TIDAK menghalangi):
  ```
  sc.exe stop SLCAgent && sc.exe delete SLCAgent && rmdir /s /q C:\lab
  ```
- Nama layanan `SLCAgent` sengaja jelas — tidak menyamar komponen Windows,
  tidak menonaktifkan Defender/keamanan, dan bisa dihentikan admin kapan pun.

## 5. Emergency stop & pembatalan

- Per perangkat: `control.emergency_stop(dev_id)` — perangkat berhenti
  menerima tugas baru; banner UI menampilkan statusnya. Lepas dengan
  `lepas_emergency()`.
- Tingkat operator/misi: `mission.batalkan_misi()` membatalkan seluruh
  misi berjalan (deadline & budget juga membatasi otomasi).
- UI: tombol `[CTRL-E: EMERGENCY STOP]` selalu tampil.

## 6. Langkah demo UTS (11 langkah examiner)

1. **Arsitektur & inventaris** — tampilkan `docs/SLC-ARCHITECTURE-v4.0.md`
   dan `control.inventaris()` (mode DEMO: label sintetis terlihat jelas).
2. **Data kesehatan endpoint** — buka `detail_perangkat()`: kesehatan,
   tugas tertunda, aktivitas terakhir, alert.
3. **Luncurkan asesmen terbatas** — `MissionEngine` + misi inventaris;
   scope/budget/deadline eksplisit sebelum eksekusi.
4. **AI merencanakan & mengeksekusi** — tampilkan state misi
   `REQUESTED → … → REPORTING` dan antrean per-langkah.
5. **Output nyata & bukti verifikasi** — hasil per-tugas + verifikasi
   postcondition (bukan sekadar exit 0) + referensi bukti ber-hash.
6. **Skenario adversarial aman** — `jalankan_red()`: 4 skenario sintetis
   (RB-01..RB-04) ter-scope; di luar scope DITOLAK (fixture uji ada).
7. **Baseline vs perbaikan** — `jalankan_blue()` + `bandingkan_konfigurasi()`:
   precision/recall/FPR sebelum-sesudah; yang tak diukur dinyatakan.
8. **Timeline insiden (simulasi)** — `render_timeline()` + event pipeline
   dengan label `ASAL` (telemetri/sintetis/replay/inferensi).
9. **Integritas bukti** — `audit.verify()` (hash berantai) +
   `evidence.build_pack()`.
10. **Remediasi + tes** — `slc_remediation`: 12 langkah dengan inspeksi
    diff, tes, persetujuan, checkpoint, dan rollback; zona larangan aktif.
11. **Ekspor laporan** — `laporan_teks/json` misi + `--evaluasi` acceptance.

## 7. Keamanan & kompatibilitas Windows (ringkas)

- Default aman: bind 127.0.0.1; kunci file 0600; tolak-default untuk aksi
  & parameter; whitelist pesan; HMAC+nonce.
- Bila produk keamanan menandai aplikasi: catat nama deteksi, hash artefak,
  versi produk, dan langkah reproduksi; perbaiki akar masalah; gunakan kanal
  submission false-positive resmi vendor. TIDAK ada jaminan lolos semua
  produk keamanan — dan itu tidak diklaim.
- Jangan pernah membuat eksklusi AV otomatis atau menonaktifkan Defender.

## 8. Known limitations (jujur)

- 3 test TLS pinning di-skip di CI (butuh sertifikat nyata — jalankan di
  lab Windows).
- Instalasi Windows Service nyata hanya bisa diverifikasi di PC fisik
  (prosedur terdokumentasi; CI tidak bisa menjalankan `sc.exe`).
- Digital twin membangun model dari inventaris terverifikasi; dependensi
  tanpa bukti dilabeli asumsi, bukan fakta.
