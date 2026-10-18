# Audit Teknis & Laporan Implementasi — WebCam Guard v1.3

Tanggal: 2026-10-18 · Scope: repo `akmalseptain/webcam-guard-` (main @ `0348ad4`, v1.2)
Metode: audit source code nyata (13 file v1.2), pemetaan terhadap arsitektur target
(master prompt 10 fase), implementasi prioritas tertinggi, pengujian ulang.

---

## 1. Temuan audit (K-01 .. K-10)

| ID | Temuan | Severity | Status v1.3 |
|---|---|---|---|
| K-01 | Tidak ada subsystem network monitoring sama sekali (Phase 2 kosong) | Tinggi | ✅ Diimplementasi (MVP): `netmon.py` |
| K-02 | Tidak ada mesin forensik/korelasi event — log tersebar (events.csv, sessions.csv) tanpa skema umum | Tinggi | ✅ Diimplementasi (MVP): `forensics.py` |
| K-03 | Tidak ada pengujian keamanan kredensial (Phase 5 kosong) | Tinggi | ✅ Diimplementasi (MVP, 100% sintetis): `credcheck.py` |
| K-04 | Tidak ada validasi kontrol deteksi (red team / detection validation) | Sedang | ✅ Diimplementasi (MVP, scope-enforced): `redsim.py` |
| K-05 | Tidak ada RBAC/audit terpusat — hanya token pairing per sesi mirroring | Tinggi | ✅ Diimplementasi: `audit_core.py` (RBAC + PBKDF2 + rate limiter + audit hash-chain) |
| K-06 | Tidak ada dashboard operasi terpadu | Sedang | ✅ Versi teks: `lab_status.py` (web UI → roadmap) |
| K-07 | Live capture tidak ada; tidak ada export PCAP | Sedang | ✅ PCAP write/read klasik + adapter eksternal (tcpdump/tshark/dumpcap) dicek runtime |
| K-08 | Integritas bukti: log bisa diedit tanpa jejak | Tinggi | ✅ Hash-chain di audit_core + forensics (verify() mendeteksi tamper — diuji unit test) |
| K-09 | Endpoint telemetry (Phase 3) belum ada sama sekali | Rendah* | ⏳ Roadmap (butuh arsitektur agent + enrollment; tidak dipaksakan di v1.3) |
| K-10 | Analisis trafik terenkripsi (Phase 4) belum ada | Rendah* | ⏳ Roadmap (SNI diekstrak; proxy HTTPS lab eksplisit ditunda) |

\* Rendah bagi penggunaan lab saat ini (tugas kuliah); bukan karena tidak penting.

## 2. Keputusan desain utama

1. **Stdlib-only untuk semua modul baru** — test bisa dijalankan di mana pun
   tanpa `pip`; OpenCV/mss/cryptography tetap hanya untuk fitur webcam/mirror.
2. **Metadata-only untuk netmon** — payload aplikasi TIDAK disimpan/didekode;
   hanya header + metadata protokol (DNS query name, SNI, baris HTTP).
3. **100% sintetis untuk credcheck** — kredensial dibuang-buat, bukti dimask,
   ada verifikasi otomatis `no_secret_leak_verified` di laporan.
4. **Scope-enforced untuk redsim** — `lab_scope.json` adalah batas keras;
   target di luar scope ditolak (`ScopeError`) dan penolakan ter-audit.
   Semua skenario simulasi POLA (T1046/T1071/T1547/T1078), bukan serangan nyata.
5. **Tamper-evident untuk semua bukti** — audit log & event store memakai
   hash-chain; `verify()` melaporkan baris pertama yang tidak konsisten.

## 3. Hasil uji NYATA (dijalankan ulang, bukan klaim)

- `python -m py_compile *.py` — semua 13 modul lolos kompilasi.
- `python -m unittest discover -s tests` — **133/133 PASS** (42 test v1.2 tetap
  hijau + 91 test baru: audit_core 22, credcheck 21, forensics 12, netmon 24,
  redsim 12 — sebagian besar bug ditemukan oleh test itu sendiri).
- Demo end-to-end nyata (run terpisah):
  - `netmon --demo`: 25 paket sintetis → **15 flow, 3 anomali**
    (port_c2/T1071, port_scan/T1046, beacon/T1071); metadata diekstrak:
    DNS `lab-01.local`, HTTP `GET lab.local/index.html`, SNI `lab-service.local`;
    PCAP demo (2 KB) ditulis dan bisa dibaca ulang via `--analyze`.
  - `credcheck`: **8 temuan (semuanya KRITIS)** — password assignment,
    api_key, bearer, AWS-key, session_cookie, IDOR (VULNERABLE by design),
    missing-authz (VULNERABLE by design), password di log;
    `no_secret_leak_verified = true` (tidak ada nilai rahasia polos di laporan).
  - `redsim`: **4/4 skenario TERDETEKSI, detection_rate = 1.0**; audit utuh;
    target uji `8.8.8.8` (di luar scope) → **REFUSED_OUT_OF_SCOPE** + tercatat
    di audit hash-chain.
  - `forensics`: 4 event redsim dinormalisasi, rantai integritas OK,
    1 kandidat insiden terkorelasi (host lab-01.local).
  - `lab_status`: dashboard menampilkan aset scope, 4 event, 10 audit (utuh),
    temuan credcheck, 1 file capture, kandidat insiden.
- Bug yang ditemukan & diperbaiki SELAMA pengujian (bukti test bekerja):
  1. `parse_sni` salah membaca record TLS → exception pada ClientHello valid.
  2. Demo menghasilkan 26 paket (kelebihan 1) → jumlah tidak konsisten dgn dok.
  3. `credcheck.mask` salah nama parameter (tertangkap unit test).
  4. Ekspektasi tamper-audit: verify() melapor indeks baris pertama yang
     berubah (0, bukan 1) — test dikoreksi mengikuti perilaku benar.
  5. Threshold entropi: string uji terlalu pendek untuk regex {24,} — test
     diperbaiki dengan sampel 24-karakter.

## 4. Batasan yang JUJUR diakui (tidak klaim kemampuan yang tidak ada)

- **Live capture** mendelegasikan ke tcpdump/tshark/dumpcap; bila tidak
  terpasang, netmon menolak dengan pesan jelas (tidak ada mode "palsu").
  Pengukuran akurasi capture nyata hanya bisa di lab berinterface fisik.
- **TLS inspection**: hanya metadata SNI yang dibaca; TIDAK ada dekripsi
  trafik pihak ketiga. Proxy HTTPS untuk aplikasi uji = roadmap (Phase 4).
- **Endpoint telemetry (Phase 3)** belum ada: butuh agent + enrollment
  terautentikasi + mTLS — sengaja tidak dipaksakan di rilis ini.
- **Dashboard web (Phase 8)**: versi teks berfungsi penuh membaca artefak
  nyata; UI web (RBAC per-session, rate limit login) = roadmap.
- **MITRE ATT&CK** dipetakan pada level teknik (T1046/T1071/T1547/T1078)
  untuk skenario simulasi; bukan framework emulasi penuh (mis. Caldera).
- **Test protokol mirroring** tetap memakai socket polos (ssl_ctx=None);
  TLS asli diverifikasi manual di laptop (sertifikat self-signed lab).

## 5. Roadmap berikutnya (urutan prioritas)

1. Phase 3 MVP: agent endpoint (inventory proses + enrollment HMAC + health).
2. Phase 4: proxy HTTPS lab eksplisit + trust store terpisah untuk app uji.
3. Dashboard web (Flask/FastAPI) dengan login RBAC + rate limit.
4. Integrasi redsim → forensics otomatis (sudah: event redsim masuk store).
5. Retensi & rotasi kebijakan (retention policy) untuk lab_events/lab_audit.

## 6. Reproduksi

```bash
python -m unittest discover -s tests          # 133 test
python netmon.py --demo                       # 25 paket, 15 flow, 3 anomali
python credcheck.py                           # 8 temuan sintetis
python redsim.py                              # 4/4, detection_rate 1.0
python forensics.py                           # timeline + integritas
python lab_status.py                          # dashboard teks
```

Semua angka di atas berasal dari eksekusi nyata pada commit v1.3.
