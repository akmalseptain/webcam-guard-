# Laporan Evaluasi & Acceptance — v4.0 Sovereign Lab Control

dihasilkan: 2026-10-18 15:57:11

**Suite: 486 test — SEMUA LULUS (failures=0, errors=0, skipped=3)**

| Kategori acceptance | Cakupan test | Status |
|---|---|---|
| Enrollment & revokasi | test_slc_control | dijalankan suite |
| Autentikasi gagal / sertifikat invalid | test_slc_endpoint | dijalankan suite |
| Aksi tak diizinkan / policy | test_slc_control test_slc_actions | dijalankan suite |
| Perangkat di luar scope | test_slc_actions test_slc_endpoint | dijalankan suite |
| Tugas kedaluwarsa / duplikat | test_slc_control | dijalankan suite |
| Agent disconnect / retry / pembatalan | test_slc_endpoint test_slc_mission | dijalankan suite |
| Verifikasi postcondition | test_slc_mission test_slc_control | dijalankan suite |
| Audit log lengkap | test_slc_control test_audit_core | dijalankan suite |
| Integritas bukti | test_evidence test_forensics | dijalankan suite |
| Remediasi aman & rollback | test_slc_twin_remediation | dijalankan suite |
| Limit sumber daya | test_slc_endpoint | dijalankan suite |
| Label sintetis vs nyata | test_slc_events test_slc_demo | dijalankan suite |
| Siklus layanan Windows (bila testable) | test_slc_endpoint | dijalankan suite |
| Paket install/remove (docs) | TIDAK_DIJALANKAN_CI | TIDAK DIJALANKAN di CI (butuh Windows fisik — prosedur terdokumentasi) |

## Yang tidak dapat dijalankan di environment ini (jujur)

- TLS dengan sertifikat nyata: 3 test `TestTLSPinning` di-skip (tidak ada `openssl`/`cryptography` untuk membuat sertifikat di CI; jalankan di laptop Windows dengan sertifikat lab).
- Instalasi Windows Service nyata: butuh PC Windows fisik dengan hak Administrator (prosedur di docs/SLC-INSTALL-DEMO.md).
- koneksi ke perangkat fisik: mode FISIK terdokumentasi, tidak dipalsukan di CI.