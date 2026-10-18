<!-- Laporan ini DIGENERATE oleh range_report.py pada 2026-10-18 15:09:10; jangan edit manual. -->

# RANGE REPORT v3.0 — Before/After Terukur

```text
====================================================================
 RANGE REPORT v3.0 — before/after terukur  (2026-10-18 15:09:10)
====================================================================

BASELINE v2.0 (dikunci dari build terverifikasi):
  test total        : 204
  posture           : 93.8 (bloker: tidak ada)
  netmon           : P=1.0 R=0.75
  scenario engine  : TIDAK ADA (baru di v3.0)

HASIL v3.0 (angka aktual build ini):
  test total        : 345  (baseline 204, delta +141)
  test modul range  : 141
  posture           : 93.8 (LULUS 14, PERINGAT 2, GAGAL 0, bloker: tidak ada)  (baseline 93.8, delta +0.0)
  netmon            : P=1.0 R=0.75 FPR=0.0 FNR=0.25 (TP=3 FP=0 FN=1 TN=5)
  scenario engine   : 4/4 terdeteksi (detection_rate=1.0)
      kontrol fim: 1/1 (skenario: R-FIM-TAMPER)
      kontrol netmon_beacon: 1/1 (skenario: R-C2-BEACON)
      kontrol netmon_port_scan: 1/1 (skenario: R-RECON)
      kontrol rbac: 1/1 (skenario: R-PRIVILEGE)

KRITERIA PENERIMAAN:
  [LULUS       ] K1 — jumlah test total >= 300 (baseline 204 + >=96 baru)
  [LULUS       ] K2 — test baru modul range >= 100
  [LULUS       ] K3 — posture >= 93.8 & tanpa bloker (tidak regres vs v2.0)
  [LULUS       ] K4 — netmon tidak regres: precision >= 1.0, recall >= 0.75 (ekstensi v3.0 tak merusak)
  [LULUS       ] K5 — scenario engine: detection_rate 1.0 pada fixture loopback (semua kontrol menangkap)

--------------------------------------------------------------------
  LULUS 5/5  GAGAL 0  TIDAK DIUKUR 0
  CATATAN JUJUR: angka dari pengukuran build ini; detektor diuji
  pada fixture sintetis, BUKAN jaminan akurasi dunia nyata. TLS/mTLS antar-host nyata, kamera OpenCV, pip-audit/SBOM dan rollback VM tetap langkah manual owner.
====================================================================
```
