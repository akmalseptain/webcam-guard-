"""privacy.py — Webcam Privacy Guard (v2.0, BARU, STDLIB-ONLY).

Kebijakan privasi EKSPLISIT untuk rekaman lab webcam:
- Retention: rekaman lebih tua dari `maks_umur_hari` atau total melebihi
  `maks_total_mb` dihapus (kebijakan default aman; pembersihan JUJUR:
  dry-run kecuali `jalankan=True`).
- Izin file: perketatizin() mengubah izin media ke 0o600 di POSIX
  (di non-POSIX: no-op terdokumentasi, bukan klaim).
- Fail-safe blur: keputusan_frame_blur() menerapkan kebijakan FAIL-CLOSED —
  bila proses blur GAGAL, frame TIDAK diteruskan (lebih baik kehilangan
  frame daripada membocorkan wajah). Kebijakan privasi tidak pernah
  fail-open.
- Jejak privasi: peristiwa (mulai/berhenti rekam, blur gagal, pembersihan)
  dicatat LOKAL ke privacy_events.jsonl — hanya metadata, tanpa konten.
  Rekaman TIDAK pernah disembunyikan; jejak justru wajib.

Batasan jujur:
- log privasi TIDAK ber-hash-chain (berbeda dari audit/event forensik);
  untuk jaminan integritas gunakan audit_core.AuditLog.
- chmod 0600 hanya efektif di POSIX.
"""

import json
import os
import time
from datetime import datetime

EKSTENSI_MEDIA = (".mp4", ".avi", ".mov", ".mkv", ".jpg", ".jpeg", ".png")


def _sekarang():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class PrivacyGuard:
    """Kebijakan privasi rekaman: retensi umur+kuota, izin 0600,
    keputusan blur fail-safe, dan jejak privasi lokal."""

    def __init__(self, direktori_media="recordings",
                 log_path="privacy_events.jsonl",
                 maks_umur_hari=7, maks_total_mb=500.0):
        self.direktori = direktori_media
        self.log_path = log_path
        self.maks_umur_hari = maks_umur_hari
        self.maks_total_mb = maks_total_mb

    # ------------------------------------------------ jejak privasi
    def catat(self, event, detail=""):
        """Catat peristiwa privasi (metadata saja — tanpa konten media)."""
        entri = {"ts": _sekarang(), "event": str(event),
                 "detail": str(detail)}
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entri, ensure_ascii=False) + "\n")
        return entri

    def baca_log(self, n=50):
        """Baca `n` peristiwa privasi terakhir."""
        if not os.path.exists(self.log_path):
            return []
        hasil = []
        with open(self.log_path, encoding="utf-8") as f:
            for baris in f:
                baris = baris.strip()
                if not baris:
                    continue
                try:
                    hasil.append(json.loads(baris))
                except ValueError:
                    continue
        return hasil[-n:]

    # ------------------------------------------------ retensi
    def _file_media(self):
        """Daftar file media: [(path, ukuran_byte, umur_hari), ...]."""
        hasil = []
        if not os.path.isdir(self.direktori):
            return hasil
        sekarang = time.time()
        for nama in sorted(os.listdir(self.direktori)):
            p = os.path.join(self.direktori, nama)
            if not os.path.isfile(p):
                continue
            if not nama.lower().endswith(EKSTENSI_MEDIA):
                continue
            try:
                st = os.stat(p)
            except OSError:
                continue
            umur_hari = max(0.0, (sekarang - st.st_mtime) / 86400.0)
            hasil.append((p, st.st_size, umur_hari))
        return hasil

    def ringkasan(self):
        """Ringkasan retensi: jumlah, total MB, file tertua, pelanggaran."""
        files = self._file_media()
        total_mb = sum(u for _, u, _ in files) / (1024.0 * 1024.0)
        tertua = max((u for _, _, u in files), default=0.0)
        return {
            "n_file": len(files),
            "total_mb": round(total_mb, 4),
            "umur_tertua_hari": round(tertua, 3),
            "n_melebihi_umur": sum(1 for _, _, u in files
                                   if u > self.maks_umur_hari),
            "melebihi_kuota": total_mb > self.maks_total_mb,
            "maks_umur_hari": self.maks_umur_hari,
            "maks_total_mb": self.maks_total_mb,
        }

    def bersihkan(self, jalankan=False):
        """Terapkan kebijakan retensi. TANPA `jalankan=True` TIDAK ADA
        file yang dihapus — hanya rencana (safe default).

        Urutan: (1) hapus semua yang lebih tua dari maks_umur_hari;
        (2) bila total masih melebihi kuota, hapus file TERLAMA dulu
        sampai kuota terpenuhi.
        """
        files = self._file_media()
        rencana = [p for p, _, umur in files if umur > self.maks_umur_hari]
        sisa = [(p, u, umur) for p, u, umur in files
                if umur <= self.maks_umur_hari]
        total = sum(u for _, u, _ in sisa)
        # kuota: hapus file TERLAMA dulu (umur terbesar) sampai kuota terpenuhi
        sisa.sort(key=lambda x: x[2], reverse=True)
        for p, u, _ in sisa:
            if total / (1024.0 * 1024.0) > self.maks_total_mb:
                rencana.append(p)
                total -= u
        terhapus = []
        if jalankan:
            for p in rencana:
                try:
                    os.unlink(p)
                    terhapus.append(p)
                except OSError:
                    continue
            if terhapus:
                self.catat("RETENSI_DIJALANKAN",
                           f"{len(terhapus)} file dihapus")
        return {"direncanakan": rencana, "terhapus": terhapus,
                "jalankan": bool(jalankan)}

    # ------------------------------------------------ izin file
    def perketatizin(self):
        """Ubah izin file media ke 0o600 (hanya pemilik) di POSIX.

        Return daftar (path, berhasil: bool). Di non-POSIX, tidak
        mengubah apa pun (dihitung False, bukan diklaim berhasil).
        """
        hasil = []
        for p, _, _ in self._file_media():
            try:
                os.chmod(p, 0o600)
                hasil.append((p, True))
            except OSError:
                hasil.append((p, False))
        return hasil

    # ------------------------------------------------ fail-safe blur
    def keputusan_frame_blur(self, blur_berhasil):
        """Kebijakan FAIL-CLOSED untuk pemrosesan blur wajah.

        blur_berhasil=True  -> "LANJUTKAN"  (frame boleh diteruskan)
        blur_berhasil=False -> "TOLAK_FRAME" (frame TIDAK diteruskan —
                              lebih baik kehilangan frame daripada
                              membocorkan wajah yang seharusnya diblur)
        """
        if blur_berhasil:
            return "LANJUTKAN"
        self.catat("BLUR_GAGAL", "frame DITOLAK sesuai kebijakan fail-safe")
        return "TOLAK_FRAME"


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="privacy v2.0 — kebijakan privasi rekaman: ringkasan, "
                    "retensi (dry-run default), izin 0600.")
    ap.add_argument("--dir", default="recordings")
    ap.add_argument("--log", default="privacy_events.jsonl")
    ap.add_argument("--maks-umur-hari", type=float, default=7.0)
    ap.add_argument("--maks-total-mb", type=float, default=500.0)
    ap.add_argument("--bersihkan", action="store_true",
                    help="JALANKAN pembersihan retensi (menghapus file!)")
    sub = ap.parse_args()
    pg = PrivacyGuard(sub.dir, sub.log, sub.maks_umur_hari, sub.maks_total_mb)
    print("[privacy] ringkasan:", json.dumps(pg.ringkasan(),
                                             ensure_ascii=False))
    hasil = pg.bersihkan(jalankan=sub.bersihkan)
    if sub.bersihkan:
        print(f"[privacy] terhapus: {len(hasil['terhapus'])} file")
    else:
        print(f"[privacy] rencana hapus (dry-run): "
              f"{len(hasil['direncanakan'])} file — pakai --bersihkan "
              f"untuk menjalankan")
    izin = pg.perketatizin()
    ok = sum(1 for _, s in izin if s)
    print(f"[privacy] izin 0600 diterapkan pada {ok}/{len(izin)} file "
          f"(POSIX)")


if __name__ == "__main__":
    main()
