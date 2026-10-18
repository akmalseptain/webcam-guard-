"""stealth_sim.py — Detektor DEFENSIF aplikasi pemantauan tersembunyi (LAB).

Tujuan edukasi: modul ini TIDAK menyembunyikan proses dan TIDAK
mengambil data rahasia apa pun. Justru sebaliknya — ia mendemonstrasikan
jejak yang biasanya ditinggalkan tool pemantauan (spyware) supaya Anda
bisa mengenalinya, lalu memindai empat kategori indikator:

1. Proses dengan nama/lokasi mencurigakan     (dataset sintetis)
2. Koneksi jaringan ke tujuan tidak wajar     (dataset sintetis)
3. Mekanisme persistensi/startup otomatis     (dataset sintetis
   + folder startup NYATA laptop Anda, read-only)
4. Aplikasi dengan kombinasi izin berlebihan  (dataset sintetis)

Dataset sintetis: stealth_dataset.json (tidak ada data nyata).
Pemakaian:
  python stealth_sim.py                 # pindai dataset + tampilkan dashboard
  python stealth_sim.py --lokal         # + periksa folder startup laptop ini
"""

import argparse
import json
import os

DATASET_DEFAULT = "stealth_dataset.json"

# Pola nama proses khas tool pemantauan — dipakai UNTUK DIKENALI.
POLA_PROSES = ("keylog", "hook", "spy", "rat", "sniff", "capture",
               "screenshot", "vnc", "remote_view", "silent")
PORT_TERCURIGA = (4444, 5555, 1337, 4445, 8888, 31337)

# Nama startup yang lazim & wajar (tidak diperlakukan mencurigakan).
NAMA_WAJAR = ("steam", "onedrive", "adobe", "google", "microsoft",
              "spotify", "discord", "zoom", "update")

# Lokasi persistensi yang sering disalahgunakan — diperiksa READ-ONLY.
PATH_PERSISTENSI = [
    ("~/.config/autostart", "Linux: folder autostart"),
    ("~/Library/LaunchAgents", "macOS: LaunchAgents per-user"),
    ("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
     "Windows: folder Startup"),
    ("~\\AppData\\Roaming\\Microsoft\\Windows\\CurrentVersion\\Run",
     "Windows: registry Run (nilai key diperiksa manual)"),
]

IZIN_SENSITIF = ("kamera", "mikrofon", "aksesibilitas", "layar", "keylog")


def analisa_proses(daftar):
    """Deteksi proses dengan nama mencurigakan atau berjalan dari folder temp."""
    temuan = []
    for p in daftar:
        nama = str(p.get("nama", "")).lower()
        path = str(p.get("path", "")).lower()
        pola = next((x for x in POLA_PROSES if x in nama), None)
        if pola:
            temuan.append({
                "tipe": "proses", "sev": "TINGGI",
                "temuan": f"proses '{p.get('nama')}' cocok pola '{pola}'",
                "saran": "periksa sumber file & hapus bila tidak dikenal"})
        elif path and ("\\temp\\" in path or "/tmp/" in path):
            temuan.append({
                "tipe": "proses", "sev": "SEDANG",
                "temuan": f"'{p.get('nama')}' berjalan dari folder sementara",
                "saran": "biner di folder temp = indikator klasik malware"})
    return temuan


def analisa_koneksi(daftar):
    """Deteksi koneksi ke port khas C2 / proses mencurigakan."""
    temuan = []
    for k in daftar:
        nama = str(k.get("proses", "")).lower()
        port = int(k.get("port_remote", 0))
        if any(p in nama for p in POLA_PROSES) or port in PORT_TERCURIGA:
            temuan.append({
                "tipe": "koneksi", "sev": "TINGGI",
                "temuan": f"{k.get('proses')} -> {k.get('ip_remote')}:"
                          f"{port} (port/proses khas C2)",
                "saran": "blokir & cari tahu proses induknya"})
        elif port > 20000:
            temuan.append({
                "tipe": "koneksi", "sev": "SEDANG",
                "temuan": f"{k.get('proses')} -> port tinggi {port}",
                "saran": "periksa apakah aplikasi ini memang wajar"})
    return temuan


def analisa_persistensi(daftar):
    """Deteksi item startup/registry dari dataset sintetis."""
    temuan = []
    for e in daftar:
        nama = str(e.get("nama", "")).lower()
        lokasi = str(e.get("lokasi", "")).lower()
        pola = next((x for x in POLA_PROSES if x in nama), None)
        if pola:
            temuan.append({
                "tipe": "persistensi", "sev": "TINGGI",
                "temuan": f"'{e.get('nama')}' persisten di {e.get('lokasi')}",
                "saran": "hapus entri startup & scan dengan antivirus"})
        elif (any(a in lokasi for a in ("startup", "autostart", "launchagent",
                                        "\\run\\", "\\run"))
              and not any(w in nama for w in NAMA_WAJAR)):
            temuan.append({
                "tipe": "persistensi", "sev": "SEDANG",
                "temuan": f"item startup tidak dikenal: '{e.get('nama')}'",
                "saran": "pastikan Anda mengenali item ini"})
    return temuan


def analisa_izin(daftar):
    """Deteksi aplikasi dengan kombinasi izin sensitif berlebihan."""
    temuan = []
    for a in daftar:
        izin = [str(i).lower() for i in a.get("izin", [])]
        sensitif = [i for i in izin if i in IZIN_SENSITIF]
        if len(sensitif) >= 3:
            temuan.append({
                "tipe": "izin", "sev": "TINGGI",
                "temuan": f"'{a.get('aplikasi')}' meminta {len(sensitif)} izin "
                          f"sensitif: {', '.join(sensitif)}",
                "saran": "kombinasi izin seperti ini layak dicurigai"})
        elif len(sensitif) == 2:
            temuan.append({
                "tipe": "izin", "sev": "SEDANG",
                "temuan": f"'{a.get('aplikasi')}' meminta {', '.join(sensitif)}",
                "saran": "wajar untuk konferensi video, tapi periksa ulang"})
    return temuan


def pindai_persistensi_lokal():
    """Periksa folder startup NYATA di laptop ini — READ-ONLY."""
    temuan = []
    for path, deskripsi in PATH_PERSISTENSI:
        p = os.path.expanduser(path)
        if os.path.isdir(p):
            try:
                isi = os.listdir(p)
            except OSError:
                isi = []
            for item in isi:
                temuan.append({
                    "tipe": "persistensi", "sev": "RENDAH",
                    "temuan": f"{item} ({deskripsi})",
                    "saran": "pastikan Anda mengenali item ini"})
    return temuan


def muat_dataset(path=DATASET_DEFAULT):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def pindai_dataset(data):
    """Jalankan keempat analisis terhadap dataset."""
    return {
        "proses": analisa_proses(data.get("proses", [])),
        "koneksi": analisa_koneksi(data.get("koneksi", [])),
        "persistensi": analisa_persistensi(data.get("persistensi", [])),
        "izin": analisa_izin(data.get("izin", [])),
    }


def cetak_dashboard(hasil, lokal=None):
    """Cetak dashboard indikator kompromi (hipotetis)."""
    baris = "=" * 62
    print(baris)
    print(" STEALTH DETECTOR — Dashboard Indikator (simulasi defensif)")
    print(baris)
    total = 0
    for kategori, temuan in hasil.items():
        print(f"\n[{kategori.upper()}] {len(temuan)} temuan")
        for t in temuan:
            total += 1
            print(f"  ({t['sev']}) {t['temuan']}")
            print(f"         -> {t['saran']}")
    if lokal is not None:
        print(f"\n[STARTUP LOKAL — read-only] {len(lokal)} entri")
        for t in lokal:
            total += 1
            print(f"  ({t['sev']}) {t['temuan']}")
            print(f"         -> {t['saran']}")
    print("\n" + baris)
    tinggi = sum(1 for temuan in hasil.values() for t in temuan
                 if t["sev"] == "TINGGI")
    print(f" Total indikator: {total} (TINGGI: {tinggi})")
    print(" Catatan: simulasi edukasi — tidak ada data nyata yang dikumpulkan.")
    return total


def main():
    ap = argparse.ArgumentParser(
        description="Stealth Detector v1.2 (lab) — kenali jejak aplikasi "
                    "pemantauan tersembunyi dari dataset sintetis.")
    ap.add_argument("--dataset", default=DATASET_DEFAULT)
    ap.add_argument("--lokal", action="store_true",
                    help="periksa juga folder startup laptop ini (read-only)")
    args = ap.parse_args()

    data = muat_dataset(args.dataset)
    hasil = pindai_dataset(data)
    lokal = pindai_persistensi_lokal() if args.lokal else None
    cetak_dashboard(hasil, lokal)


if __name__ == "__main__":
    main()
