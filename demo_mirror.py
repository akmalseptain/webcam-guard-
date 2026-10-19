"""Demo mirroring SATU PERINTAH (lab 1 PC).

Menjalankan mirror_server.py di subprocess, menjawab prompt persetujuan
otomatis (SETUJU + y), MEMBACA kode pairing / token VIEWER / fingerprint
langsung dari output server (tidak ada salin-tempel manual), lalu
menjalankan mirror_viewer.py dengan nilai yang benar.

Pemakaian:
    python demo_mirror.py

Kontrol viewer setelah jendela muncul: p jeda, r lanjut, s stop, q keluar.
Tutup dengan Ctrl-C untuk mengakhiri sesi (server ikut dimatikan).

Catatan keamanan: nilai tetap dipertukarkan melalui stdout server di
mesin yang sama (loopback) — token TIDAK ditulis ke file, tetap hanya
di memori sesi.
"""
import os
import re
import signal
import subprocess
import sys
import threading

BASE = os.path.dirname(os.path.abspath(__file__))
HEX64 = re.compile(r"\b([0-9a-f]{64})\b")


def _baris_server(proc, hasil, siap):
    """Baca stdout server, cetak ulang ke layar, tangkap nilai sesi."""
    for line in proc.stdout:
        print(line, end="")
        if hasil.get("pair") is None:
            m = re.search(r"Kode pairing\s*:\s*([0-9A-F]{4}-[0-9A-F]{4})", line)
            if m:
                hasil["pair"] = m.group(1)
        if hasil.get("fp") is None:
            for m in HEX64.finditer(line):
                # fingerprint dicetak di baris tersendiri SEBELUM token;
                # token VIEWER ditandai labelnya, jadi cek dulu label.
                if "Token" not in line:
                    hasil["fp"] = m.group(1)
                    break
        if hasil.get("tok") is None:
            m = re.search(r"Token VIEWER\s*:\s*([0-9a-f]{64})", line, re.I)
            if m:
                hasil["tok"] = m.group(1)
        if hasil.get("tok") and hasil.get("pair") and hasil.get("fp"):
            siap.set()
            # terus cetak output server berikutnya (menu/status)
            for line2 in proc.stdout:
                print(line2, end="")


def main():
    srv_path = os.path.join(BASE, "mirror_server.py")
    if not os.path.exists(srv_path):
        sys.exit("mirror_server.py tidak ditemukan di folder ini.")

    print("[demo] Menjalankan MIRROR SERVER ...")
    proc = subprocess.Popen(
        [sys.executable, "-u", srv_path],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", cwd=BASE,
    )
    # jawab kedua prompt server secara otomatis
    proc.stdin.write("SETUJU\ny\n")
    proc.stdin.flush()

    hasil = {"pair": None, "tok": None, "fp": None}
    siap = threading.Event()
    t = threading.Thread(
        target=_baris_server, args=(proc, hasil, siap), daemon=True)
    t.start()

    if not siap.wait(timeout=60):
        proc.kill()
        sys.exit("[demo] GAGAL membaca pairing/token/fingerprint dari server "
                 "dalam 60 detik. Jalankan manual: python mirror_server.py")

    pair, tok, fp = hasil["pair"], hasil["tok"], hasil["fp"]
    print("\n[demo] Server siap. Menjalankan VIEWER otomatis ...")
    print(f"[demo] pairing={pair} (tidak perlu disalin — otomatis)\n")

    viewer = subprocess.Popen(
        [sys.executable, os.path.join(BASE, "mirror_viewer.py"), pair,
         "--host", "127.0.0.1", "--role", "viewer",
         "--token", tok, "--pin", fp],
        cwd=BASE,
    )
    try:
        viewer.wait()
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[demo] Viewer selesai. Menutup server ...")
        try:
            viewer.terminate()
        except Exception:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        print("[demo] Sesi mirroring berakhir. Audit: sessions.csv")


if __name__ == "__main__":
    main()
