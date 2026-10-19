"""Demo mirroring SATU PERINTAH + SATU JENDELA (lab 1 PC).

Menjalankan mirror_server.py sebagai subprocess, menjawab prompt
persetujuan otomatis (SETUJU + y), MEMBACA kode pairing / token VIEWER /
fingerprint langsung dari output server, lalu menjalankan logika viewer
DI DALAM proses ini (bukan subprocess) — sehingga jendela stream tidak
pernah yatim: Ctrl-C di terminal mematikan server DAN stream bersama.

Pemakaian:
    python demo_mirror.py

Kontrol stream setelah jendela muncul: p jeda, r lanjut, q keluar.
Ctrl-C di terminal mengakhiri seluruh sesi. Menutup jendela stream dengan
tombol X juga mengakhiri sesi (bukan memunculkan jendela baru tiap frame).
Hanya SATU instance demo yang boleh jalan (mutex) — instance kedua
menolak jalan agar jendela stream tidak menumpuk.
"""
import json
import os
import re
import subprocess
import sys
import threading
import time

import mirror_stream

BASE = os.path.dirname(os.path.abspath(__file__))
HEX64 = re.compile(r"\b([0-9a-f]{64})\b")
JUDUL = "WebCam Guard Mirror (lab — persetujuan aktif)"
MUTEX_NAME = "Local\\webcam_guard_demo_mirror"


def _kunci_satu_instance():
    """Mutex Windows: satu-satunya instance demo yang boleh jalan.

    Tanpa ini, demo kedua yang dijalankan bersamaan memunculkan jendela
    stream kedua/ketiga — sumber 'jendela terlalu banyak'. Mutex dilepas
    otomatis OS saat proses mati, jadi crash tidak mengunci selamanya.
    Return: handle (boleh jalan), False (sudah ada instance lain),
    None (non-Windows / mutex gagal dibuat — lanjut tanpa guard).
    """
    if sys.platform != "win32":
        return None
    import ctypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = k32.CreateMutexW(None, False, MUTEX_NAME)
    if not handle:
        return None
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        return False
    return handle


def _matikan_sisa_windows():
    """Matikan HANYA proses demo/server/viewer lama yang masih hidup.

    Versi lalu: taskkill /IM python.exe membunuh SEMUA python di laptop
    (IDE, agent CLI, jupyter) dan error-nya di-silent — kalau gagal,
    sisa jendela stream menumpuk tanpa peringatan. Versi ini memilih PID
    berdasarkan nama proses python* + command line skrip mirror, lalu
    melaporkan tiap hasil secara jujur.
    """
    ps_cmd = (
        "Get-CimInstance Win32_Process | Where-Object { "
        "$_['Name'] -like 'python*' -and $_.CommandLine -match "
        "'demo_mirror[.]py|mirror_server[.]py|mirror_viewer[.]py' } | "
        "Select-Object ProcessId | ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                           ps_cmd],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"[demo] Pembersihan sisa dilewati: {e}")
        return
    if not r.stdout.strip():
        return
    try:
        data = json.loads(r.stdout)
    except ValueError:
        return
    if isinstance(data, dict):
        data = [data]
    for p in data:
        pid = p.get('ProcessId')
        if not pid or int(pid) == os.getpid():
            continue
        k = subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, text=True)
        if k.returncode == 0:
            print(f"[demo] Sisa sesi lama dimatikan: PID {pid}")
        else:
            print(f"[demo] GAGAL mematikan PID {pid} "
                  f"({(k.stderr or k.stdout).strip()}) — tutup manual "
                  "jendela stream lama itu.")


def _baris_server(proc, hasil):
    """Baca stdout server; tangkap pairing/fingerprint/token/aktif."""
    for line in proc.stdout:
        if hasil.get("pair") is None:
            m = re.search(r"Kode pairing\s*:\s*([0-9A-F]{4}-[0-9A-F]{4})", line)
            if m:
                hasil["pair"] = m.group(1)
        if hasil.get("fp") is None:
            for m in HEX64.finditer(line):
                if "Token" not in line:
                    hasil["fp"] = m.group(1)
                    break
        if hasil.get("tok") is None:
            m = re.search(r"Token VIEWER\s*:\s*([0-9a-f]{64})", line, re.I)
            if m:
                hasil["tok"] = m.group(1)
        if "Sesi AKTIF" in line:
            hasil["aktif"] = True
    hasil["mati"] = True


def jalankan_viewer(pair, tok, fp):
    """Logika viewer mirror_viewer.py, IN-PROCESS (jendela stream milik
    proses demo ini — mati bersama proses, tidak yatim)."""
    import socket
    import cv2
    import numpy as np

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(30)
    raw.connect(("127.0.0.1", 8443))
    sock = mirror_stream.make_client_ssl_ctx().wrap_socket(raw)
    der = sock.getpeercert(binary_form=True)
    if not mirror_stream.pin_cocok(der, fp):
        print("!! PIN TIDAK COCOK — kemungkinan MITM. Batal.")
        sock.close()
        sys.exit(3)

    mirror_stream.kirim_json(sock, {"cmd": "HELLO", "kode": pair,
                                    "role": "viewer", "token": tok})
    resp = mirror_stream.terima_json(sock)
    if resp.get("cmd") != "WELCOME":
        print(f"Ditolak server: {resp.get('alasan', resp)}")
        sock.close()
        sys.exit(1)

    print(f"\n[demo] TERHUBUNG: {resp.get('device')} — stream aktif.")
    print("[demo] Kontrol jendela stream: p jeda | r lanjut | q keluar "
          "| Ctrl-C (terminal) akhiri sesi.\n")
    berhenti = False
    jendela_ada = False
    try:
        while not berhenti:
            jenis, data = mirror_stream.terima_frame(sock)
            if jenis == "FRM":
                img = cv2.imdecode(np.frombuffer(data, np.uint8),
                                   cv2.IMREAD_COLOR)
                if img is not None:
                    # Tutup-X pengguna: akhiri sesi SEBELUM imshow
                    # memunculkan jendela baru tiap frame.
                    if jendela_ada and cv2.getWindowProperty(
                            JUDUL, cv2.WND_PROP_VISIBLE) < 1:
                        print("[demo] Jendela stream ditutup (X) — "
                              "mengakhiri sesi.")
                        mirror_stream.kirim_json(sock, {"cmd": "LEAVE"})
                        berhenti = True
                        continue
                    cv2.imshow(JUDUL, img)
                    jendela_ada = True
                    key = cv2.waitKey(30) & 0xFF
                    if key == ord("p"):
                        mirror_stream.kirim_json(sock, {"cmd": "PAUSE"})
                    elif key == ord("r"):
                        mirror_stream.kirim_json(sock, {"cmd": "RESUME"})
                    elif key == ord("q"):
                        mirror_stream.kirim_json(sock, {"cmd": "LEAVE"})
                        berhenti = True
            else:
                cmd = data.get("cmd")
                if cmd == "STOP":
                    print("Pengirim menghentikan sesi.")
                    break
                if cmd == "STOP_DENIED":
                    pass  # viewer memang tidak boleh stop
                elif cmd == "PAUSED":
                    print("[jeda — tekan r untuk lanjut]")
                elif cmd == "REVOKED":
                    print("Akses dicabut pengirim.")
                    break
                elif cmd == "BYE":
                    break
    finally:
        try:
            cv2.destroyAllWindows()
        except Exception:
            pass
        try:
            sock.close()
        except OSError:
            pass


def main():
    srv_path = os.path.join(BASE, "mirror_server.py")
    if not os.path.exists(srv_path):
        sys.exit("mirror_server.py tidak ditemukan di folder ini.")

    mutex = _kunci_satu_instance()
    if mutex is False:
        sys.exit("[demo] Demo mirror SUDAH berjalan di jendela lain. Akhiri "
                 "sesi itu dulu (q di jendela stream / Ctrl-C di "
                 "terminalnya), lalu jalankan lagi.")

    # Matikan hanya proses demo/server/viewer LAMA — bukan semua
    # python di laptop (lihat _matikan_sisa_windows).
    if sys.platform == "win32":
        _matikan_sisa_windows()

    print("[demo] Server menyala... tunggu jendela stream muncul.")
    proc = subprocess.Popen(
        [sys.executable, "-u", srv_path],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", cwd=BASE,
    )
    proc.stdin.write("SETUJU\ny\n")
    proc.stdin.flush()

    hasil = {"pair": None, "tok": None, "fp": None}
    threading.Thread(target=_baris_server, args=(proc, hasil),
                     daemon=True).start()

    for _ in range(60):
        if hasil.get("tok") and hasil.get("pair") and hasil.get("fp"):
            break
        if proc.poll() is not None:
            sys.exit("[demo] Server mati di awal. Jalankan manual: "
                     "python mirror_server.py")
        time.sleep(1)
    else:
        proc.kill()
        sys.exit("[demo] GAGAL membaca pairing/token/fingerprint (60 dtk).")

    # Tunggu server mencetak "Sesi AKTIF" (= port listening). Jangan
    # probe port — soket server adalah SSL socket; probe TCP yang
    # langsung ditutup akan menyangkut thread accept server.
    for _ in range(60):
        if hasil.get("aktif"):
            break
        if hasil.get("mati") or proc.poll() is not None:
            sys.exit("[demo] Server mati sebelum listening.")
        time.sleep(1)
    else:
        proc.kill()
        sys.exit("[demo] Server tidak mencapai 'Sesi AKTIF' (60 dtk).")
    time.sleep(1.0)  # margin kecil sebelum connect

    try:
        jalankan_viewer(hasil["pair"], hasil["tok"], hasil["fp"])
    except KeyboardInterrupt:
        print("\n[demo] Ctrl-C — menutup sesi.")
    except (ConnectionError, OSError) as e:
        print(f"[demo] Koneksi bermasalah: {e}")
    finally:
        print("[demo] Menutup server ...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        print("[demo] Sesi mirroring berakhir. Audit: sessions.csv")


if __name__ == "__main__":
    main()
