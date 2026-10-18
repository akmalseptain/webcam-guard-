import argparse
import csv
import os
import subprocess
import sys
import time
from datetime import datetime

import cv2

# ============================================================
#  WebCam Guard v1.3 — Advanced Cybersecurity Lab Edition
#  Fitur baru vs v1.2 (submenu "A. Lab Lanjutan"):
#   - netmon   : analisis PCAP + metadata DNS/SNI/HTTP + deteksi
#                anomali (port C2, port scan, beaconing) — metadata-only
#   - credcheck: asesmen keamanan kredensial 100% SINTETIS (masked)
#   - redsim   : emulasi red team TERKUNCI lab_scope.json (MITRE ATT&CK)
#   - forensics: timeline + korelasi event + bukti hash-chain
#   - lab_status: dashboard teks status lab
#   - audit_core: RBAC + PBKDF2 + rate limiter + audit tamper-evident
#
#  Fitur v1.2:
#   - Mirror Server: bagikan layar ke penonton lab DENGAN
#     persetujuan eksplisit + kode pairing/token + TLS + audit
#   - Stealth Detector: kenali jejak aplikasi pemantauan
#     tersembunyi dari dataset sintetis (defensif, read-only)
#
#  Fitur v1.1: deteksi wajah + blur, zona pantauan (ROI),
#   multi-kamera, log kejadian (events.csv), headless mode,
#   sensitivitas realtime, counter FPS + HUD status.
#
#  HANYA untuk perangkat milik sendiri / lab yang diotorisasi
#  (edukasi, diawasi dosen). Tidak menyembunyikan proses dan
#  tidak mengambil kredensial/data rahasia apa pun.
# ============================================================

RECORDINGS_DIR = "recordings"
SNAPSHOTS_DIR = "snapshots"
EVENTS_LOG = "events.csv"
os.makedirs(RECORDINGS_DIR, exist_ok=True)
os.makedirs(SNAPSHOTS_DIR, exist_ok=True)

MIN_AREA = 800          # luas kontur minimum agar dianggap gerakan (px)
RECORD_COOLDOWN = 3.0   # detik jeda antar rekaman otomatis
STILL_FRAMES_STOP = 60  # frame tanpa gerakan sebelum rekaman berhenti
FACE_DEDUP_COOLDOWN = 10.0  # detik jeda antar event "wajah terdeteksi"

# Haar cascade bawaan OpenCV (wajah depan)
FACE_CASCADE = cv2.CascadeClassifier(
    cv2.data.haarcascades + "haarcascade_frontalface_default.xml")


# ------------------------------------------------------------
# Logging kejadian (CSV) & statistik
# ------------------------------------------------------------
def log_event(event_type, detail=""):
    """Catat satu kejadian ke events.csv (timestamp, jenis, detail)."""
    baru = not os.path.exists(EVENTS_LOG)
    with open(EVENTS_LOG, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if baru:
            w.writerow(["timestamp", "event", "detail"])
        w.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    event_type, detail])


def show_stats():
    """Ringkasan semua kejadian yang tercatat di events.csv."""
    print("\n[=] ===== Statistik Kejadian =====")
    if not os.path.exists(EVENTS_LOG):
        print("  Belum ada kejadian tercatat. Jalankan mode deteksi dulu.")
        return
    rows = []
    with open(EVENTS_LOG, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # lewati header
        rows = list(reader)
    if not rows:
        print("  Log kosong.")
        return
    total = len(rows)
    hari_ini = datetime.now().strftime("%Y-%m-%d")
    n_hari_ini = sum(1 for r in rows if r and r[0].startswith(hari_ini))
    per_jenis = {}
    for r in rows:
        if len(r) >= 2:
            per_jenis[r[1]] = per_jenis.get(r[1], 0) + 1
    print(f"  Total kejadian   : {total}")
    print(f"  Kejadian hari ini: {n_hari_ini}")
    print("  Per jenis:")
    for jenis, n in sorted(per_jenis.items(), key=lambda x: -x[1]):
        print(f"    - {jenis:<20} {n}x")
    print(f"  Kejadian terakhir: {rows[-1][0]} ({rows[-1][1]})")


# ------------------------------------------------------------
# Utilitas kamera
# ------------------------------------------------------------
def list_cameras(max_index=5):
    """Tes kamera mana saja yang bisa diakses (cek keamanan)."""
    available = []
    for i in range(max_index):
        cap = cv2.VideoCapture(i, cv2.CAP_ANY)
        if cap.isOpened():
            ret, _ = cap.read()
            if ret:
                available.append(i)
            cap.release()
    return available


def security_check():
    """Tes akses kamera — bukti program biasa bisa buka kamera tanpa peringatan."""
    print("\n[?] Menguji akses kamera...")
    cams = list_cameras()
    if not cams:
        print("  [!] TIDAK ada kamera yang bisa dibuka program ini.")
        print("      (Bagus! Berarti kamera terkunci dengan baik, atau driver bermasalah.)")
    else:
        print(f"  [+] Kamera yang dapat diakses index: {cams}")
        print("      Artinya: program Python biasa BISA membuka kamera tanpa peringatan.")
        print("      Pelajaran keamanan: siapapun dengan akses laptopmu bisa melakukan hal yang sama.")
        print("      Proteksi: tutup lensa dengan cover, dan audit aplikasi yang punya izin kamera.")
        log_event("tes_akses", f"kamera={cams}")
    input("\nTekan Enter untuk kembali ke menu...")


def draw_timestamp(frame):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    cv2.putText(frame, ts, (10, 25),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
    return frame


def draw_hud(frame, status, fps, zone, threshold):
    """HUD: status, FPS, zona, sensitivitas."""
    h, w = frame.shape[:2]
    cv2.putText(frame, f"Status: {status}", (10, h - 34),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 0), 2)
    cv2.putText(frame, f"FPS: {fps:5.1f}  Sens: {threshold}", (10, h - 12),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 0), 2)
    if zone:
        x, y, zw, zh = zone
        cv2.rectangle(frame, (x, y), (x + zw, y + zh), (0, 255, 255), 2)
        cv2.putText(frame, "ZONA", (x, max(15, y - 8)),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 1)
    return frame


def open_camera(index):
    cap = cv2.VideoCapture(index)
    if not cap.isOpened():
        print(f"  [!] Gagal membuka kamera index {index}.")
        return None
    return cap


# ------------------------------------------------------------
# Mode 1: Live view (C = ganti kamera)
# ------------------------------------------------------------
def live_view(camera_index=0):
    cap = open_camera(camera_index)
    if cap is None:
        return
    idx = camera_index
    print("  [*] Live view. Tombol: Q keluar | C ganti kamera")
    prev = time.time()
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        now = time.time()
        fps = 1.0 / max(now - prev, 1e-6)
        prev = now
        frame = draw_timestamp(frame)
        cv2.putText(frame, f"Kamera {idx}  FPS {fps:5.1f}", (10, 50),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 0), 2)
        cv2.imshow("WebCam Guard - Live View", frame)
        key = cv2.waitKey(1) & 0xFF
        if key == ord("q"):
            break
        if key == ord("c"):
            cap.release()
            cv2.destroyAllWindows()
            idx = (idx + 1) % 5
            cap = open_camera(idx)
            if cap is None:
                return
            log_event("ganti_kamera", f"index={idx}")
    cap.release()
    cv2.destroyAllWindows()


# ------------------------------------------------------------
# Mode 2: Deteksi gerakan + zona pantauan
# ------------------------------------------------------------
def motion_detection(camera_index=0, headless=False, threshold=25):
    cap = open_camera(camera_index)
    if cap is None:
        return
    zone = None  # (x, y, w, h) zona pantauan; None = seluruh frame

    ret, frame = cap.read()
    if not ret:
        cap.release()
        return
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    gray = cv2.GaussianBlur(gray, (21, 21), 0)
    background = gray

    recording = False
    writer = None
    last_record_end = 0.0
    still_frames = 0
    prev = time.time()

    if headless:
        print("  [*] HEADLESS: log gerakan tanpa GUI. Tekan Ctrl+C untuk berhenti.")
    else:
        print("  [*] Tombol: Q keluar | C kamera | Z zona | +/- sensitivitas")

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            now = time.time()
            fps = 1.0 / max(now - prev, 1e-6)
            prev = now

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            gray = cv2.GaussianBlur(gray, (21, 21), 0)

            diff = cv2.absdiff(background, gray)
            _, thresh_img = cv2.threshold(diff, threshold, 255, cv2.THRESH_BINARY)
            thresh_img = cv2.dilate(thresh_img, None, iterations=2)

            # Mask zona: nol-kan area di luar zona supaya hanya gerakan
            # DI DALAM zona yang terhitung.
            if zone:
                mask = np_zero_like(thresh_img)
                x, y, zw, zh = zone
                mask[y:y + zh, x:x + zw] = thresh_img[y:y + zh, x:x + zw]
                thresh_img = mask

            contours, _ = cv2.findContours(
                thresh_img.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

            motion = False
            for c in contours:
                if cv2.contourArea(c) < MIN_AREA:
                    continue
                motion = True
                (x, y, w, h) = cv2.boundingRect(c)
                cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 0, 255), 2)
                cv2.putText(frame, "GERAKAN!", (x, y - 10),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)

            if motion:
                ts = time.strftime("%Y%m%d_%H%M%S")
                snap = os.path.join(SNAPSHOTS_DIR, f"gerakan_{ts}.jpg")
                cv2.imwrite(snap, frame)
                log_event("gerakan", snap)

                if not recording and (time.time() - last_record_end) > RECORD_COOLDOWN:
                    fname = os.path.join(RECORDINGS_DIR, f"rekam_{ts}.mp4")
                    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
                    fps_rec = cap.get(cv2.CAP_PROP_FPS) or 20.0
                    writer = cv2.VideoWriter(fname, fourcc, fps_rec,
                                             (frame.shape[1], frame.shape[0]))
                    recording = True
                    still_frames = 0
                    log_event("mulai_rekam", fname)
                    print(f"  [+] Gerakan -> {snap} | rekam {fname}")
                still_frames = 0
            else:
                background = cv2.addWeighted(background, 0.9, gray, 0.1, 0)
                if recording:
                    still_frames += 1
                    if still_frames > STILL_FRAMES_STOP:
                        writer.release()
                        writer = None
                        recording = False
                        last_record_end = time.time()
                        log_event("stop_rekam", "gerakan berhenti")
                        print("  [-] Gerakan berhenti, rekaman disimpan.")

            if recording and writer is not None:
                writer.write(frame)

            if not headless:
                status = "REKAM" if recording else ("GERAKAN!" if motion else "aman")
                frame = draw_timestamp(frame)
                frame = draw_hud(frame, status, fps, zone, threshold)
                cv2.imshow("WebCam Guard - Motion Detection", frame)
                key = cv2.waitKey(1) & 0xFF
                if key == ord("q"):
                    break
                if key == ord("c"):
                    cap.release()
                    cv2.destroyAllWindows()
                    cap = open_camera(camera_index + 1)
                    if cap is None:
                        return
                if key == ord("z"):
                    sel = cv2.selectROI("Pilih zona lalu Enter (Esc batal)",
                                       frame, showCrosshair=False)
                    cv2.destroyWindow("Pilih zona lalu Enter (Esc batal)")
                    zone = sel if sel[2] > 0 and sel[3] > 0 else None
                    log_event("zona", str(zone))
                if key in (ord("+"), ord("=")):
                    threshold = min(threshold + 5, 100)
                if key == ord("-"):
                    threshold = max(threshold - 5, 5)
    except KeyboardInterrupt:
        print("\n  [*] Dihentikan oleh user (Ctrl+C).")
    finally:
        if writer is not None:
            writer.release()
        cap.release()
        cv2.destroyAllWindows()


def np_zero_like(img):
    """Nol-kan gambar (pengganti numpy untuk mask zona)."""
    h, w = img.shape[:2]
    return cv2.multiply(img, 0)  # trik tanpa numpy: kalikan 0


# ------------------------------------------------------------
# Mode baru: Deteksi wajah + blur privasi
# ------------------------------------------------------------
def face_guard(camera_index=0):
    """Deteksi wajah (Haar cascade); tekan B untuk blur wajah (privasi)."""
    cap = open_camera(camera_index)
    if cap is None:
        return
    blur_on = True
    last_face_event = 0.0
    prev = time.time()
    print("  [*] Face Guard. Tombol: Q keluar | B blur on/off")
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        now = time.time()
        fps = 1.0 / max(now - prev, 1e-6)
        prev = now

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = FACE_CASCADE.detectMultiScale(
            gray, scaleFactor=1.1, minNeighbors=5, minSize=(60, 60))

        n_wajah = 0
        for (x, y, w, h) in faces:
            n_wajah += 1
            if blur_on:
                roi = frame[y:y + h, x:x + w]
                frame[y:y + h, x:x + w] = cv2.GaussianBlur(roi, (45, 45), 0)
                cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)
                cv2.putText(frame, "WAJAH (blur)", (x, y - 8),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 0), 1)
            else:
                cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 255), 2)
                cv2.putText(frame, "WAJAH", (x, y - 8),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 255), 1)

        # Dedup event: catat "wajah terdeteksi" max 1x per FACE_DEDUP_COOLDOWN
        if n_wajah > 0 and (time.time() - last_face_event) > FACE_DEDUP_COOLDOWN:
            last_face_event = time.time()
            log_event("wajah", f"jumlah={n_wajah} blur={'on' if blur_on else 'off'}")
            print(f"  [+] Wajah terdeteksi: {n_wajah} (blur {'aktif' if blur_on else 'nonaktif'})")

        frame = draw_timestamp(frame)
        cv2.putText(frame, f"Wajah: {n_wajah}  FPS: {fps:5.1f}  Blur: {'ON' if blur_on else 'OFF'}",
                    (10, 50), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 0), 2)
        cv2.imshow("WebCam Guard - Face Guard", frame)
        key = cv2.waitKey(1) & 0xFF
        if key == ord("q"):
            break
        if key == ord("b"):
            blur_on = not blur_on
            log_event("toggle_blur", "on" if blur_on else "off")
    cap.release()
    cv2.destroyAllWindows()


# ------------------------------------------------------------
# Mode 3: Rekam manual
# ------------------------------------------------------------
def manual_record(camera_index=0, seconds=10):
    cap = open_camera(camera_index)
    if cap is None:
        return
    ret, frame = cap.read()
    if not ret:
        cap.release()
        return
    ts = time.strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(RECORDINGS_DIR, f"manual_{ts}.mp4")
    fps = cap.get(cv2.CAP_PROP_FPS) or 20.0
    writer = cv2.VideoWriter(fname, cv2.VideoWriter_fourcc(*"mp4v"),
                             fps, (frame.shape[1], frame.shape[0]))
    print(f"  [*] Merekam {seconds} detik ke {fname} ...")
    start = time.time()
    while time.time() - start < seconds:
        ret, frame = cap.read()
        if not ret:
            break
        writer.write(draw_timestamp(frame))
        cv2.imshow("WebCam Guard - Recording (Q batal)", frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break
    writer.release()
    cap.release()
    cv2.destroyAllWindows()
    log_event("rekam_manual", fname)
    print(f"  [+] Selesai: {fname}")


# ------------------------------------------------------------
# Menu & CLI
# ------------------------------------------------------------
def _python_exe():
    """Path interpreter saat ini (agar venv ikut terpakai)."""
    return sys.executable or "python"


def lab_lanjutan():
    """Submenu Laboratorium Lanjutan (v1.3) — semua modul stdlib-only."""
    while True:
        print("\n---------- LAB LANJUTAN (v1.3) ----------")
        print("1. netmon — demo analisis paket sintetis")
        print("2. netmon — live capture (butuh tcpdump/tshark/dumpcap)")
        print("3. credcheck — asesmen kredensial (100% sintetis)")
        print("4. redsim — emulasi red team (scope-enforced)")
        print("5. forensics — timeline + korelasi + laporan")
        print("6. lab_status — dashboard status lab")
        print("0. Kembali ke menu utama")
        pilih = input("Pilih [0-6]: ").strip()
        exe = _python_exe()
        if pilih == "1":
            subprocess.run([exe, "netmon.py", "--demo"])
        elif pilih == "2":
            iface = input("Antarmuka lab (mis. eth0): ").strip() or "eth0"
            menit = input("Durasi menit [1]: ").strip() or "1"
            subprocess.run([exe, "netmon.py", "--capture-iface", iface,
                            "--minutes", menit, "--save-pcap",
                            "captures/lab_capture.pcap"])
        elif pilih == "3":
            subprocess.run([exe, "credcheck.py"])
        elif pilih == "4":
            subprocess.run([exe, "redsim.py"])
        elif pilih == "5":
            subprocess.run([exe, "forensics.py"])
        elif pilih == "6":
            subprocess.run([exe, "lab_status.py"])
        elif pilih == "0":
            return
        else:
            print("Pilihan tidak valid.")


def petunjuk_viewer():
    """Petunjuk menjalankan penonton di laptop kedua (lab)."""
    print("\n[i] ===== Mirror Viewer (laptop penonton) =====")
    print("  1. Dari pengirim (menu 8): salin KODE PAIRING + TOKEN (admin/viewer).")
    print("  2. Di laptop penonton, jalankan:")
    print("       python mirror_viewer.py KODE-PAIRING --host <ip-pengirim> --role viewer --token TOKEN")
    print("  3. Kontrol penonton: p=jeda, r=lanjut, s=minta stop, q=keluar.")
    print("  4. Pengirim bisa jeda/stop/mencabut penonton kapan saja;")
    print("     semua sesi tercatat di sessions.csv pada sisi pengirim.")
    input("\nTekan Enter untuk kembali ke menu...")


def menu(camera_index):
    while True:
        print("\n========== WebCam Guard v1.3 ==========")
        print("1. Live view kamera")
        print("2. Deteksi gerakan (zona + auto rekam)")
        print("3. Face Guard (deteksi wajah + blur privasi)")
        print("4. Rekam video manual (10 detik)")
        print("5. Statistik kejadian (log CSV)")
        print("6. Tes akses kamera (cek keamanan)")
        print("7. Stealth Detector (simulasi defensif, dataset sintetis)")
        print("8. Mirror Server (bagikan layar dgn persetujuan eksplisit)")
        print("9. Petunjuk Mirror Viewer (untuk laptop penonton)")
        print("A. Lab Lanjutan (netmon/credcheck/redsim/forensics/status)")
        print("0. Keluar")
        pilih = input("Pilih menu [0-9A]: ").strip()

        if pilih == "1":
            live_view(camera_index)
        elif pilih == "2":
            motion_detection(camera_index)
        elif pilih == "3":
            face_guard(camera_index)
        elif pilih == "4":
            manual_record(camera_index)
        elif pilih == "5":
            show_stats()
        elif pilih == "6":
            security_check()
        elif pilih == "7":
            print("  [*] Menjalankan Stealth Detector (dataset sintetis)...")
            print("      Periksa juga folder startup laptop nyata:")
            print("      python stealth_sim.py --lokal")
            subprocess.run([_python_exe(), "stealth_sim.py"])
        elif pilih == "8":
            print("  [*] Menjalankan Mirror Server — persetujuan eksplisit wajib.")
            subprocess.run([_python_exe(), "mirror_server.py"])
        elif pilih == "9":
            petunjuk_viewer()
        elif pilih in ("A", "a"):
            lab_lanjutan()
        elif pilih == "0":
            print("Sampai jumpa! Tetap amankan perangkatmu. :)")
            break
        else:
            print("Pilihan tidak valid.")


def main():
    parser = argparse.ArgumentParser(
        description="WebCam Guard v1.3 — pengawasan webcam lokal + lab "
                    "mirroring (persetujuan eksplisit) + stealth detector "
                    "defensif + lab lanjutan (netmon/credcheck/redsim/"
                    "forensics)")
    parser.add_argument("-c", "--camera", type=int, default=0, help="index kamera (default: 0)")
    parser.add_argument("--headless", action="store_true", help="mode tanpa GUI: log gerakan ke CSV saja")
    parser.add_argument("-t", "--threshold", type=int, default=25, help="sensitivitas deteksi gerakan 5-100 (default: 25)")
    args = parser.parse_args()

    if args.headless:
        log_event("start_headless", f"kamera={args.camera}")
        motion_detection(args.camera, headless=True, threshold=args.threshold)
    else:
        menu(args.camera)


if __name__ == "__main__":
    main()
