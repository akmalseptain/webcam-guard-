import cv2
import os
import time

RECORDINGS_DIR = "recordings"
SNAPSHOTS_DIR = "snapshots"
os.makedirs(RECORDINGS_DIR, exist_ok=True)
os.makedirs(SNAPSHOTS_DIR, exist_ok=True)

MIN_AREA = 800        # luas kontur minimum agar dianggap gerakan (px)
RECORD_COOLDOWN = 3.0 # detik jeda antar rekaman otomatis
THRESHOLD = 25        # sensitivitas deteksi gerakan (0-255)


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
    """Tes akses kamera — penting untuk tahu kamera bisa dibuka tanpa peringatan."""
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
    input("\nTekan Enter untuk kembali ke menu...")


def draw_timestamp(frame):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    cv2.putText(frame, ts, (10, 25),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
    return frame


def live_view(camera_index=0):
    cap = cv2.VideoCapture(camera_index)
    if not cap.isOpened():
        print("  [!] Gagal membuka kamera.")
        return
    print("  [*] Live view aktif. Tekan Q di jendela untuk keluar.")
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frame = draw_timestamp(frame)
        cv2.imshow("WebCam Guard - Live View (tekan Q untuk keluar)", frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break
    cap.release()
    cv2.destroyAllWindows()


def motion_detection(camera_index=0):
    """Deteksi gerakan: snapshot + rekam otomatis saat ada gerakan."""
    cap = cv2.VideoCapture(camera_index)
    if not cap.isOpened():
        print("  [!] Gagal membuka kamera.")
        return

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

    print("  [*] Deteksi gerakan aktif. Tekan Q di jendela untuk keluar.")

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray = cv2.GaussianBlur(gray, (21, 21), 0)

        diff = cv2.absdiff(background, gray)
        _, thresh = cv2.threshold(diff, THRESHOLD, 255, cv2.THRESH_BINARY)
        thresh = cv2.dilate(thresh, None, iterations=2)

        contours, _ = cv2.findContours(
            thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

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

            if not recording and (time.time() - last_record_end) > RECORD_COOLDOWN:
                fname = os.path.join(RECORDINGS_DIR, f"rekam_{ts}.mp4")
                fourcc = cv2.VideoWriter_fourcc(*"mp4v")
                fps = cap.get(cv2.CAP_FPS) or 20.0
                writer = cv2.VideoWriter(fname, fourcc, fps,
                                          (frame.shape[1], frame.shape[0]))
                recording = True
                still_frames = 0
                print(f"  [+] Gerakan terdeteksi -> {snap} | mulai rekam {fname}")
            still_frames = 0
        else:
            background = cv2.addWeighted(background, 0.9, gray, 0.1, 0)
            if recording:
                still_frames += 1
                if still_frames > 60:
                    writer.release()
                    writer = None
                    recording = False
                    last_record_end = time.time()
                    print("  [-] Gerakan berhenti, rekaman disimpan.")

        if recording and writer is not None:
            writer.write(frame)

        status = "REKAM" if recording else ("GERAKAN!" if motion else "aman")
        cv2.putText(frame, f"Status: {status}", (10, frame.shape[0] - 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 0), 2)
        frame = draw_timestamp(frame)
        cv2.imshow("WebCam Guard - Motion Detection (Q untuk keluar)", frame)

        if cv2.waitKey(1) & 0xFF == ord("q"):
            break

    if writer is not None:
        writer.release()
    cap.release()
    cv2.destroyAllWindows()


def manual_record(camera_index=0, seconds=10):
    """Rekam video manual selama N detik."""
    cap = cv2.VideoCapture(camera_index)
    if not cap.isOpened():
        print("  [!] Gagal membuka kamera.")
        return
    ret, frame = cap.read()
    if not ret:
        cap.release()
        return
    ts = time.strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(RECORDINGS_DIR, f"manual_{ts}.mp4")
    fps = cap.get(cv2.CAP_FPS) or 20.0
    writer = cv2.VideoWriter(fname, cv2.VideoWriter_fourcc(*"mp4v"),
                             fps, (frame.shape[1], frame.shape[0]))
    print(f"  [*] Merekam {seconds} detik ke {fname} ...")
    start = time.time()
    while time.time() - start < seconds:
        ret, frame = cap.read()
        if not ret:
            break
        writer.write(draw_timestamp(frame))
        cv2.imshow("WebCam Guard - Recording (Q untuk batal)", frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break
    writer.release()
    cap.release()
    cv2.destroyAllWindows()
    print(f"  [+] Selesai: {fname}")


def menu():
    while True:
        print("\n========== WebCam Guard ==========")
        print("1. Live view kamera")
        print("2. Deteksi gerakan (auto snapshot + rekam)")
        print("3. Rekam video manual (10 detik)")
        print("4. Tes akses kamera (cek keamanan)")
        print("5. Keluar")
        pilih = input("Pilih menu [1-5]: ").strip()

        if pilih == "1":
            live_view()
        elif pilih == "2":
            motion_detection()
        elif pilih == "3":
            manual_record()
        elif pilih == "4":
            security_check()
        elif pilih == "5":
            print("Sampai jumpa! Tetap amankan kameramu. :)")
            break
        else:
            print("Pilihan tidak valid.")


if __name__ == "__main__":
    menu()
