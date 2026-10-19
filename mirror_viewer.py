"""mirror_viewer.py — Penonton: dashboard melihat layar pengirim (LAB, v2.0).

Penggunaan:
  python mirror_viewer.py KODE-PAIRING --host <ip> --role admin \
      --token TOKEN --pin SHA256-FINGERPRINT

v2.0 — PIN WAJIB-EFEKTIF (anti-MITM):
  Tanpa --pin                → hard exit 2 (dengan peringatan keras):
                              klien menolak menerima sertifikat siapa pun.
  Pin TIDAK cocok            → koneksi ditutup SEBELUM data aplikasi
                              dikirim, exit 3.
  Pin cocok                  → lanjut (trust via pinning, bukan CA).
  (Dulu v1.2: CERT_NONE tanpa pinning — MITM di jaringan lab mungkin.)

Kontrol (terlihat oleh penonton):
  p = minta jeda | r = minta lanjut | s = minta stop (admin-only,
  viewer menerima STOP_DENIED) | q = keluar

PENGIRIM memegang kendali penuh: ia bisa jeda/stop/mencabut penonton
kapan pun dari menunya. Koneksi dibungkus TLS (min TLSv1.2, timeout 30 s).
"""

import argparse
import socket
import sys

import mirror_auth
import mirror_stream

KONTROL = """
----------------- KONTROL PENONTON -----------------
  p = minta jeda       r = minta lanjut
  s = minta stop       q = keluar (LEAVE)
  (s hanya efektif untuk role admin — viewer menerima STOP_DENIED)
----------------------------------------------------
Pengirim bisa menolak/mencabut akses Anda kapan saja.
"""


def main():
    ap = argparse.ArgumentParser(
        description="WebCam Guard v2.0 — Mirror Viewer (lab): lihat layar "
                    "yang DIBAGIKAN SUKARELA melalui TLS ter-PIN.")
    ap.add_argument("kode", help="kode pairing dari pengirim (XXXX-XXXX)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--role", default="viewer", choices=mirror_auth.ROLES)
    ap.add_argument("--token", required=True,
                    help="token dari pengirim (diterima out-of-band)")
    ap.add_argument("--pin", required=True,
                    help="WAJIB (v2.0): SHA-256 fingerprint sertifikat "
                         "yang dicetak pengirim — tanpa ini klien menolak "
                         "koneksi (anti-MITM)")
    args = ap.parse_args()

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(30)
    raw.connect((args.host, args.port))
    sock = mirror_stream.make_client_ssl_ctx().wrap_socket(raw)

    # v2.0: verifikasi PIN SEBELUM mengirim data aplikasi apa pun.
    # self-signed TIDAK dipercaya hanya karena self-signed.
    der = sock.getpeercert(binary_form=True)
    if not mirror_stream.pin_cocok(der, args.pin):
        print("!! PIN TIDAK COCOK — sertifikat server bukan yang diharapkan.")
        print("!! Kemungkinan MITM. Koneksi ditutup SEBELUM data dikirim.")
        try:
            sock.close()
        except OSError:
            pass
        sys.exit(3)

    mirror_stream.kirim_json(sock, {"cmd": "HELLO", "kode": args.kode,
                                     "role": args.role, "token": args.token})
    resp = mirror_stream.terima_json(sock)
    if resp.get("cmd") != "WELCOME":
        print(f"Ditolak server: {resp.get('alasan', resp)}")
        try:
            sock.close()
        except OSError:
            pass
        sys.exit(1)

    print(f"Terhubung : {resp.get('device')}")
    print(f"Sesi      : {resp.get('state')} | ID Anda: {resp.get('id')}")
    print(KONTROL)

    try:
        import cv2
        import numpy as np
    except ImportError as e:
        try:
            sock.close()
        except OSError:
            pass
        sys.exit(f"opencv/numpy belum terpasang ({e}). "
                 "Jalankan: pip install -r requirements.txt")

    berhenti = False
    try:
        while not berhenti:
            jenis, data = mirror_stream.terima_frame(sock)
            if jenis == "FRM":
                img = cv2.imdecode(np.frombuffer(data, np.uint8),
                                   cv2.IMREAD_COLOR)
                if img is not None:
                    cv2.imshow("WebCam Guard Mirror (lab - persetujuan aktif)",
                               img)
                    key = cv2.waitKey(30) & 0xFF
                    if key == ord("p"):
                        mirror_stream.kirim_json(sock, {"cmd": "PAUSE"})
                    elif key == ord("r"):
                        mirror_stream.kirim_json(sock, {"cmd": "RESUME"})
                    elif key == ord("s"):
                        mirror_stream.kirim_json(sock, {"cmd": "STOP_REQ"})
                    elif key == ord("q"):
                        mirror_stream.kirim_json(sock, {"cmd": "LEAVE"})
                        berhenti = True
            else:
                cmd = data.get("cmd")
                if cmd == "STOP":
                    print("Pengirim menghentikan sesi. Terima kasih.")
                    break
                if cmd == "STOP_DENIED":
                    print("STOP_DENIED — hanya admin yang bisa "
                          "menghentikan sesi.")
                elif cmd == "PAUSED":
                    print("[jeda — tekan r untuk minta dilanjutkan]")
                elif cmd == "REVOKED":
                    print("Akses Anda dicabut oleh pengirim.")
                    break
                elif cmd == "BYE":
                    break
    except (ConnectionError, OSError) as e:
        print(f"Koneksi berakhir: {e}")
    finally:
        try:
            cv2.destroyAllWindows()
        except Exception:
            pass
        try:
            sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    main()
