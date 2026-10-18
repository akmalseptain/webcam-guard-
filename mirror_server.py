"""mirror_server.py — Pengirim: laptop yang layarnya di-mirror (LAB, v2.0).

Alur:
1. Buat kode pairing + token acak 256-bit (admin/viewer) — v2.0 token
   TIDAK dicetak kecuali diminta eksplisit (anti shoulder-surfing/log).
2. ConsentGate: pengirim WAJIB mengetik SETUJU — tidak ada jalur bypass.
3. Pastikan sertifikat TLS (mirror_stream.ensure_cert) -> SSLContext
   (minimum TLSv1.2), cetak FINGERPRINT SHA-256 utk --pin penonton.
4. MirrorServer.listen (token_map: role ditentukan SISI SERVER) ->
   tangkap layar (mss) -> JPEG (cv2) -> broadcast (bounded queue).
5. Menu pengirim: mulai/jeda/lanjut/stop/cabut/status — semua terlihat.

Setiap kejadian tercatat ke sessions.csv (audit trail).
Modul inti (mirror_auth, mirror_stream) stdlib-only; OpenCV/mss/numpy
baru dibutuhkan di sini untuk menangkap layar.
"""

import argparse
import socket
import sys
import threading
import time

import mirror_auth
import mirror_stream

MENU = """
================ PENGIRIM (kendali penuh) ================
[1] MULAI streaming   [2] JEDA             [3] LANJUT
[4] STOP sesi         [5] CABUT penonton   [6] STATUS
[0] Sembunyikan menu (sesi tetap jalan, Ctrl-C untuk stop)
Pilih: """


class PengambilLayar:
    """Tangkap layar -> JPEG. Butuh mss + opencv + numpy di laptop."""

    def __init__(self, kualitas=70):
        import cv2
        import mss
        import numpy  # noqa: F401  (dipakai via frame_jpeg)
        self.cv2 = cv2
        self.kualitas = kualitas
        self.sct = mss.mss()
        self.monitor = self.sct.monitors[1]

    def frame_jpeg(self):
        import numpy as np
        raw = self.sct.grab(self.monitor)
        img = np.asarray(raw)[:, :, :3]  # BGRA -> BGR
        ok, buf = self.cv2.imencode(
            ".jpg", img,
            [int(self.cv2.IMWRITE_JPEG_QUALITY), self.kualitas])
        return buf.tobytes() if ok else None


def menu_pengirim(srv):
    """Kontrol yang SELALU terlihat pengguna — bukan mode tersembunyi."""
    while srv.running:
        try:
            pilih = input(MENU).strip()
        except (EOFError, KeyboardInterrupt):
            srv.stop()
            return
        if pilih == "1":
            srv.state = "aktif"
            mirror_auth.audit_log("MULAI", "pengirim", "streaming aktif")
        elif pilih == "2":
            srv.state = "jeda"
            mirror_auth.audit_log("JEDA", "pengirim", "streaming dijeda")
        elif pilih == "3":
            srv.state = "aktif"
            mirror_auth.audit_log("LANJUT", "pengirim", "streaming dilanjutkan")
        elif pilih == "4":
            srv.stop()
            mirror_auth.audit_log("STOP", "pengirim", "dihentikan pengirim")
            return
        elif pilih == "5":
            with srv.lock:
                daftar = list(srv.clients.keys())
            if not daftar:
                print("  Tidak ada penonton.")
                continue
            for cid in daftar:
                print(f"  - {cid}")
            cid = input("  ID penonton yang dicabut: ").strip()
            if cid in daftar:
                srv.revoke(cid)
                mirror_auth.audit_log("CABUT", "pengirim", f"dicabut: {cid}")
            else:
                print("  ID tidak dikenal.")
        elif pilih == "6":
            print(f"  State sesi: {srv.state} | Penonton: {srv.n_penonton()}")
        elif pilih == "0":
            return


def loop_frame(srv, ambil, fps):
    interval = 1.0 / max(1, fps)
    while srv.running:
        if srv.state == "aktif":
            jpg = ambil.frame_jpeg()
            if jpg:
                srv.broadcast_frame(jpg)
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(
        description="WebCam Guard v2.0 — Mirror Server (lab): bagikan layar "
                    "dengan persetujuan eksplisit, terenkripsi TLS, ter-audit.")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--fps", type=int, default=5)
    ap.add_argument("--kualitas", type=int, default=70)
    args = ap.parse_args()

    kode = mirror_auth.buat_kode_pairing()
    # v2.0: token acak 256-bit per sesi (BUKAN deterministik dari kode
    # pairing seperti v1.3) — role dipetakan SISI SERVER via token_map.
    token_admin = mirror_stream.buat_token_acak()
    token_viewer = mirror_stream.buat_token_acak()
    token_map = {token_admin: "admin", token_viewer: "viewer"}

    print("=" * 58)
    print(" WebCam Guard v2.0 — MIRROR SERVER (Cybersecurity Lab)")
    print("=" * 58)
    print("  Bagikan info ini HANYA kepada dosen/penonton yang Anda")
    print("  otorisasi (out-of-band, mis. WA/email kampus):")
    print(f"    Kode pairing : {kode}")
    print(f"    Listening    : {args.host}:{args.port}")
    print("    Token ADMIN / VIEWER: TIDAK dicetak di layar (v2.0).")
    print("    Penonton memverifikasi server dengan --pin (anti-MITM).")

    gate = mirror_auth.ConsentGate()
    while True:
        jawab = input("\nKetik SETUJU untuk mengizinkan mirroring layar ini: ")
        if gate.minta(jawab):
            break
        print("  Tidak disetujui — mirroring tidak boleh dimulai.")
    mirror_auth.audit_log("CONSENT", "pengirim", "persetujuan eksplisit diberikan")

    cert_file, key_file = mirror_stream.ensure_cert()
    fp = mirror_stream.cert_fingerprint(cert_file)
    print(f"  TLS           : {cert_file} (enkripsi in-transit, min TLSv1.2)")
    print(f"  Fingerprint sertifikat (SHA-256 DER) — salin ke penonton:")
    print(f"    {fp}")
    mirror_auth.audit_log("CERT_FINGERPRINT", "pengirim", fp)

    # v2.0: token hanya ditampilkan bila diminta EKSPLISIT (anti
    # shoulder-surfing / log terminal); default TIDAK dicetak.
    try:
        jawab = input("\nTampilkan token admin/viewer sekarang? "
                      "(y/T, default Tidak): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        jawab = ""
    if jawab == "y":
        print(f"    Token ADMIN  : {token_admin}")
        print(f"    Token VIEWER : {token_viewer}")
        mirror_auth.audit_log("TOKEN_DITUNJUKKAN", "pengirim",
                              "token ditampilkan di terminal (permintaan eksplisit)")
    else:
        print("    Token tidak ditampilkan. Jalankan ulang dan jawab 'y' "
              "saat ingin membagikannya.")
    print("    (Token juga tersimpan di memori sesi ini saja — tidak "
          "ditulis ke file)")

    try:
        ambil = PengambilLayar(args.kualitas)
    except ImportError as e:
        sys.exit(f"Dependensi layar belum terpasang ({e}).\n"
                 "Jalankan: pip install -r requirements.txt")

    try:
        ip = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        ip = "127.0.0.1"
    info = f"{socket.gethostname()} ({ip})"

    ctx = mirror_stream.make_server_ssl_ctx(cert_file, key_file)
    srv = mirror_stream.MirrorServer(kode, info, args.host, args.port,
                                      ssl_ctx=ctx, token_map=token_map)
    srv.start()
    mirror_auth.audit_log("LISTEN", "pengirim",
                          f"server {args.host}:{args.port}, max 3 penonton")
    print(f"\n  Perangkat: {info}")
    print("  Sesi AKTIF. Penonton (dengan kode+token) tampil di menu [6].\n")

    threading.Thread(target=menu_pengirim, args=(srv,), daemon=True).start()
    try:
        loop_frame(srv, ambil, args.fps)
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop()
        mirror_auth.audit_log("SESI_END", "pengirim", "server ditutup")
    print("\nSesi mirroring berakhir. Audit trail: sessions.csv")


if __name__ == "__main__":
    main()
