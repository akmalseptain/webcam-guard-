"""mirror_stream.py — Protokol streaming terenkripsi (TLS) untuk screen mirror.

Modul ini STDLIB-ONLY agar logika protokol bisa diuji tanpa OpenCV.
Arsitektur:
- Transport bisa disuntik (param `ssl_ctx`) → test memakai socket polos,
  produksi memakai TLS (lihat ensure_cert()).
- Format wire: [4-byte panjang big-endian][payload].
  Payload perintah = JSON utf-8; frame = b"FRM" + jpeg-bytes.
- Perintah: HELLO {kode, role, token} -> WELCOME/DENY;
  FRAME; PAUSE; RESUME; STOP_REQ (penonton minta stop); STOP (pengirim);
  REVOKED (penonton dicabut); BYE.
"""

import json
import os
import socket
import ssl
import struct
import threading

CERT_FILE = "lab-cert.pem"
KEY_FILE = "lab-key.pem"


# ------------------------------------------------------------
# Sertifikat (dipanggil oleh mirror_server di laptop pengguna)
# ------------------------------------------------------------
def ensure_cert(cert_file=CERT_FILE, key_file=KEY_FILE):
    """Pastikan sertifikat self-signed ada; buat bila belum.

    Urutan usaha:
    1. Pakai file yang sudah ada.
    2. Pakai library `cryptography` bila terpasang (pip install cryptography).
    3. Pakai CLI `openssl` bila ada.
    4. Gagal -> raise dengan instruksi jelas.
    """
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file

    # Usaha 1: library cryptography
    try:
        import datetime
        import ipaddress

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subjek = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "webcam-guard-lab")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(subjek).issuer_name(subjek)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"),
                     x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                    critical=False)
                .sign(key, hashes.SHA256()))
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return cert_file, key_file
    except ImportError:
        pass

    # Usaha 2: CLI openssl
    import subprocess
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key_file, "-out", cert_file, "-days", "365",
             "-subj", "/CN=webcam-guard-lab"],
            check=True, capture_output=True, timeout=30)
        return cert_file, key_file
    except (FileNotFoundError, subprocess.SubprocessError):
        raise RuntimeError(
            "Tidak bisa membuat sertifikat TLS. Jalankan salah satu:\n"
            "  pip install cryptography   (lalu jalankan ulang), atau\n"
            "  openssl req -x509 -newkey rsa:2048 -nodes -keyout lab-key.pem "
            "-out lab-cert.pem -days 365 -subj /CN=webcam-guard-lab")


# ------------------------------------------------------------
# Transport primitives
# ------------------------------------------------------------
def kirim_payload(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def terima_payload(sock, max_len=10 * 1024 * 1024):
    header = _terima_exact(sock, 4)
    (panjang,) = struct.unpack(">I", header)
    if panjang > max_len:
        raise ValueError(f"payload terlalu besar: {panjang}")
    return _terima_exact(sock, panjang)


def _terima_exact(sock, n):
    buf = b""
    while len(buf) < n:
        potongan = sock.recv(min(65536, n - len(buf)))
        if not potongan:
            raise ConnectionError("koneksi terputus")
        buf += potongan
    return buf


def kirim_json(sock, obj):
    kirim_payload(sock, json.dumps(obj).encode("utf-8"))


def terima_json(sock):
    return json.loads(terima_payload(sock).decode("utf-8"))


def kirim_frame(sock, jpeg_bytes):
    kirim_payload(sock, b"FRM" + jpeg_bytes)


def terima_frame(sock):
    """Terima payload; return ('FRM', bytes) atau ('JSON', dict)."""
    data = terima_payload(sock)
    if data[:3] == b"FRM":
        return "FRM", data[3:]
    return "JSON", json.loads(data.decode("utf-8"))


# ------------------------------------------------------------
# Server (sisi pengirim — laptop yang layarnya dimirror)
# ------------------------------------------------------------
class MirrorServer:
    """Server streaming: verifikasi auth per koneksi, kirim frame.

    Param `ssl_ctx` None = socket polos (untuk unit test protokol);
    produksi wajib pass hasil make_server_ssl_ctx().
    """

    def __init__(self, kode, info_device, host="0.0.0.0", port=8443,
                 ssl_ctx=None, max_penonton=3):
        self.kode = kode
        self.info_device = info_device
        self.host = host
        self.port = port
        self.ssl_ctx = ssl_ctx
        self.max_penonton = max_penonton
        self.lock = threading.Lock()
        self.clients = {}          # addr_str -> {sock, role, id}
        self.running = False
        self.state = "aktif"        # aktif | jeda | berhenti
        self.server_sock = None

    def start(self):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((self.host, self.port))
        raw.listen(self.max_penonton)
        self.server_sock = raw if self.ssl_ctx is None else \
            ssl_wrap_server(self.ssl_ctx, raw)
        self.running = True

    def stop(self):
        self.running = False
        self.state = "berhenti"
        with self.lock:
            for c in self.clients.values():
                try:
                    kirim_json(c["sock"], {"cmd": "STOP"})
                    c["sock"].close()
                except OSError:
                    pass
            self.clients.clear()
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass

    def handle_client(self, sock, addr):
        """Satu thread per penonton: verifikasi, lalu terima perintah."""
        addr_str = f"{addr[0]}:{addr[1]}"
        cid = None
        try:
            hello = terima_json(sock)
            if hello.get("cmd") != "HELLO":
                kirim_json(sock, {"cmd": "DENY", "alasan": "harus HELLO dulu"})
                sock.close()
                return
            role = hello.get("role", "viewer")
            from mirror_auth import verifikasi_token
            if not verifikasi_token(self.kode, role, hello.get("token", "")):
                kirim_json(sock, {"cmd": "DENY", "alasan": "kode/token salah"})
                sock.close()
                return
            with self.lock:
                if len(self.clients) >= self.max_penonton:
                    kirim_json(sock, {"cmd": "DENY", "alasan": "penonton penuh"})
                    sock.close()
                    return
                cid = f"{role}@{addr_str}"
                self.clients[cid] = {"sock": sock, "role": role, "id": cid}
            kirim_json(sock, {"cmd": "WELCOME", "device": self.info_device,
                              "state": self.state, "id": cid})
            while self.running:
                jenis, data = terima_frame(sock)
                if jenis == "JSON":
                    cmd = data.get("cmd")
                    if cmd == "STOP_REQ":
                        # penonton minta berhenti → pengirim menghormati
                        with self.lock:
                            self.state = "berhenti"
                        kirim_json(sock, {"cmd": "STOP"})
                        self.running = False
                    elif cmd == "PAUSE":
                        with self.lock:
                            self.state = "jeda"
                    elif cmd == "RESUME":
                        with self.lock:
                            self.state = "aktif"
                    elif cmd == "LEAVE":
                        kirim_json(sock, {"cmd": "BYE"})
                        break
        except (ConnectionError, ValueError, OSError):
            pass
        finally:
            with self.lock:
                # hapus dengan kedua kemungkinan kunci (cid maupun addr_str)
                for k in (cid, addr_str):
                    if k is not None:
                        self.clients.pop(k, None)
            try:
                sock.close()
            except OSError:
                pass

    def accept_loop(self):
        while self.running:
            try:
                sock, addr = self.server_sock.accept()
            except OSError:
                break
            threading.Thread(target=self.handle_client,
                             args=(sock, addr), daemon=True).start()

    def broadcast_frame(self, jpeg_bytes):
        """Kirim frame ke semua penonton; buang penonton mati."""
        with self.lock:
            mati = []
            for cid, c in self.clients.items():
                try:
                    if self.state == "aktif":
                        kirim_frame(c["sock"], jpeg_bytes)
                    else:
                        kirim_json(c["sock"], {"cmd": "PAUSED"})
                except OSError:
                    mati.append(cid)
            for cid in mati:
                del self.clients[cid]

    def revoke(self, cid, oleh_role="admin"):
        """Cabut penonton (hanya admin)."""
        with self.lock:
            c = self.clients.pop(cid, None)
        if c:
            try:
                kirim_json(c["sock"], {"cmd": "REVOKED"})
                c["sock"].close()
            except OSError:
                pass

    def n_penonton(self):
        with self.lock:
            return len(self.clients)


def ssl_wrap_server(ssl_ctx, raw_sock):
    s = ssl_ctx.wrap_socket(raw_sock, server_side=True)
    return s


def make_server_ssl_ctx(cert_file=CERT_FILE, key_file=KEY_FILE):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


def make_client_ssl_ctx():
    """Klien lab: jangan verifikasi CA publik (sert self-signed lab),
    TAPI hanya boleh dipakai untuk perangkat lab yang diotorisasi."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
