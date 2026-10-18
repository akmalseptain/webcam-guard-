"""mirror_stream.py — Protokol streaming terenkripsi (TLS) — v2.0.

Modul STDLIB-ONLY agar logika protokol bisa diuji tanpa OpenCV.
Arsitektur:
- Transport bisa disuntik (param `ssl_ctx`) → test memakai socket polos,
  produksi memakai TLS (lihat ensure_cert()).
- Format wire: [4-byte panjang big-endian][payload], MAX_PAYLOAD 10 MiB.
  Payload perintah = JSON utf-8; frame = b"FRM" + jpeg-bytes.
- Perintah: HELLO {kode, role, token} -> WELCOME/DENY; FRAME; PAUSE;
  RESUME; STOP_REQ (penonton minta stop); STOP (pengirim); REVOKED; BYE.

v2.0 — perubahan dari v1.3 (motivasi audit A-02/A-03/A-06):
- RATE LIMIT per-IP di auth: 5 kegagalan/60 s → koneksi berikutnya
  dikunci ("terlalu banyak upaya gagal") — token benar pun ditolak
  selama terkunci. (getar ~4.600 upaya/dtk kini tertutup.)
- ROLE DARI SERVER: bila `token_map` diberikan ({token: role}), role
  ditentukan dari token di SISI SERVER — role yang diklaim klien
  DIABAIKAN (mencegah privilege escalation via klaim "admin").
- STOP_REQ ADMIN-ONLY: penonton role viewer menerima STOP_DENIED dan
  sesi global TIDAK berhenti (dulu: viewer bisa menstop seluruh sesi).
- WRITER THREAD per klien + antrian BOUNDED (4): penonton lambat tidak
  bisa memblok penonton lain (backpressure: klien lambat di-drop).
- PINNING: cert_fingerprint() (SHA-256 DER) + pin_cocok() constant-time.
  Klien memverifikasi PIN SEBELUM mengirim data aplikasi.
- TLS minimum v1.2 (server & klien), timeout baca 30 s.

JUJUR soal TLS: unit test memakai socket polos (ssl_ctx=None) untuk
logika protokol. Handshake TLS penuh + pin diuji manual antar-2-host
di laptop (lihat docs/V2.0-SECURITY.md).
"""

import hashlib
import hmac
import json
import os
import queue
import secrets
import socket
import ssl
import struct
import threading

from audit_core import RateLimiter

CERT_FILE = "lab-cert.pem"
KEY_FILE = "lab-key.pem"

MAX_PAYLOAD = 10 * 1024 * 1024        # 10 MiB (di atasnya → ValueError)
ANTRIAN_KIRIM = 4                     # bounded queue per klien (backpressure)
GAGAL_MAKS = 5                        # kegagalan auth per-IP sebelum lockout
JENDELA_GAGAL = 60.0                  # detik
READ_TIMEOUT = 30.0                   # detik — klien mati tidak menggantung


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

    PENTING (v2.0): sertifikat self-signed TIDAK dipercaya hanya karena
    ada — klien WAJIB --pin SHA-256 (lihat mirror_viewer).
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


def cert_fingerprint(cert_file=CERT_FILE):
    """SHA-256 dari sertifikat DALAM BENTUK DER.

    Menggunakan DER (bukan byte file PEM) supaya cocok dengan
    sock.getpeercert(binary_form=True) di sisi klien — klien membandingkan
    hasil yang sama. Dicetak pengirim, disalin penonton → --pin.
    """
    import base64
    with open(cert_file, "rb") as f:
        data = f.read()
    if b"-----BEGIN" in data:
        body = b"".join(l for l in data.splitlines()
                        if not l.startswith(b"-----"))
        der = base64.b64decode(body)
    else:
        der = data
    return hashlib.sha256(der).hexdigest()


def pin_cocok(cert_der, pin):
    """Bandingkan SHA-256(cert DER) dengan pin — CONSTANT-TIME.

    pin: hex string SHA-256 dari fingerprint yang dibagikan out-of-band.
    """
    if not cert_der or not pin:
        return False
    return hmac.compare_digest(
        hashlib.sha256(cert_der).hexdigest(), str(pin).strip().lower())


def buat_token_acak():
    """Token sesi acak 256-bit (secrets — BUKAN deterministik dari kode).

    v1.3: token = HMAC(kode, role) → bisa dihitung siapa pun yang tahu
    kode, tidak ada entropi tambahan. v2.0: token acak per sesi, role
    dipetakan di sisi SERVER (token_map).
    """
    return secrets.token_hex(32)  # 256 bit


# ------------------------------------------------------------
# Transport primitives
# ------------------------------------------------------------
def kirim_payload(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def terima_payload(sock, max_len=MAX_PAYLOAD):
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

    v2.0:
    - token_map (opsional): {token: role} — role ditentukan SERVER;
      klaim role klien diabaikan. Tanpa token_map → jalur legacy
      mirror_auth.verifikasi_token(kode, role, token).
    - rate limit per-IP (GAGAL_MAKS/JENDELA_GAGAL).
    """

    def __init__(self, kode, info_device, host="0.0.0.0", port=8443,
                 ssl_ctx=None, max_penonton=3, token_map=None):
        self.kode = kode
        self.info_device = info_device
        self.host = host
        self.port = port
        self.ssl_ctx = ssl_ctx
        self.max_penonton = max_penonton
        self.token_map = token_map
        self.limiter = RateLimiter(maks=GAGAL_MAKS, jendela=JENDELA_GAGAL)
        self.lock = threading.Lock()
        self.clients = {}          # cid -> {sock, role, id, antrian}
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
            klien = list(self.clients.values())
            self.clients.clear()
        for c in klien:
            self._antre(c, ("JSON", {"cmd": "STOP"}))
            self._antre(c, None)  # sentinel: writer menutup socket
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass

    # ---------------- per-klien: writer thread + antrian bounded ----
    def _writer(self, c):
        """Thread pengirim per klien: klien lambat hanya merugikan
        dirinya sendiri (antrian penuh → klien di-drop, bukan semua
        penonton menunggu)."""
        antrian = c["antrian"]
        try:
            while True:
                try:
                    item = antrian.get(timeout=0.25)
                except queue.Empty:
                    if not self.running and antrian.empty():
                        break
                    continue
                if item is None:
                    break
                jenis, data = item
                if jenis == "FRM":
                    kirim_frame(c["sock"], data)
                else:
                    kirim_json(c["sock"], data)
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            try:
                c["sock"].close()
            except OSError:
                pass
            with self.lock:
                self.clients.pop(c["id"], None)

    def _antre(self, c, item):
        """Masukkan item ke antrian klien; penuh → drop klien (backpressure)."""
        try:
            c["antrian"].put_nowait(item)
            return True
        except queue.Full:
            self._drop(c)
            return False

    def _drop(self, c):
        with self.lock:
            self.clients.pop(c.get("id"), None)
        try:
            c["sock"].close()
        except OSError:
            pass

    # ---------------- auth + siklus hidup klien ----------------
    def _autentikasi(self, ip, hello):
        """Return role bila sah; None bila gagal (DENY).

        v2.0: role dari token_map di SISI SERVER bila tersedia;
        limiter per-IP mengunci setelah GAGAL_MAKS kegagalan.
        """
        # lockout dulu — token benar pun ditolak selama terkunci
        if self.limiter.hitung(ip) >= GAGAL_MAKS:
            return None, "terlalu banyak upaya gagal"
        if hello.get("cmd") != "HELLO" or hello.get("kode") != self.kode:
            self.limiter.allow(ip)  # catat kegagalan
            return None, "kode salah"
        token = hello.get("token", "")
        if self.token_map is not None:
            role = self.token_map.get(token)  # role dari SERVER
            if role is None:
                self.limiter.allow(ip)
                return None, "kode/token salah"
            return role, None
        # jalur legacy (tanpa token_map): verifikasi HMAC per role
        from mirror_auth import verifikasi_token
        role = hello.get("role", "viewer")
        if not verifikasi_token(self.kode, role, token):
            self.limiter.allow(ip)
            return None, "kode/token salah"
        return role, None

    def handle_client(self, sock, addr):
        """Satu thread per penonton: verifikasi, lalu terima perintah."""
        addr_str = f"{addr[0]}:{addr[1]}"
        ip = addr[0]
        cid = None
        c = None
        try:
            sock.settimeout(READ_TIMEOUT)
            try:
                hello = terima_json(sock)
            except socket.timeout:
                return  # klien diam → tutup, jangan gantung
            role, alasan = self._autentikasi(ip, hello)
            if role is None:
                if alasan == "terlalu banyak upaya gagal":
                    kirim_json(sock, {"cmd": "DENY", "alasan": alasan})
                else:
                    kirim_json(sock, {"cmd": "DENY", "alasan": alasan})
                sock.close()
                return
            with self.lock:
                if len(self.clients) >= self.max_penonton:
                    kirim_json(sock, {"cmd": "DENY", "alasan": "penonton penuh"})
                    sock.close()
                    return
                cid = f"{role}@{addr_str}"
                c = {"sock": sock, "role": role, "id": cid,
                     "antrian": queue.Queue(maxsize=ANTRIAN_KIRIM)}
                self.clients[cid] = c
                threading.Thread(target=self._writer, args=(c,),
                                daemon=True).start()
            kirim_json(sock, {"cmd": "WELCOME", "device": self.info_device,
                              "state": self.state, "id": cid})
            while self.running:
                jenis, data = terima_frame(sock)
                if jenis == "JSON":
                    cmd = data.get("cmd")
                    if cmd == "STOP_REQ":
                        # v2.0: hanya admin yang boleh menstop sesi global
                        if role == "admin":
                            with self.lock:
                                self.state = "berhenti"
                            kirim_json(sock, {"cmd": "STOP"})
                            self.running = False
                        else:
                            kirim_json(sock, {"cmd": "STOP_DENIED",
                                              "alasan": "hanya admin yang "
                                                        "bisa menghentikan sesi"})
                    elif cmd == "PAUSE":
                        with self.lock:
                            self.state = "jeda"
                    elif cmd == "RESUME":
                        with self.lock:
                            self.state = "aktif"
                    elif cmd == "LEAVE":
                        kirim_json(sock, {"cmd": "BYE"})
                        break
        except (ConnectionError, ValueError, OSError, socket.timeout):
            pass
        finally:
            with self.lock:
                if cid is not None and cid in self.clients:
                    self.clients.pop(cid, None)
            if c is not None:
                # writer thread yang menutup socket lewat sentinel
                try:
                    c["antrian"].put_nowait(None)
                except queue.Full:
                    try:
                        sock.close()
                    except OSError:
                        pass
            else:
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
        """Antre frame ke semua penonton (bounded — penonton lambat di-drop)."""
        with self.lock:
            klien = list(self.clients.values())
        for c in klien:
            if self.state == "aktif":
                self._antre(c, ("FRM", jpeg_bytes))
            else:
                self._antre(c, ("JSON", {"cmd": "PAUSED"}))

    def revoke(self, cid, oleh_role="admin"):
        """Cabut penonton (hanya admin)."""
        with self.lock:
            c = self.clients.pop(cid, None)
        if c:
            self._antre(c, ("JSON", {"cmd": "REVOKED"}))
            self._antre(c, None)

    def n_penonton(self):
        with self.lock:
            return len(self.clients)


def ssl_wrap_server(ssl_ctx, raw_sock):
    s = ssl_ctx.wrap_socket(raw_sock, server_side=True)
    return s


def make_server_ssl_ctx(cert_file=CERT_FILE, key_file=KEY_FILE):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    # v2.0: minimum TLS 1.2 (jangan terima versi usang bila interpreter
    # default-nya lebih longgar)
    if hasattr(ssl, "TLSVersion"):
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except (ValueError, AttributeError):
            pass
    return ctx


def make_client_ssl_ctx():
    """Klien lab: CERT_NONE karena KEPERCAYAAN MELALUI PINNING (bukan CA).

    Self-signed TIDAK dipercaya hanya karena self-signed: klien WAJIB
    memverifikasi --pin (SHA-256 sertifikat) SEBELUM mengirim data
    aplikasi (lihat mirror_viewer.py — tanpa pin: hard exit 2).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "TLSVersion"):
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except (ValueError, AttributeError):
            pass
    return ctx
