# authority.py

import os, glob, socket, hashlib, math, random
from datetime import datetime
from .fe_scheme import keygen, generate_prime

# ── RSA helpers ────────────────────────────────────────────────────────────

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b//a)*y, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

def generate_rsa_keys(bits=512):
    p = generate_prime(bits//2)
    q = generate_prime(bits//2)
    N = p*q
    phi = (p-1)*(q-1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return (N, e, d)

def rsa_sign(msg, rsa_priv):
    N, e, d = rsa_priv
    h = int(hashlib.sha256(msg.encode()).hexdigest(), 16) % N
    return pow(h, d, N)

# ── key folder setup & cleanup ─────────────────────────────────────────────

BASE_DIR = os.path.dirname(__file__)
KEY_DIR  = os.path.abspath(os.path.join(BASE_DIR, os.pardir, "keys"))
os.makedirs(KEY_DIR, exist_ok=True)
for f in glob.glob(os.path.join(KEY_DIR, "*.txt")):
    os.remove(f)

def start_authority_server(logger, shutdown_event=None):
    """
    Blocks and serves on localhost:8000 until shutdown_event is set.
    """
    def log(msg):
        ts = datetime.now().strftime("%H:%M:%S")
        logger(f"[{ts}] [Authority] {msg}")

    # 1) Paillier keypair
    public_key, private_key = keygen(256)
    lam_priv, mu_priv       = private_key
    def _write(name, txt):
        open(os.path.join(KEY_DIR, name), "w").write(txt)

    _write("public_key.txt", f"{public_key[0]}\n{public_key[1]}\n")
    log(f"Paillier public key written (n={public_key[0]}, g={public_key[1]})")

    # 2) RSA keypair to sign function‐keys
    rsa_priv = generate_rsa_keys(512)
    rsa_pub  = (rsa_priv[0], rsa_priv[1])
    _write("ta_rsa_pub.txt", f"{rsa_pub[0]}\n{rsa_pub[1]}\n")
    log("RSA public key written to ta_rsa_pub.txt")

    # 3) SSE key (demo: 128-bit random int)
    sse_key = random.getrandbits(128)
    _write("sse_key.txt", str(sse_key))
    log("SSE key written to sse_key.txt")

    # 4) Listen for requests
    host, port = "localhost", 8000
    with socket.socket() as s:
        s.bind((host, port))
        s.listen(5)
        s.settimeout(1.0)
        log(f"Listening on {host}:{port}")
        while True:
            if shutdown_event and shutdown_event.is_set():
                log("Shutdown signal received, exiting")
                return
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue

            with conn:
                # **NEW** ignore empty “handshake” connects
                data = conn.recv(4096)
                if not data:
                    continue

                data = data.decode().strip()
                log(f"Connection from {addr}")
                log(f"Received: {data!r}")
                parts = data.split()

                if parts[0] == "GET_PUBLIC_KEY":
                    resp = f"{public_key[0]},{public_key[1]}"
                    conn.sendall(resp.encode())
                    log("→ public key sent")

                elif (len(parts)==3 and parts[0].upper()=="GET_FKEY"
                      and parts[1].upper()=="AGG"):
                    qhash = parts[2]
                    fkey_data = f"FKEY:AGG;hash:{qhash};lam:{lam_priv};mu:{mu_priv}"
                    sig = rsa_sign(fkey_data, rsa_priv)
                    token = f"{fkey_data}|{sig}"
                    conn.sendall(token.encode())
                    log("→ signed function key sent")

                elif parts[0].upper()=="GET_SSE_KEY":
                    conn.sendall(str(sse_key).encode())
                    log("→ SSE key sent")

                else:
                    conn.sendall(b"ERROR: Unknown command")
                    log("⚠ Unknown command")

# ── Async helpers ─────────────────────────────────────────────────────────

import threading, time

_authority_thread   = None
_authority_shutdown = None

def start_authority_async(logger, host='localhost', port=8000, timeout=5.0):
    """
    Launch authority server in background. Returns once it's accepting.
    """
    global _authority_thread, _authority_shutdown
    if _authority_thread and _authority_thread.is_alive():
        raise RuntimeError("Authority server already running")
    _authority_shutdown = threading.Event()
    def target():
        start_authority_server(logger, shutdown_event=_authority_shutdown)
    _authority_thread = threading.Thread(target=target, daemon=True)
    _authority_thread.start()

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                logger("[Authority] startup confirmed")
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("Authority did not start in time")

def stop_authority():
    """
    Signal authority to stop and wait for thread to join.
    """
    global _authority_thread, _authority_shutdown
    if _authority_shutdown:
        _authority_shutdown.set()
    if _authority_thread:
        _authority_thread.join()
    _authority_thread   = None
    _authority_shutdown = None
