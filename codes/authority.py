# authority.py

import os
import glob
import socket
import hashlib
import math
import random
from datetime import datetime
from .fe_scheme import keygen, generate_prime

# ── RSA helpers ────────────────────────────────────────────────────────────
# Extended GCD for modular inverse
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b//a)*y, y)

# Compute modular inverse of a modulo m
def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

# Generate an RSA keypair (N, e, d)
def generate_rsa_keys(bits=512):
    # Generate two primes p, q of half the bit-length
    p = generate_prime(bits//2)
    q = generate_prime(bits//2)
    N = p * q
    phi = (p-1) * (q-1)
    # Common choice for e
    e = 65537
    # If e not coprime with phi, find next odd coprime
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    # Compute private exponent d
    d = modinv(e, phi)
    return (N, e, d)

# Sign a message using RSA private key (d,N)
def rsa_sign(msg, rsa_priv):
    N, e, d = rsa_priv
    # Hash message to integer mod N
    h = int(hashlib.sha256(msg.encode()).hexdigest(), 16) % N
    # Signature = h^d mod N
    return pow(h, d, N)


# ── Key folder setup & cleanup ──────────────────────────────────────────────
# Determine where to store keys
BASE_DIR = os.path.dirname(__file__)
KEY_DIR  = os.path.abspath(os.path.join(BASE_DIR, os.pardir, "keys"))
os.makedirs(KEY_DIR, exist_ok=True)

# Remove any existing key files on startup
for f in glob.glob(os.path.join(KEY_DIR, "*.txt")):
    os.remove(f)


def start_authority_server(logger, shutdown_event=None):
    """
    Start the Authority microservice:
      1. Generate Paillier keypair and write public_key.txt
      2. Generate RSA keypair for signing and write ta_rsa_pub.txt
      3. Generate a random SSE key and write sse_key.txt
      4. Listen on localhost:8000 for GET_PUBLIC_KEY, GET_FKEY, GET_SSE_KEY requests
    Blocks until `shutdown_event` is set.
    """
    def log(msg):
        ts = datetime.now().strftime("%H:%M:%S")
        logger(f"[{ts}] [Authority] {msg}")

    # 1) Paillier keypair (for functional encryption)
    public_key, private_key = keygen(256)    # 256-bit modulus
    lam_priv, mu_priv       = private_key
    def _write(name, txt):
        # Helper to write text files into the key directory
        open(os.path.join(KEY_DIR, name), "w").write(txt)

    # Save Paillier public parameters (n, g)
    _write("public_key.txt", f"{public_key[0]}\n{public_key[1]}\n")
    log(f"Paillier public key written (n={public_key[0]}, g={public_key[1]})")

    # 2) RSA keypair to sign function‐keys
    rsa_priv = generate_rsa_keys(512)       # 512-bit RSA for signing
    rsa_pub  = (rsa_priv[0], rsa_priv[1])   # (N, e)
    _write("ta_rsa_pub.txt", f"{rsa_pub[0]}\n{rsa_pub[1]}\n")
    log("RSA public key written to ta_rsa_pub.txt")

    # 3) SSE key used for row‐level symmetric encryption (toy implementation)
    sse_key = random.getrandbits(128)       # 128-bit random integer
    _write("sse_key.txt", str(sse_key))
    log("SSE key written to sse_key.txt")

    # 4) Serve requests over a TCP socket
    host, port = "localhost", 8000
    with socket.socket() as s:
        s.bind((host, port))
        s.listen(5)
        s.settimeout(1.0)
        log(f"Listening on {host}:{port}")

        while True:
            # Check for shutdown signal
            if shutdown_event and shutdown_event.is_set():
                log("Shutdown signal received, exiting")
                return

            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue

            with conn:
                # Read incoming request
                data = conn.recv(4096)
                if not data:
                    # Empty handshake, ignore
                    continue

                data = data.decode().strip()
                log(f"Connection from {addr}")
                log(f"Received: {data!r}")
                parts = data.split()

                # Handle GET_PUBLIC_KEY
                if parts[0] == "GET_PUBLIC_KEY":
                    resp = f"{public_key[0]},{public_key[1]}"
                    conn.sendall(resp.encode())
                    log("→ public key sent")

                # Handle GET_FKEY AGG <query_hash>
                elif (len(parts) == 3 and parts[0].upper() == "GET_FKEY"
                      and parts[1].upper() == "AGG"):
                    # Build the function key data string
                    qhash = parts[2]
                    fkey_data = f"FKEY:AGG;hash:{qhash};lam:{lam_priv};mu:{mu_priv}"
                    # Sign it with RSA private key
                    sig = rsa_sign(fkey_data, rsa_priv)
                    token = f"{fkey_data}|{sig}"
                    conn.sendall(token.encode())
                    log("→ signed function key sent")

                # Handle GET_SSE_KEY
                elif parts[0].upper() == "GET_SSE_KEY":
                    conn.sendall(str(sse_key).encode())
                    log("→ SSE key sent")

                # Unknown command
                else:
                    conn.sendall(b"ERROR: Unknown command")
                    log("⚠ Unknown command")


# ── Async helpers ─────────────────────────────────────────────────────────
import threading, time

_authority_thread   = None
_authority_shutdown = None

def start_authority_async(logger, host='localhost', port=8000, timeout=5.0):
    """
    Launch the Authority server in a background thread.
    Returns once it is accepting connections.
    """
    global _authority_thread, _authority_shutdown
    if _authority_thread and _authority_thread.is_alive():
        raise RuntimeError("Authority server already running")

    # Event to signal shutdown
    _authority_shutdown = threading.Event()
    def target():
        start_authority_server(logger, shutdown_event=_authority_shutdown)

    # Start thread
    _authority_thread = threading.Thread(target=target, daemon=True)
    _authority_thread.start()

    # Wait until the server responds on the socket
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
    Signal the Authority server to stop and wait for the thread to exit.
    """
    global _authority_thread, _authority_shutdown
    if _authority_shutdown:
        _authority_shutdown.set()
    if _authority_thread:
        _authority_thread.join()
    _authority_thread   = None
    _authority_shutdown = None
