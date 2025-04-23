import os, glob, socket, sys, hashlib, math
from .fe_scheme import keygen, generate_prime, lcm, modinv

# --- RSA helpers ---
def egcd(a, b):
    if a == 0: return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b//a)*y, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

def generate_rsa_keys(bits=128):
    p = generate_prime(bits//2)
    q = generate_prime(bits//2)
    N = p*q
    phi = (p-1)*(q-1)
    e  = 65537
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

# --- key folder setup & cleanup ---
BASE_DIR = os.path.dirname(__file__)
KEY_DIR  = os.path.abspath(os.path.join(BASE_DIR, os.pardir, "keys"))
os.makedirs(KEY_DIR, exist_ok=True)
for f in glob.glob(os.path.join(KEY_DIR, "*.txt")):
    os.remove(f)

def _write(name, txt):
    with open(os.path.join(KEY_DIR, name), "w") as f:
        f.write(txt)

def start_authority_server(logger):
    logger("[TA] Listening on localhost:8000")
    # 1) Paillier keypair
    public_key, _ = keygen(256)
    _write("public_key.txt", f"{public_key[0]}\n{public_key[1]}\n")
    logger(f"[TA] Paillier public key   n={public_key[0]}, g={public_key[1]}")

    # 2) RSA keypair for signing FE‐keys
    rsa_priv = generate_rsa_keys(128)
    rsa_pub  = (rsa_priv[0], rsa_priv[1])
    _write("ta_rsa_pub.txt", f"{rsa_pub[0]}\n{rsa_pub[1]}\n")
    logger("[TA] RSA public key written to ta_rsa_pub.txt")

    # 3) Listen for requests
    host, port = "localhost", 8000
    with socket.socket() as s:
        s.bind((host, port))
        s.listen(5)
        logger(f"[TA] Listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            with conn:
                logger(f"[TA] ⇄ Connection from {addr}")
                data = conn.recv(4096).decode().strip()
                logger(f"[TA] ⇐ Received: {data}")

                parts = data.split()
                if parts[0] == "GET_PUBLIC_KEY":
                    resp = f"{public_key[0]},{public_key[1]}"
                    conn.sendall(resp.encode())
                    logger("[TA] ⇒ Sent: public_key")

                elif parts[0].upper() == "GET_FKEY" and len(parts) == 3 and parts[1].upper() == "AGG":
                    qhash = parts[2]
                    logger(f"[TA] ⇐ Received FKEY request for query hash: {qhash[:8]}...")
                    
                    # Generate fresh λ and μ for this function key
                    logger("[TA] Generating new function key parameters...")
                    p = generate_prime(128)
                    q = generate_prime(128)
                    n = p*q
                    lam = lcm(p-1, q-1)
                    def L(u): return (u-1)//n
                    mu = modinv(L(pow(n+1, lam, n*n)), n)
                    
                    logger(f"[TA] Generated fresh parameters: λ={lam}, μ={mu}")
                    
                    fkey_data = f"FKEY:AGG;hash:{qhash};lam:{lam};mu:{mu}"
                    logger(f"[TA] Function key data: {fkey_data}")
                    
                    # Sign the function key
                    sig = rsa_sign(fkey_data, rsa_priv)
                    token = f"{fkey_data}|{sig}"
                    
                    logger(f"[TA] ⇒ Sending signed function key to client")
                    conn.sendall(token.encode())

                else:
                    conn.sendall(b"ERROR: Unknown command")
                    logger("[TA] ⇒ ERROR: Unknown command")

if __name__ == "__main__":
    try:
        start_authority_server()
    except KeyboardInterrupt:
        print("[TA] Shutting down.")
        sys.exit(0)