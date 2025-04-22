# authority.py
import socket, sys, time, random, math, hashlib
from fe_scheme import keygen

# --- RSA SIGNING FUNCTIONS (simple implementation) ---
def generate_rsa_keys(bits=128):
    """Generate a simple RSA key pair for signing."""
    p = generate_small_prime(bits // 2)
    q = generate_small_prime(bits // 2)
    N = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return (N, e, d)

def generate_small_prime(bits):
    from fe_scheme import generate_prime
    return generate_prime(bits)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """Compute modular inverse."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

def rsa_sign(message, rsa_priv):
    """Sign a message using RSA private key."""
    N, e, d = rsa_priv
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % N
    signature = pow(h, d, N)
    return signature

def rsa_verify(message, signature, rsa_pub):
    """Verify an RSA signature."""
    N, e = rsa_pub
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % N
    h_from_sig = pow(signature, e, N)
    return h == h_from_sig
# --- End RSA signing functions ---

rsa_priv = None  # (N, e, d)
rsa_pub = None   # (N, e)

def write_public_key_to_file(public_key):
    n, g = public_key
    with open("public_key.txt", "w") as f:
        f.write(f"{n}\n{g}\n")

def write_rsa_pub_to_file(rsa_pub):
    N, e = rsa_pub
    with open("ta_rsa_pub.txt", "w") as f:
        f.write(f"{N}\n{e}\n")

def start_authority_server():
    global rsa_priv, rsa_pub
    # Generate Paillier keypair (public: n,g; private: λ,μ)
    public_key, private_key = keygen(256)
    print(f"[TA] Generated Paillier public key: n={public_key[0]}, g={public_key[1]}")
    write_public_key_to_file(public_key)
    print("[TA] Public key written to public_key.txt")
    
    # Generate a small RSA keypair for signing FE‐keys
    rsa_priv = generate_rsa_keys(128)
    rsa_pub = (rsa_priv[0], rsa_priv[1])
    write_rsa_pub_to_file(rsa_pub)
    print("[TA] RSA keypair generated and public key written to ta_rsa_pub.txt")
    
    host, port = "localhost", 8000
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(5)
        print(f"[TA] Listening on {host}:{port} for key requests...")
        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(4096)
                if not data:
                    continue
                cmd = data.decode().strip()
                if cmd == "GET_PUBLIC_KEY":
                    # Return Paillier public key
                    resp = f"{public_key[0]},{public_key[1]}"
                    conn.sendall(resp.encode())
                elif cmd.upper() == "GET_FKEY AGG":
                    # Issue the functional (decryption) key λ,μ for aggregation
                    lam, mu = private_key
                    fkey_data = f"FKEY:AGG;lam:{lam};mu:{mu}"
                    sig = rsa_sign(fkey_data, rsa_priv)
                    conn.sendall(f"{fkey_data}|{sig}".encode())
                else:
                    conn.sendall(b"ERROR: Unknown command.")

if __name__ == "__main__":
    try:
        start_authority_server()
    except KeyboardInterrupt:
        print("\n[TA] Shutting down.")
        sys.exit(0)
