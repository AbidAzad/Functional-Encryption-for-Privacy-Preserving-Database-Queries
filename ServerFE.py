# server.py
import socket, sys, hashlib, sqlite3, sqlparse
from fe_scheme import encrypt
from demo_data import demo_data  # import demo data

def load_public_key():
    try:
        with open("public_key.txt", "r") as f:
            lines = f.read().splitlines()
            n = int(lines[0].strip())
            g = int(lines[1].strip())
            return (n, g)
    except Exception as e:
        print(f"[Server] Error loading public key: {e}")
        sys.exit(1)

def load_ta_rsa_pub():
    try:
        with open("ta_rsa_pub.txt", "r") as f:
            lines = f.read().splitlines()
            N = int(lines[0].strip())
            e = int(lines[1].strip())
            return (N, e)
    except Exception as e:
        print(f"[Server] Error loading TA RSA public key: {e}")
        sys.exit(1)

def verify_fkey(token_full, rsa_pub):
    """
    Expected token format: fkey_data|signature, where fkey_data should contain "FKEY:AGG"
    """
    if "|" not in token_full:
        return False
    fkey_data, sig_str = token_full.split("|", 1)
    try:
        signature = int(sig_str)
    except ValueError:
        return False
    import hashlib
    N, e = rsa_pub
    h = int(hashlib.sha256(fkey_data.encode()).hexdigest(), 16) % N
    h_from_sig = pow(signature, e, N)
    return h == h_from_sig and "FKEY:AGG" in fkey_data

# Custom aggregate: multiply ciphertexts modulo n^2.
class PaillierProd:
    def __init__(self, n_sq):
        self.n_sq = n_sq
        self.product = 1
    def step(self, value):
        if value is not None:
            # Stored value is a string; convert it back to int.
            self.product = (self.product * int(value)) % self.n_sq
    def finalize(self):
        # Return as string so SQLite treats it as TEXT.
        return str(self.product)

def init_sqlite_db(public_key):
    # Create an in-memory SQLite database and populate it with encrypted data.
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    # Create table with column type TEXT so that large ciphertexts can be stored.
    c.execute("CREATE TABLE transactions (encrypted_value TEXT)")
    for row in demo_data:
        plaintext = row[0]
        ciphertext = encrypt(plaintext, public_key)
        # Store ciphertext as string.
        c.execute("INSERT INTO transactions (encrypted_value) VALUES (?)", (str(ciphertext),))
    conn.commit()
    n, _ = public_key
    n_sq = n * n
    conn.create_aggregate("paillier_prod", 1, lambda: PaillierProd(n_sq))
    return conn

def rewrite_query(query):
    query_upper = query.upper()
    if "SUM(" in query_upper:
        return "SELECT paillier_prod(encrypted_value) FROM transactions"
    elif "COUNT(" in query_upper:
        return "SELECT COUNT(*) FROM transactions"
    elif "AVG(" in query_upper:
        return "AVG"  # special marker for AVG handling
    elif "MIN(" in query_upper or "MAX(" in query_upper:
        return None  # not supported on encrypted data
    else:
        return None

def start_server():
    public_key = load_public_key()
    rsa_pub = load_ta_rsa_pub()
    sql_conn = init_sqlite_db(public_key)
    host = "localhost"
    port = 9000
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(5)
        print(f"[Server] Encrypted Database Server listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[Server] Connection from {addr}")
                data = conn.recv(4096)
                if not data:
                    continue
                message = data.decode().strip()
                print(f"[Server] Received message:\n{message}")
                # Expecting three lines: "QUERY", functional key token, and SQL query.
                lines = message.splitlines()
                if len(lines) < 3 or lines[0].strip().upper() != "QUERY":
                    response = "ERROR: Invalid message format. Expecting three lines."
                    print("[Server] " + response)
                    conn.sendall(response.encode())
                    continue
                fkey_token = lines[1].strip()
                query = lines[2].strip()
                print(f"[Server] Received functional key: {fkey_token}")
                print(f"[Server] Received query: {query}")
                query_hash = hashlib.sha256(query.encode()).hexdigest()
                print(f"[Server] Query hash (SHA256): {query_hash}")
                if not verify_fkey(fkey_token, rsa_pub):
                    response = "ERROR: Invalid or unauthorized functional key."
                    print("[Server] " + response)
                    conn.sendall(response.encode())
                    continue
                try:
                    sqlparse.parse(query)
                except Exception as e:
                    response = f"ERROR: {str(e)}"
                    print("[Server] " + response)
                    conn.sendall(response.encode())
                    continue
                rewritten = rewrite_query(query)
                if rewritten is None:
                    response = "ERROR: Query type not supported on encrypted data."
                    print("[Server] " + response)
                    conn.sendall(response.encode())
                    continue
                if rewritten == "AVG":
                    # Special handling for AVG: compute encrypted sum and plaintext count.
                    cur = sql_conn.cursor()
                    try:
                        cur.execute("SELECT paillier_prod(encrypted_value) FROM transactions")
                        sum_ciphertext = cur.fetchone()[0]
                        cur.execute("SELECT COUNT(*) FROM transactions")
                        count_plain = cur.fetchone()[0]
                    except Exception as e:
                        response = f"ERROR: SQL execution error: {str(e)}"
                        print("[Server] " + response)
                        conn.sendall(response.encode())
                        continue
                    # Encrypt count as string.
                    count_ciphertext = str(encrypt(count_plain, public_key))
                    response = f"{sum_ciphertext}\n{count_ciphertext}"
                elif "COUNT" in rewritten.upper():
                    cur = sql_conn.cursor()
                    try:
                        cur.execute(rewritten)
                        count_plain = cur.fetchone()[0]
                        # Encrypt the count and convert to string.
                        count_ciphertext = str(encrypt(count_plain, public_key))
                    except Exception as e:
                        response = f"ERROR: SQL execution error: {str(e)}"
                        print("[Server] " + response)
                        conn.sendall(response.encode())
                        continue
                    response = count_ciphertext
                else:
                    cur = sql_conn.cursor()
                    try:
                        cur.execute(rewritten)
                        result = cur.fetchone()[0]
                    except Exception as e:
                        response = f"ERROR: SQL execution error: {str(e)}"
                        print("[Server] " + response)
                        conn.sendall(response.encode())
                        continue
                    response = str(result)
                conn.sendall(response.encode())

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("[Server] Shutting down server.")
        sys.exit(0)
