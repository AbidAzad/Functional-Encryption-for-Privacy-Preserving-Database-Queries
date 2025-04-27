# codes/ServerFE.py

import os
import time
import sqlite3
import socket
import hashlib
import json
import csv
import re
from datetime import datetime
from .fe_scheme import encrypt  # Paillier encryption function

# Determine where to store/read key files
BASE_DIR = os.path.dirname(__file__)
KEY_DIR  = os.path.abspath(os.path.join(BASE_DIR, os.pardir, "keys"))
os.makedirs(KEY_DIR, exist_ok=True)  # Ensure the keys directory exists

def _wait_for_keys():
    """
    Block until the public key and SSE key files are present.
    This ensures the authority has written keys before the server starts.
    """
    while not (os.path.exists(os.path.join(KEY_DIR, "public_key.txt")) and
               os.path.exists(os.path.join(KEY_DIR, "sse_key.txt"))):
        time.sleep(0.05)

def load_public_key():
    """
    Read the Paillier public key (n, g) from file.
    Blocks until keys are available.
    """
    _wait_for_keys()
    with open(os.path.join(KEY_DIR, "public_key.txt")) as f:
        n, g = map(int, f.read().split())
    return (n, g)

def load_ta_rsa_pub():
    """
    Read the authority's RSA public key (N, e) used to verify FE tokens.
    """
    _wait_for_keys()
    with open(os.path.join(KEY_DIR, "ta_rsa_pub.txt")) as f:
        N, e = map(int, f.read().split())
    return (N, e)

def load_sse_key():
    """
    Read the symmetric SSE key (an integer) from file.
    """
    _wait_for_keys()
    return int(open(os.path.join(KEY_DIR, "sse_key.txt")).read().strip())

def verify_fkey(token, rsa_pub, expected_hash):
    """
    Verify the RSA signature on a function-key token.
    Returns True if valid and matches the expected query hash, False otherwise.
    """
    if "|" not in token:
        return False
    data, sig_str = token.split("|", 1)
    try:
        sig = int(sig_str)
    except:
        return False

    # Recompute the hash of the token data
    N, e = rsa_pub
    h = int(hashlib.sha256(data.encode()).hexdigest(), 16) % N
    # Verify signature
    if pow(sig, e, N) != h:
        return False

    # Ensure the token claims the correct query hash
    parts = dict(p.split(":",1) for p in data.split(";") if ":" in p)
    return parts.get("hash") == expected_hash

def init_databases(csv_path, public_key, logger):
    """
    Load the CSV file at csv_path and prepare three in-memory SQLite DBs:
      1) plain: for COUNT(*)
      2) enc:   Paillier-encrypted numeric columns for FE
      3) sse:   XOR-encrypted numeric columns for SSE fall-back
    Returns (header, numeric_cols, plain_db, enc_db, sse_db).
    """
    # 1) Read CSV rows
    with open(csv_path, newline='', encoding='utf-8') as f:
        rdr    = csv.reader(f)
        header = next(rdr)
        # Remove BOM if present
        header[0] = header[0].lstrip('\ufeff')
        rows   = [r for r in rdr if any(cell.strip() for cell in r)]

    # 2) Identify numeric columns by checking every non-empty cell
    def is_num(s):
        try:
            float(s)
            return True
        except:
            return False

    numeric_cols = [
        header[i]
        for i in range(len(header))
        if all(is_num(r[i].strip()) for r in rows if r[i].strip())
    ]

    # 3) Build plain-text DB for COUNT(*)
    plain = sqlite3.connect(":memory:")
    pcur  = plain.cursor()
    defs  = ", ".join(f'"{col}" TEXT' for col in header)
    pcur.execute(f"CREATE TABLE data ({defs})")
    pcur.executemany(
        f"INSERT INTO data VALUES ({','.join('?' for _ in header)})",
        rows
    )
    plain.commit()

    # 4) Build Paillier‐encrypted DB for FE on numeric columns
    enc  = sqlite3.connect(":memory:")
    ecur = enc.cursor()
    if numeric_cols:
        # Only include numeric columns
        enc_defs = ", ".join(f'"{c}" TEXT' for c in numeric_cols)
        ecur.execute(f"CREATE TABLE data_enc ({enc_defs})")
        # Encrypt each numeric value with the public Paillier key
        for r in rows:
            cipher_row = []
            for c in numeric_cols:
                raw = r[header.index(c)].strip()
                iv  = int(float(raw)) if raw else 0
                cipher_row.append(str(encrypt(iv, public_key)))
            ecur.execute(
                f"INSERT INTO data_enc VALUES ({','.join('?' for _ in numeric_cols)})",
                cipher_row
            )
        enc.commit()

    # Register a custom aggregate paillier_prod for encrypted SUM
    n, _ = public_key
    enc.create_aggregate(
        "paillier_prod", 1,
        lambda: type("A", (), {
            "n_sq":    n*n,
            "product": 1,
            "step":    lambda self,v: setattr(self, "product", (self.product*int(v))%self.n_sq),
            "finalize":lambda self: str(self.product)
        })()
    )

    # 5) Build SSE‐encrypted DB for WHERE filter operations
    sse  = sqlite3.connect(":memory:")
    scur = sse.cursor()
    if numeric_cols:
        sse_defs = ", ".join(f'"{c}" TEXT' for c in numeric_cols)
        scur.execute(f"CREATE TABLE data_sse ({sse_defs})")
        sse_key = load_sse_key()
        for r in rows:
            row_s = []
            for c in numeric_cols:
                raw = r[header.index(c)].strip()
                iv  = int(float(raw)) if raw else 0
                # XOR-encrypt the integer
                row_s.append(str(iv ^ sse_key))
            scur.execute(
                f"INSERT INTO data_sse VALUES ({','.join('?' for _ in numeric_cols)})",
                row_s
            )
        sse.commit()

    return header, numeric_cols, plain, enc, sse

def rewrite_query(q, numeric_cols, logger):
    """
    Decide whether to run the query under FE or fall back to SSE_TABLE:
      - Pure aggregates (SUM, COUNT, AVG) on numeric columns → FE
      - Otherwise (e.g. WHERE filters) → SSE_TABLE
    Returns a tuple (mode, fn, col) where mode is "FE" or "SSE_TABLE".
    """
    ts_str = datetime.now().strftime("%H:%M:%S")
    logger(f"[{ts_str}] rewrite: {q!r}")
    s = q.strip().rstrip(";")
    pat = re.compile(
        r"^SELECT\s+(SUM|COUNT|AVG)\(\s*(\*|\"([^\"]+)\"|(\w+))\)\s+FROM\s+data$",
        re.IGNORECASE
    )
    m = pat.match(s)
    if m:
        fn  = m.group(1).upper()
        col = "*" if (fn=="COUNT" and "*" in m.group(2)) else (m.group(3) or m.group(4))
        # If SUM/AVG on a non-numeric column, cannot do FE
        if fn in ("SUM","AVG") and col not in numeric_cols:
            logger("  → col not numeric, SSE_TABLE")
            return "SSE_TABLE", None, None
        logger(f"  → FE(fn={fn},col={col})")
        return "FE", fn, col

    # Anything else (e.g. WHERE) goes to SSE_TABLE
    logger("  → detected WHERE/non-agg → SSE_TABLE")
    return "SSE_TABLE", None, None

def start_server(csv_path, logger, shutdown_event=None):
    """
    Main server loop:
      - Loads keys and databases
      - Listens on localhost:9000 for client connections
      - Each request must be:
          QUERY
          <function-key token>
          <SQL query>
      - Verifies token, chooses mode, executes, returns JSON result
    """
    public_key  = load_public_key()
    rsa_pub     = load_ta_rsa_pub()
    header, numeric_cols, plain_db, enc_db, sse_db = init_databases(csv_path, public_key, logger)

    with socket.socket() as sock:
        sock.bind(("localhost", 9000))
        sock.listen(5)
        sock.settimeout(1.0)
        logger("Server listening on localhost:9000")

        while True:
            # Allow graceful shutdown if event set
            if shutdown_event and shutdown_event.is_set():
                logger("Server shutdown")
                return
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue

            data = conn.recv(65536)
            if not data:
                conn.close()
                continue

            lines = data.decode().splitlines()
            # Expect at least 3 lines: "QUERY", token, SQL
            if len(lines)<3 or lines[0].upper()!="QUERY":
                conn.sendall(b"ERROR: Bad format")
                conn.close()
                continue

            _, raw_fkey, query = lines
            logger(f"→ Received query: {query!r}")
            qhash = hashlib.sha256(query.encode()).hexdigest()
            start = time.time()

            # Verify FE token; if invalid, force SSE_TABLE
            if not verify_fkey(raw_fkey, rsa_pub, qhash):
                mode, fn, col = "SSE_TABLE", None, None
            else:
                mode, fn, col = rewrite_query(query, numeric_cols, logger)

            # Execute under FE or SSE_TABLE
            if mode == "FE":
                cur = enc_db.cursor()
                if fn == "SUM":
                    # Use custom aggregate to multiply ciphertexts
                    cur.execute(f'SELECT paillier_prod("{col}") FROM data_enc')
                    ciph = int(cur.fetchone()[0])
                    resp = {"mode":"FE","fn":"SUM","cipher":ciph}
                elif fn == "COUNT":
                    cnt  = plain_db.execute("SELECT COUNT(*) FROM data").fetchone()[0]
                    resp = {"mode":"FE","fn":"COUNT","cipher":encrypt(cnt, public_key)}
                else:  # AVG
                    cur.execute(f'SELECT paillier_prod("{col}") FROM data_enc')
                    ssum = int(cur.fetchone()[0])
                    cnt  = plain_db.execute("SELECT COUNT(*) FROM data").fetchone()[0]
                    resp = {"mode":"FE","fn":"AVG","sum":ssum,"count":cnt}
            else:
                # SSE fallback: send back XOR-encrypted rows
                scur = sse_db.cursor()
                cols_expr = ", ".join(f'"{c}"' for c in numeric_cols)
                scur.execute(f"SELECT {cols_expr} FROM data_sse")
                rows = scur.fetchall()
                resp = {
                    "mode":    "SSE_TABLE",
                    "columns": numeric_cols,
                    "rows":    rows
                }

            # Attach server processing time (for benchmarking)
            resp["server_time"] = time.time() - start

            conn.sendall(json.dumps(resp).encode())
            conn.close()

# ── Async helpers ─────────────────────────────────────────────────────────

import threading

_server_thread   = None
_server_shutdown = None

def start_server_async(csv_path, logger, host='localhost', port=9000, timeout=3600.0):
    """
    Launch start_server in a background thread, and wait until it's accepting connections.
    """
    global _server_thread, _server_shutdown
    if _server_thread and _server_thread.is_alive():
        raise RuntimeError("ServerFE already running")
    _server_shutdown = threading.Event()
    def target():
        start_server(csv_path, logger, shutdown_event=_server_shutdown)
    _server_thread = threading.Thread(target=target, daemon=True)
    _server_thread.start()

    # Wait for server socket to open
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                logger("[ServerFE] startup confirmed")
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("ServerFE did not start in time")

def stop_server():
    """
    Signal the server thread to stop and wait for it.
    """
    global _server_thread, _server_shutdown
    if _server_shutdown:
        _server_shutdown.set()
    if _server_thread:
        _server_thread.join()
    _server_thread   = None
    _server_shutdown = None
