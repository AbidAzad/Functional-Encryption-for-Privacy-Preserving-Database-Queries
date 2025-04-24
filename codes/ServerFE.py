import os, time, sqlite3, socket, hashlib, sqlparse, json, csv, re
from .fe_scheme import encrypt

BASE_DIR = os.path.dirname(__file__)
KEY_DIR  = os.path.abspath(os.path.join(BASE_DIR, os.pardir, "keys"))

def _wait_for_keys():
    pk = os.path.join(KEY_DIR, "public_key.txt")
    while not os.path.exists(pk):
        time.sleep(0.05)

def load_public_key():
    _wait_for_keys()
    with open(os.path.join(KEY_DIR, "public_key.txt")) as f:
        n, g = map(int, f.read().split())
    return (n, g)

def load_ta_rsa_pub():
    _wait_for_keys()
    with open(os.path.join(KEY_DIR, "ta_rsa_pub.txt")) as f:
        N, e = map(int, f.read().split())
    return (N, e)

def verify_fkey(token: str, rsa_pub: tuple, expected_hash: str) -> bool:
    """Check signature and matching hash."""
    if "|" not in token:
        return False
    data, sig_str = token.split("|", 1)
    try:
        sig = int(sig_str)
    except:
        return False
    N, e = rsa_pub
    h = int(hashlib.sha256(data.encode()).hexdigest(), 16) % N
    if pow(sig, e, N) != h:
        return False
    parts = dict(p.split(":", 1) for p in data.split(";") if ":" in p)
    return parts.get("hash") == expected_hash

class PaillierProd:
    def __init__(self, n_sq):
        self.n_sq   = n_sq
        self.product = 1
    def step(self, v):
        if v is not None:
            self.product = (self.product * int(v)) % self.n_sq
    def finalize(self):
        return str(self.product)

def init_databases(csv_path, public_key, logger):
    # Load CSV
    with open(csv_path, newline='', encoding='utf-8') as f:
        rdr = csv.reader(f)
        header = next(rdr)
        header[0] = header[0].lstrip('\ufeff')
        rows = [r for r in rdr if any(cell.strip() for cell in r)]
    logger(f"[Server][DEBUG] header = {header}")
    logger(f"[Server][DEBUG] sample = {rows[:3]}")

    # Detect numeric columns
    def is_num(s):
        try: float(s); return True
        except: return False

    numeric_cols = []
    for i, col in enumerate(header):
        vals = [r[i].strip().strip('\'"') for r in rows if r[i].strip()!='']
        if vals and all(is_num(v) for v in vals):
            numeric_cols.append(col)
    logger(f"[Server][DEBUG] numeric_cols = {numeric_cols}")

    # Plaintext DB
    plain = sqlite3.connect(":memory:")
    cp = plain.cursor()
    col_defs = ", ".join(f'"{h}" TEXT' for h in header)
    cp.execute(f"CREATE TABLE data ({col_defs})")
    cp.executemany(
        f"INSERT INTO data VALUES ({','.join('?' for _ in header)})", rows
    )
    plain.commit()

    # Encrypted DB (only numeric columns)
    enc = sqlite3.connect(":memory:")
    ce = enc.cursor()
    if numeric_cols:
        enc_defs = ", ".join(f'"{c}" TEXT' for c in numeric_cols)
        ce.execute(f"CREATE TABLE data_enc ({enc_defs})")
        for r in rows:
            row_c = []
            for c in numeric_cols:
                iv = int(float(r[header.index(c)])) if r[header.index(c)].strip() else 0
                row_c.append(str(encrypt(iv, public_key)))
            ce.execute(
                f"INSERT INTO data_enc VALUES ({','.join('?' for _ in numeric_cols)})",
                row_c
            )
        enc.commit()

    # Register our Paillier‐prod aggregator
    n, _ = public_key
    enc.create_aggregate("paillier_prod", 1, lambda: PaillierProd(n*n))

    return header, numeric_cols, plain, enc

def rewrite_query(q, numeric_cols, logger):
    logger(f"[Server][DEBUG] rewrite IN: {q!r}")
    s = q.strip().rstrip(";").strip()
    if re.search(r"\bWHERE\b", s, re.IGNORECASE):
        logger("[Server][DEBUG] WHERE → SSE")
        return "SSE", None, None

    pat = re.compile(
        r"^SELECT\s+(SUM|COUNT|AVG)\(\s*(\*|\"([^\"]+)\"|(\w+))\)\s+FROM\s+data$",
        re.IGNORECASE
    )
    m = pat.match(s)
    if not m:
        logger("[Server][DEBUG] no match → SSE")
        return "SSE", None, None

    fn = m.group(1).upper()
    col = "*" if (fn=="COUNT" and "*" in m.group(2)) else (m.group(3) or m.group(4))
    logger(f"[Server][DEBUG] fn={fn}, col={col}")
    if fn in ("SUM","AVG") and col not in numeric_cols:
        logger("[Server][DEBUG] not numeric → SSE")
        return "SSE", None, None

    logger("[Server][DEBUG] → FE")
    return "FE", fn, col

def start_server(csv_path, logger):
    public_key = load_public_key()
    rsa_pub    = load_ta_rsa_pub()
    header, numeric_cols, db_plain, db_enc = init_databases(csv_path, public_key, logger)

    with socket.socket() as sock:
        sock.bind(("localhost", 9000))
        sock.listen(5)
        logger("[Server] Listening on localhost:9000")
        while True:
            conn, addr = sock.accept()
            logger(f"[Server] Connection from {addr}")
            data = conn.recv(65536)
            if not data:
                conn.close()
                continue

            lines = data.decode().splitlines()
            if len(lines)<3 or lines[0].upper()!="QUERY":
                conn.sendall(b"ERROR: Bad format")
                conn.close()
                continue

            _, raw_fkey, query = lines
            logger(f"[Server] Received token: {raw_fkey!r}")
            logger(f"[Server] Received query: {query!r}")
            qhash = hashlib.sha256(query.encode()).hexdigest()
            logger(f"[Server] Query hash = {qhash}")

            if not verify_fkey(raw_fkey, rsa_pub, qhash):
                conn.sendall(b"ERROR: Invalid or mismatched FE key")
                conn.close()
                continue

            mode, fn, col = rewrite_query(query, numeric_cols, logger)
            logger(f"[Server][DEBUG] mode={mode}, fn={fn}, col={col}")

            if mode == "FE":
                cur = db_enc.cursor()
                if fn == "SUM":
                    cur.execute(f'SELECT paillier_prod("{col}") FROM data_enc')
                    ciph = int(cur.fetchone()[0])
                    resp = {"mode":"FE","fn":"SUM","cipher":ciph}
                elif fn == "COUNT":
                    cnt = db_plain.execute("SELECT COUNT(*) FROM data").fetchone()[0]
                    resp = {"mode":"FE","fn":"COUNT","cipher":encrypt(cnt,public_key)}
                else:  # AVG
                    cur.execute(f'SELECT paillier_prod("{col}") FROM data_enc')
                    csum = int(cur.fetchone()[0])
                    cnt  = db_plain.execute("SELECT COUNT(*) FROM data").fetchone()[0]
                    resp = {"mode":"FE","fn":"AVG","sum":csum,"count":cnt}

                logger(f"[Server] Generated FE ciphertext: {resp}")

            else:
                cur = db_plain.cursor()
                try:
                    cur.execute(query)
                except Exception as e:
                    conn.sendall(f"ERROR: SQL error: {e}".encode())
                    conn.close()
                    continue

                cols = [d[0] for d in cur.description]
                rows = cur.fetchall()
                out  = []
                for r in rows:
                    row_enc = []
                    for c, v in zip(cols, r):
                        if c in numeric_cols:
                            iv = int(float(v)) if v!="" else 0
                            row_enc.append(str(encrypt(iv, public_key)))
                        else:
                            row_enc.append(v)
                    out.append(row_enc)
                resp = {"mode":"SSE", "columns":cols,
                        "numeric_cols":numeric_cols, "results":out}
                logger(f"[Server] Generated SSE response: {resp}")

            resp_json = json.dumps(resp)
            conn.sendall(resp_json.encode())
            logger(f"[Server] Sent response: {resp_json}")
            conn.close()
