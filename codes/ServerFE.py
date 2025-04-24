import os, time, sqlite3, socket, hashlib, json, csv, re
from datetime import datetime
from .fe_scheme import encrypt

BASE_DIR = os.path.dirname(__file__)
KEY_DIR  = os.path.abspath(os.path.join(BASE_DIR, os.pardir, "keys"))

def _wait_for_keys():
    # wait until both FE and SSE keys exist
    while not (os.path.exists(os.path.join(KEY_DIR, "public_key.txt")) and
               os.path.exists(os.path.join(KEY_DIR, "sse_key.txt"))):
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

def load_sse_key():
    _wait_for_keys()
    return int(open(os.path.join(KEY_DIR, "sse_key.txt")).read().strip())

def verify_fkey(token, rsa_pub, expected_hash):
    if "|" not in token:
        return False
    data, sig_str = token.split("|",1)
    try:
        sig = int(sig_str)
    except:
        return False
    N, e = rsa_pub
    h = int(hashlib.sha256(data.encode()).hexdigest(), 16) % N
    if pow(sig, e, N) != h:
        return False
    parts = dict(p.split(":",1) for p in data.split(";") if ":" in p)
    return parts.get("hash") == expected_hash

def init_databases(csv_path, public_key, logger):
    # 1) load CSV
    with open(csv_path, newline='', encoding='utf-8') as f:
        rdr    = csv.reader(f)
        header = next(rdr)
        header[0] = header[0].lstrip('\ufeff')
        rows   = [r for r in rdr if any(cell.strip() for cell in r)]

    #logger(f"[DEBUG] header = {header}")
    #logger(f"[DEBUG] sample plaintext rows = {rows[:3]}")

    # 2) detect numeric columns
    def is_num(s):
        try: float(s); return True
        except: return False

    numeric_cols = [
        header[i]
        for i in range(len(header))
        if all(is_num(r[i].strip()) for r in rows if r[i].strip())
    ]
    #logger(f"[DEBUG] numeric_cols = {numeric_cols}")

    # 3) plaintext in-memory DB
    plain = sqlite3.connect(":memory:")
    pcur  = plain.cursor()
    defs  = ", ".join(f'"{h}" TEXT' for h in header)
    pcur.execute(f"CREATE TABLE data ({defs})")
    pcur.executemany(
        f"INSERT INTO data VALUES ({','.join('?' for _ in header)})",
        rows
    )
    plain.commit()

    # 4) Paillier-encrypted DB for FE
    enc = sqlite3.connect(":memory:")
    ecur = enc.cursor()
    if numeric_cols:
        enc_defs = ", ".join(f'"{c}" TEXT' for c in numeric_cols)
        ecur.execute(f"CREATE TABLE data_enc ({enc_defs})")
        for r in rows:
            cipher_row = []
            for c in numeric_cols:
                iv = int(float(r[header.index(c)])) if r[header.index(c)].strip() else 0
                cipher_row.append(str(encrypt(iv, public_key)))
            ecur.execute(
                f"INSERT INTO data_enc VALUES ({','.join('?' for _ in numeric_cols)})",
                cipher_row
            )
        enc.commit()
        # FIXED: pull into cols_expr before the f-string
        cols_expr_enc = ", ".join(f'"{c}"' for c in numeric_cols)
        sample_enc   = ecur.execute(
            f"SELECT {cols_expr_enc} FROM data_enc LIMIT 3"
        ).fetchall()
        logger(f"[DEBUG] encrypted sample rows = {sample_enc}")

    # register FE aggregate
    n, _ = public_key
    enc.create_aggregate("paillier_prod", 1, lambda: type(
        "A",(),{
            "n_sq":n*n,
            "product":1,
            "step":lambda self,v: setattr(self,"product",(self.product*int(v))%self.n_sq),
            "finalize":lambda self:str(self.product)
        }
    )())

    # 5) SSE-encrypted DB (simple XOR) for WHERE queries
    sse = sqlite3.connect(":memory:")
    scur = sse.cursor()
    if numeric_cols:
        # Use TEXT columns so we can store arbitrarily large integers
        sse_defs = ", ".join(f'"{c}" TEXT' for c in numeric_cols)
        scur.execute(f"CREATE TABLE data_sse ({sse_defs})")

        sse_key = load_sse_key()
        for r in rows:
            row_s = []
            for c in numeric_cols:
                iv = int(float(r[header.index(c)])) if r[header.index(c)].strip() else 0
                # XOR, then convert to string
                row_s.append(str(iv ^ sse_key))
            scur.execute(
                f"INSERT INTO data_sse VALUES ({','.join('?' for _ in numeric_cols)})",
                row_s
            )
        sse.commit()

        # Debug sample
        cols_expr_sse = ", ".join(f'"{c}"' for c in numeric_cols)
        sample_sse = scur.execute(
            f"SELECT {cols_expr_sse} FROM data_sse LIMIT 3"
        ).fetchall()
        logger(f"[DEBUG] SSE sample rows = {sample_sse}")


    return header, numeric_cols, plain, enc, sse

def rewrite_query(q, numeric_cols, logger):
    """
    FE only if pure SUM/COUNT/AVG without WHERE.
    Otherwise SSE_TABLE.
    """
    ts = datetime.now().strftime("%H:%M:%S")
    logger(f"[{ts}] rewrite: {q!r}")
    s = q.strip().rstrip(";")
    pat = re.compile(
        r"^SELECT\s+(SUM|COUNT|AVG)\(\s*(\*|\"([^\"]+)\"|(\w+))\)\s+FROM\s+data$",
        re.IGNORECASE
    )
    m = pat.match(s)
    if m:
        fn  = m.group(1).upper()
        col = "*" if (fn=="COUNT" and "*" in m.group(2)) else (m.group(3) or m.group(4))
        if fn in ("SUM","AVG") and col not in numeric_cols:
            logger("col not numeric → SSE_TABLE")
            return "SSE_TABLE", None, None
        logger(f"no-WHERE agg → FE(fn={fn},col={col})")
        return "FE", fn, col
    logger("detected WHERE or non-agg → SSE_TABLE")
    return "SSE_TABLE", None, None

def start_server(csv_path, logger):
    public_key = load_public_key()
    rsa_pub    = load_ta_rsa_pub()
    header, numeric_cols, plain_db, enc_db, sse_db = init_databases(csv_path, public_key, logger)

    with socket.socket() as sock:
        sock.bind(("localhost", 9000))
        sock.listen(5)
        logger("Server listening on localhost:9000")

        while True:
            conn, addr = sock.accept()
            data = conn.recv(65536)
            if not data:
                conn.close(); continue

            lines = data.decode().splitlines()
            if len(lines)<3 or lines[0].upper()!="QUERY":
                conn.sendall(b"ERROR: Bad format")
                conn.close(); continue

            _, raw_fkey, query = lines
            logger(f"Token: {raw_fkey!r}")
            logger(f"Query: {query!r}")
            qhash = hashlib.sha256(query.encode()).hexdigest()
            logger(f"Hash: {qhash}")

            if not verify_fkey(raw_fkey, rsa_pub, qhash):
                logger("Invalid FE key → SSE_TABLE")
                mode, fn, col = "SSE_TABLE", None, None
            else:
                mode, fn, col = rewrite_query(query, numeric_cols, logger)

            if mode == "FE":
                cur = enc_db.cursor()
                if fn == "SUM":
                    cur.execute(f'SELECT paillier_prod("{col}") FROM data_enc')
                    ciph = int(cur.fetchone()[0])
                    resp = {"mode":"FE","fn":"SUM","cipher":ciph}
                elif fn == "COUNT":
                    cnt  = plain_db.execute("SELECT COUNT(*) FROM data").fetchone()[0]
                    resp = {"mode":"FE","fn":"COUNT","cipher":encrypt(cnt, public_key)}
                else:  # AVG
                    cur.execute(f'SELECT paillier_prod("{col}") FROM data_enc')
                    csum = int(cur.fetchone()[0])
                    cnt  = plain_db.execute("SELECT COUNT(*) FROM data").fetchone()[0]
                    resp = {"mode":"FE","fn":"AVG","sum":csum,"count":cnt}
                logger("→ FE ciphertext generated")

            else:
                # SSE_TABLE fallback using sse_db only
                scur = sse_db.cursor()
                cols_expr = ", ".join(f'"{c}"' for c in numeric_cols)
                scur.execute(f"SELECT {cols_expr} FROM data_sse")
                encrypted_rows = scur.fetchall()
                resp = {
                    "mode":    "SSE_TABLE",
                    "columns": numeric_cols,
                    "rows":    encrypted_rows
                }
                logger(f"→ SSE_TABLE returned {len(encrypted_rows)} rows")

            conn.sendall(json.dumps(resp).encode())
            conn.close()
