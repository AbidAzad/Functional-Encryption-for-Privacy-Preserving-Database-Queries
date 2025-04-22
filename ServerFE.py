# ServerFE.py
import socket, sys, hashlib, sqlite3, sqlparse, json, csv, re
from fe_scheme import encrypt

def load_public_key():
    with open("public_key.txt") as f:
        n, g = map(int, f.read().split())
    return (n, g)

def load_ta_rsa_pub():
    with open("ta_rsa_pub.txt") as f:
        N, e = map(int, f.read().split())
    return (N, e)

def verify_fkey(token_full, rsa_pub):
    if "|" not in token_full:
        return False
    data, sig_str = token_full.split("|", 1)
    try:
        sig = int(sig_str)
    except ValueError:
        return False
    N, e = rsa_pub
    h = int(hashlib.sha256(data.encode()).hexdigest(), 16) % N
    return (pow(sig, e, N) == h) and ("FKEY:AGG" in data)

class PaillierProd:
    def __init__(self, n_sq):
        self.n_sq = n_sq
        self.product = 1
    def step(self, value):
        if value is not None:
            self.product = (self.product * int(value)) % self.n_sq
    def finalize(self):
        return str(self.product)

def is_number(s):
    try:
        float(s)
        return True
    except:
        return False

def init_databases(csv_path, public_key):
    # 1) Load CSV and strip BOM
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        header[0] = header[0].lstrip('\ufeff')
        rows = list(reader)

    # 2) Clean quotes off every cell
    rows = [
        [cell.strip().strip('\'"') for cell in row]
        for row in rows
    ]

    # 3) Drop rows that are entirely blank
    rows = [r for r in rows if any(cell for cell in r)]

    # Debug: header & sample
    print(f"[Server][DEBUG:init] header columns: {header}")
    print(f"[Server][DEBUG:init] cleaned sample rows: {rows[:3]}")

    # 4) Detect numeric columns (ignore empty entries)
    numeric_cols = []
    for idx, col in enumerate(header):
        non_empty_vals = [r[idx] for r in rows if r[idx] != ""]
        if non_empty_vals and all(is_number(v) for v in non_empty_vals):
            numeric_cols.append(col)
    print(f"[Server][DEBUG:init] detected numeric_cols: {numeric_cols}")

    # 5) Build plaintext DB
    conn_plain = sqlite3.connect(":memory:")
    c_plain = conn_plain.cursor()
    c_plain.execute(
        "CREATE TABLE data ({})".format(
            ", ".join(f'"{h}" TEXT' for h in header)
        )
    )
    c_plain.executemany(
        f"INSERT INTO data VALUES ({','.join('?' for _ in header)})",
        rows
    )
    conn_plain.commit()

    # 6) Build encrypted DB (only numeric columns)
    conn_enc = sqlite3.connect(":memory:")
    c_enc = conn_enc.cursor()
    if numeric_cols:
        c_enc.execute(
            "CREATE TABLE data_enc ({})".format(
                ", ".join(f'"{c}" TEXT' for c in numeric_cols)
            )
        )
        for r in rows:
            enc_row = []
            for c in numeric_cols:
                val = r[header.index(c)]
                # skip empty by treating as 0
                iv = int(float(val)) if val != "" else 0
                enc_row.append(str(encrypt(iv, public_key)))
            c_enc.execute(
                f"INSERT INTO data_enc VALUES ({','.join('?' for _ in numeric_cols)})",
                enc_row
            )
        conn_enc.commit()

    # 7) Register homomorphic aggregator
    n, _ = public_key
    conn_enc.create_aggregate("paillier_prod", 1, lambda: PaillierProd(n*n))

    return header, numeric_cols, conn_plain, conn_enc

def rewrite_query(query, numeric_cols):
    print(f"[Server][DEBUG:rewrite] input query: {query!r}")
    q = query.strip().rstrip(';').strip()
    print(f"[Server][DEBUG:rewrite] stripped query: {q!r}")

    # Any WHERE clause → SSE
    if re.search(r'\bWHERE\b', q, flags=re.IGNORECASE):
        print("[Server][DEBUG:rewrite] detected WHERE → SSE")
        return ("SSE", None, None)

    # Try to match plain SUM/COUNT/AVG
    pattern = re.compile(r"""
        ^\s*SELECT\s+
          (SUM|COUNT|AVG)\s*\(\s*
            (?:\*|"([^"]+)"|([\w]+))
          \s*\)\s+
        FROM\s+
          "?([A-Za-z_][\w]*)"?\s*$
    """, re.IGNORECASE | re.VERBOSE)

    m = pattern.match(q)
    if not m:
        print("[Server][DEBUG:rewrite] regex did NOT match → SSE")
        return ("SSE", None, None)

    fn    = m.group(1).upper()
    col_q = m.group(2)
    col_u = m.group(3)
    table = m.group(4)

    # COUNT(*) special case
    if fn == "COUNT" and "*" in q[q.index("("):q.index(")")+1]:
        col = "*"
    else:
        col = col_q or col_u

    print(f"[Server][DEBUG:rewrite] regex matched: fn={fn}, col={col}, table={table}")

    # Must query our `data` table
    if table.lower() != "data":
        print(f"[Server][DEBUG:rewrite] table '{table}' != 'data' → SSE")
        return ("SSE", None, None)

    # SUM/AVG only on numeric columns
    if fn in ("SUM","AVG") and col not in numeric_cols:
        print(f"[Server][DEBUG:rewrite] col '{col}' not in numeric_cols → SSE")
        return ("SSE", None, None)

    print(f"[Server][DEBUG:rewrite] Classified FE: fn={fn}, col={col}")
    return ("FE", fn, col)

def start_server(csv_path):
    public_key = load_public_key()
    rsa_pub    = load_ta_rsa_pub()
    header, numeric_cols, db_plain, db_enc = init_databases(csv_path, public_key)

    host, port = "localhost", 9000
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(5)
        print(f"[Server] Listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(65536)
                if not data:
                    continue

                parts = data.decode().splitlines()
                if len(parts) < 3 or parts[0].strip().upper() != "QUERY":
                    conn.sendall(b"ERROR: Bad format\n")
                    continue

                _, fkey_token, query = parts[0], parts[1].strip(), parts[2].strip()
                print(f"[Server] Received query: {query!r}")

                if not verify_fkey(fkey_token, rsa_pub):
                    conn.sendall(b"ERROR: Invalid FE key\n")
                    continue

                mode, fn, col = rewrite_query(query, numeric_cols)
                print(f"[Server][DEBUG] rewrite_query returned: mode={mode}, fn={fn}, col={col}")

                if mode == "FE":
                    cur = db_enc.cursor()
                    if fn == "SUM":
                        cur.execute(f'SELECT paillier_prod("{col}") FROM data_enc')
                        cipher = int(cur.fetchone()[0])
                        resp = {"mode":"FE","fn":"SUM","cipher":cipher}

                    elif fn == "COUNT":
                        if col == "*":
                            cnt = db_plain.execute("SELECT COUNT(*) FROM data").fetchone()[0]
                        else:
                            cnt = db_plain.execute(f'SELECT COUNT("{col}") FROM data').fetchone()[0]
                        resp = {"mode":"FE","fn":"COUNT","cipher":encrypt(cnt, public_key)}

                    else:  # AVG
                        cur.execute(f'SELECT paillier_prod("{col}") FROM data_enc')
                        sum_ct = int(cur.fetchone()[0])
                        cnt    = db_plain.execute("SELECT COUNT(*) FROM data").fetchone()[0]
                        resp    = {"mode":"FE","fn":"AVG","sum":sum_ct,"count":cnt}

                else:
                    cur = db_plain.cursor()
                    try:
                        cur.execute(query)
                    except Exception as e:
                        conn.sendall(f"ERROR: SQL execution error: {e}\n".encode())
                        continue

                    cols = [d[0].lstrip('\ufeff') for d in cur.description]
                    out_rows = []
                    for row in cur.fetchall():
                        enc_row = []
                        for c, v in zip(cols, row):
                            if c in numeric_cols:
                                iv = int(float(v)) if v!="" else 0
                                enc_row.append(str(encrypt(iv, public_key)))
                            else:
                                enc_row.append(v)
                        out_rows.append(enc_row)

                    resp = {
                        "mode":"SSE",
                        "columns": cols,
                        "numeric_cols": numeric_cols,
                        "results": out_rows
                    }

                conn.sendall(json.dumps(resp).encode())

if __name__=="__main__":
    if len(sys.argv) != 2:
        print("Usage: python ServerFE.py <your.csv>")
        sys.exit(1)
    start_server(sys.argv[1])
