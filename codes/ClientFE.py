# ClientFE.py

import os
import socket
import hashlib
import sqlparse
import json
from .fe_scheme import decrypt

BASE_DIR = os.path.dirname(__file__)
KEY_DIR  = os.path.abspath(os.path.join(BASE_DIR, os.pardir, "keys"))

def load_public_key():
    with open(os.path.join(KEY_DIR, "public_key.txt")) as f:
        n, g = map(int, f.read().split())
    return (n, g)

def load_ta_rsa_pub():
    with open(os.path.join(KEY_DIR, "ta_rsa_pub.txt")) as f:
        N, e = map(int, f.read().split())
    return (N, e)

def get_fkey(query_hash: str) -> str:
    with socket.socket() as s:
        s.connect(("localhost", 8000))
        cmd = f"GET_FKEY AGG {query_hash}"
        s.sendall(cmd.encode())
        return s.recv(4096).decode().strip()

def get_sse_key() -> int:
    with socket.socket() as s:
        s.connect(("localhost", 8000))
        s.sendall(b"GET_SSE_KEY")
        return int(s.recv(4096).decode().strip())

def verify_fkey(token: str, rsa_pub: tuple, expected_hash: str):
    """
    Verify RSA signature on the function key.
    Returns (lam, mu) if valid, else None.
    """
    if "|" not in token:
        return None
    data, sig_str = token.split("|", 1)
    try:
        sig = int(sig_str)
    except:
        return None
    N, e = rsa_pub
    h = int(hashlib.sha256(data.encode()).hexdigest(), 16) % N
    if pow(sig, e, N) != h:
        return None
    parts = dict(p.split(":",1) for p in data.split(";") if ":" in p)
    if parts.get("hash") != expected_hash:
        return None
    return (int(parts["lam"]), int(parts["mu"]))

def send_query(fkey_token: str, sql: str) -> str:
    msg = f"QUERY\n{fkey_token}\n{sql}"
    chunks = []
    with socket.socket() as s:
        s.connect(("localhost", 9000))
        s.sendall(msg.encode())
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode()

def validate_select(q: str):
    """
    Ensure it's a single SELECT statement.
    """
    parsed = sqlparse.parse(q)
    if not parsed or parsed[0].get_type() != "SELECT":
        raise ValueError("Only single SELECT statements are allowed.")

def handle_response(resp_json: str,
                    fkey: tuple,
                    public_key: tuple,
                    op: str = None,
                    col: str = None,
                    where: str = None) -> str:
    """
    - resp_json: raw JSON from the server
    - fkey: (lam, mu) or (None,None)
    - public_key: (n, g)
    - op: "SUM", "COUNT", or "AVG"
    - col: column name or "*"
    - where: the WHERE clause string (without "WHERE"), or None

    Returns a formatted string like:
      [FE] SUM = <value>
      [SSE] SUM = <value>
    """
    try:
        obj = json.loads(resp_json)
    except json.JSONDecodeError:
        return resp_json

    mode = obj.get("mode")

    # ---- Functional Encryption path ----
    if mode == "FE":
        fn = obj["fn"]
        if fn == "AVG":
            s = decrypt(int(obj["sum"]), fkey, public_key)
            c = obj["count"]
            return f"[FE] AVG = {s}/{c} = {s/c:.2f}"
        else:
            val = decrypt(int(obj["cipher"]), fkey, public_key)
            return f"[FE] {fn} = {val}"

    # ---- SSE fallback path ----
    if mode == "SSE_TABLE":
        # 1) decrypt the XOR‐encrypted rows
        sse_key = get_sse_key()
        cols    = obj["columns"]
        enc_rows= obj["rows"]
        dec_rows = []
        for row in enc_rows:
            dr = {
                name: (int(cell) ^ sse_key)
                for name, cell in zip(cols, row)
            }
            dec_rows.append(dr)

        # 2) apply WHERE filter if provided
        if where:
            import re
            m = re.match(r"^(\w+)\s*(>=|<=|!=|<>|=|<|>)\s*(.+)$", where)
            if m:
                fld, op_sym, lit = m.groups()
                lit = lit.strip("'\"")
                # numeric literal?
                try:
                    lit = float(lit)
                except:
                    pass
                ops = {
                    "=": "==", "!=": "!=", "<>": "!=", 
                    ">": ">", "<": "<", ">=": ">=", "<=": "<="
                }
                expr = ops[op_sym]
                dec_rows = [
                    r for r in dec_rows
                    if eval(f"{r[fld]}{expr}{lit}")
                ]

        # 3) perform the aggregate locally
        if op == "SUM":
            result = sum(r[col] for r in dec_rows)
        elif op == "COUNT":
            result = len(dec_rows)
        elif op == "AVG":
            cnt = len(dec_rows)
            result = (sum(r[col] for r in dec_rows)/cnt) if cnt else 0
        else:
            return f"ERROR: unknown op {op}"

        return f"[SSE] {op} = {result}"

    return f"ERROR: unknown mode {mode}"
