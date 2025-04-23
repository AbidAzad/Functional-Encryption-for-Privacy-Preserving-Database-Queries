import os, socket, hashlib, sqlparse, json
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
    """Request a function key from the Trusted Authority."""
    with socket.socket() as s:
        s.connect(("localhost", 8000))
        cmd = f"GET_FKEY AGG {query_hash}"
        s.sendall(cmd.encode())
        raw = s.recv(4096).decode().strip()
    return raw

def verify_fkey(token: str, rsa_pub: tuple, expected_hash: str):
    """
    Verify signature and that the token's embedded hash matches expected_hash.
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
    parts = dict(p.split(":", 1) for p in data.split(";") if ":" in p)
    if parts.get("hash") != expected_hash:
        return None
    return (int(parts["lam"]), int(parts["mu"]))

def send_query(fkey_token: str, sql: str) -> str:
    """Send QUERY + token + SQL to the encrypted‐DB server."""
    msg = f"QUERY\n{fkey_token}\n{sql}"
    with socket.socket() as s:
        s.connect(("localhost", 9000))
        s.sendall(msg.encode())
        return s.recv(65536).decode()

def validate_select(q: str):
    parsed = sqlparse.parse(q)
    if not parsed or parsed[0].get_type() != "SELECT":
        raise ValueError("Only SELECT statements are allowed.")

def handle_response(resp_json: str, fkey: tuple, public_key: tuple) -> str:
    """Decrypt the FE result or decode the SSE fallback."""
    obj  = json.loads(resp_json)
    mode = obj.get("mode")
    if mode == "FE":
        fn = obj["fn"]
        if fn == "AVG":
            s = decrypt(int(obj["sum"]), fkey, public_key)
            c = obj["count"]
            return f"[FE] AVG = {s}/{c} = {s/c:.2f}"
        else:
            val = decrypt(int(obj["cipher"]), fkey, public_key)
            return f"[FE] {fn} = {val}"

    elif mode == "SSE":
        cols = obj["columns"]
        nums = obj["numeric_cols"]
        rows = obj["results"]
        lines = ["[SSE-fallback] " + "\t".join(cols)]
        for r in rows:
            out = []
            for c, v in zip(cols, r):
                if c in nums:
                    out.append(str(decrypt(int(v), fkey, public_key)))
                else:
                    out.append(v)
            lines.append("\t".join(out))
        return "\n".join(lines)

    else:
        return "ERROR: bad response"