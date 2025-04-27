#!/usr/bin/env python3
import os
import time
import hashlib
import json
import re
import threading
import socket

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# ── simple-fhe imports ───────────────────────────────────────────────────────
from simplefhe import (
    initialize,       # initialize the BFV scheme
    generate_keypair, # generate BFV keys
    set_public_key,   # load BFV public key
    set_private_key,  # load BFV private key
    set_relin_keys,   # load BFV relinearization keys
    encrypt,          # BFV encryption
    decrypt as sfhe_decrypt  # BFV decryption (alias)
)

# ── Configuration ──────────────────────────────────────────────────────────────
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
FIG_DIR  = os.path.join(os.path.dirname(__file__), "figures")
# ensure output directory exists
os.makedirs(FIG_DIR, exist_ok=True)

N_RUNS = 5  # how many times to repeat each measurement

# which datasets to test and which SQL-style queries to run on them
DATASETS = {
    "Salary_Data.csv": [
        'SELECT SUM("Years of Experience") FROM data',
        'SELECT COUNT(*) FROM data',
        'SELECT AVG(Age) FROM data',
        'SELECT SUM(Age) FROM data',
        'SELECT AVG("Years of Experience") FROM data',
        'SELECT SUM(Age) FROM data WHERE Age > 30',
        'SELECT COUNT(*) FROM data WHERE "Years of Experience" >= 5',
        'SELECT AVG(Age) FROM data WHERE "Years of Experience" < 10',
    ],
    "Healthcare_Data.csv": [
        'SELECT SUM("Billing Amount") FROM data',
        'SELECT COUNT(*) FROM data',
        'SELECT AVG(Age) FROM data',
        'SELECT SUM(Age) FROM data',
        'SELECT AVG("Billing Amount") FROM data',
        'SELECT SUM(Age) FROM data WHERE Age >= 50',
        'SELECT COUNT(*) FROM data WHERE "Billing Amount" > 20000',
        'SELECT AVG(Age) FROM data WHERE "Billing Amount" < 15000',
    ],
    "Sleep_Data.csv": [
        'SELECT SUM("Sleep_Duration_Hours") FROM data',
        'SELECT COUNT(*) FROM data',
        'SELECT AVG("Heart_Rate_Variability") FROM data',
        'SELECT SUM("Heart_Rate_Variability") FROM data',
        'SELECT AVG("Sleep_Duration_Hours") FROM data',
        'SELECT SUM(Sleep_Quality_Score) FROM data WHERE Sleep_Quality_Score >= 5',
        'SELECT COUNT(*) FROM data WHERE Stress_Level > 3',
        'SELECT AVG(Body_Temperature) FROM data WHERE Light_Exposure_hours < 8',
    ],
    "Bird_Song_Data.csv": [
        'SELECT SUM(chromogram_0_0) FROM data',
        'SELECT COUNT(*) FROM data',
        'SELECT AVG(chromogram_0_0) FROM data',
        'SELECT SUM(chromogram_0_1) FROM data',
        'SELECT AVG(chromogram_0_1) FROM data',
        'SELECT SUM(chromogram_0_0) FROM data WHERE chromogram_0_0 > 100',
        'SELECT COUNT(*) FROM data WHERE chromogram_0_1 < 50',
        'SELECT AVG(chromogram_0_2) FROM data WHERE chromogram_0_2 != 0',
    ],
}

def logger(msg: str):
    """Simple timestamped console logger."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

# ── Utility: clean all “numeric” columns exactly as Paillier-FE does ──────────
def clean_numeric_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remove any non-digit characters (commas, $, etc.) from all columns,
    coerce to numeric, fill NaNs with 0, then cast to int.
    """
    for col in df.columns:
        # 1) strip out everything except digits, dot, minus
        cleaned = df[col].astype(str).str.replace(r"[^0-9\.\-]", "", regex=True)
        # 2) convert to numeric, invalid → NaN
        nums = pd.to_numeric(cleaned, errors="coerce")
        # 3) if some values parse to numbers, replace column
        if not nums.isna().all():
            df[col] = nums.fillna(0).astype(int)
    return df

# ── SQL helpers ───────────────────────────────────────────────────────────────
def shorten_label(q: str) -> str:
    """
    Create a short label for a query, e.g.
      SELECT SUM("Billing Amount") → SUM(BA)
      SELECT COUNT(*) → COUNT
      SELECT SUM(col) WHERE col>5 → SUM(col)|col>5
    """
    parts = q.split("WHERE", 1)
    sel, cond = parts[0].strip(), (parts[1].strip() if len(parts) == 2 else None)
    m = re.match(r'SELECT\s+(SUM|COUNT|AVG)\(\s*(\*|"?([\w\s\.]+)"?)\)', sel, re.IGNORECASE)
    if not m:
        return q  # fallback to full query
    op, col_expr = m.group(1).upper(), m.group(2)
    if op == "COUNT" and col_expr.strip() == "*":
        base = "COUNT"
    else:
        col = col_expr.strip().strip('"')
        # take first letters of words >2 characters
        words = re.findall(r"[A-Za-z]+", col)
        abbr = "".join(w[0] for w in words if len(w) > 2) or col[:3]
        base = f"{op}({abbr})"
    if cond:
        cm = re.match(r'^\s*"?([\w\s\.]+)"?\s*(>=|<=|!=|<>|=|<|>)\s*(.+)$', cond)
        if cm:
            fld, sym, lit = cm.group(1), cm.group(2).replace("<>", "!="), cm.group(3).strip().strip("'\"")
            words2 = re.findall(r"[A-Za-z]+", fld)
            fabbr = "".join(w[0] for w in words2 if len(w) > 2) or fld[:3]
            return f"{base}|{fabbr}{sym}{lit}"
    return base

def parse_condition(cond: str):
    """
    Parse a simple SQL WHERE clause like
      "Age >= 30"
    into (field, operator, literal) tuple,
    converting numeric literals to float.
    """
    pat = r'^\s*"?([\w\s\.]+)"?\s*(>=|<=|!=|<>|=|<|>)\s*(.+)$'
    m = re.match(pat, cond)
    if not m:
        raise ValueError(f"Cannot parse WHERE: {cond!r}")
    fld = m.group(1).strip()
    sym = m.group(2).replace("<>", "!=")
    lit = m.group(3).strip().strip("'\"")
    # numeric literal?
    if re.fullmatch(r"[\d\.]+", lit):
        lit = float(lit)
    return fld, sym, lit

# ── SimpleFHE microservice ─────────────────────────────────────────────────────
_simplefhe_thread   = None
_simplefhe_shutdown = None

def start_simplefhe_server_async(df: pd.DataFrame, port: int, logger):
    """
    Launch a background thread that listens for plaintext queries
    over a socket, executes them homomorphically via BFV, and returns
    encrypted sums/counts/averages.
    """
    global _simplefhe_thread, _simplefhe_shutdown
    if _simplefhe_thread and _simplefhe_thread.is_alive():
        raise RuntimeError("SimpleFHE server already running")
    _simplefhe_shutdown = threading.Event()

    def serve():
        with socket.socket() as sock:
            sock.bind(("localhost", port))
            sock.listen(5)
            sock.settimeout(1.0)
            logger(f"[SimpleFHE] listening on port {port}")
            while not _simplefhe_shutdown.is_set():
                try:
                    conn, _ = sock.accept()
                except socket.timeout:
                    continue
                with conn:
                    lines = conn.recv(65536).decode().splitlines()
                    if len(lines) < 2 or lines[0] != "QUERY":
                        # bad format → return error JSON
                        conn.sendall(b'{"error":"bad format"}')
                        continue
                    sql = lines[1]
                    # execute and return the raw numeric result
                    resp = {"result": _simplefhe_handle_query(sql, df)}
                    conn.sendall(json.dumps(resp).encode())

    # start server thread
    _simplefhe_thread = threading.Thread(target=serve, daemon=True)
    _simplefhe_thread.start()

    # wait until it's listening
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with socket.create_connection(("localhost", port), timeout=0.5):
                logger(f"[SimpleFHE] up on port {port}")
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("SimpleFHE server failed to start")

def stop_simplefhe_server():
    """Shut down the BFV microservice cleanly."""
    global _simplefhe_thread, _simplefhe_shutdown
    if _simplefhe_shutdown:
        _simplefhe_shutdown.set()
    if _simplefhe_thread:
        _simplefhe_thread.join()
    _simplefhe_thread, _simplefhe_shutdown = None, None

def send_simplefhe_query(sql: str, port: int) -> float:
    """Client helper: send a QUERY message and parse the JSON result."""
    msg = f"QUERY\n{sql}"
    with socket.socket() as s:
        s.connect(("localhost", port))
        s.sendall(msg.encode())
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    obj = json.loads(buf.decode())
    return float(obj["result"])

def _simplefhe_handle_query(sql: str, df: pd.DataFrame) -> float:
    """
    Private: execute a SELECT SUM/COUNT/AVG query homomorphically on df.
    Returns the decrypted float result.
    """
    q = sql.strip().rstrip(";")
    parts = q.split("WHERE", 1)
    sel, cond = parts[0].strip(), (parts[1].strip() if len(parts) == 2 else None)

    # build boolean mask for WHERE clause
    if cond:
        fld, sym, lit = parse_condition(cond)
        col = df[fld].astype(float)
        mask = col.apply(lambda x: eval(f"x {sym} {lit}"))
    else:
        mask = pd.Series(True, index=df.index)

    # COUNT(*)
    if re.match(r"SELECT\s+COUNT\s*\(\s*\*\s*\)\s+FROM\s+data", sel, re.IGNORECASE):
        csum = None
        # encrypt 1 for each matching row, sum homomorphically
        for _ in mask[mask].index:
            e = encrypt(1)
            csum = e if csum is None else (csum + e)
        return 0.0 if csum is None else float(sfhe_decrypt(csum))

    # SUM or AVG on a numeric column
    m = re.match(r'SELECT\s+(SUM|AVG)\(\s*"?([\w\s\.]+)"?\)', sel, re.IGNORECASE)
    if not m:
        raise ValueError(f"Unrecognized query for SimpleFHE: {sql!r}")
    op, colname = m.group(1).upper(), m.group(2)
    vals = df.loc[mask, colname].astype(float).dropna().tolist()

    # homomorphic sum of all values
    csum = None
    for v in vals:
        e = encrypt(int(v))
        csum = e if csum is None else (csum + e)
    total = 0.0 if csum is None else float(sfhe_decrypt(csum))

    return total if op == "SUM" else (total / len(vals) if vals else 0.0)

# ── Quick Compare Routine ─────────────────────────────────────────────────────
def compare_systems():
    """
    For each dataset, start both the Paillier-FE system and the BFV microservice,
    run each query once, and print results side by side.
    """
    from codes.authority import start_authority_async, stop_authority
    from codes.ServerFE    import start_server_async, stop_server
    from codes.ClientFE    import get_fkey, send_query, verify_fkey, load_ta_rsa_pub, load_public_key as fe_load_pub, get_sse_key
    from codes.fe_scheme   import decrypt as fe_decrypt

    print("\n=== Quick Compare: Paillier-FE vs SimpleFHE ===")
    for idx, (fname, queries) in enumerate(DATASETS.items()):
        print(f"\n-- Dataset: {fname} --")

        # 1) Load and clean the CSV
        path     = os.path.join(DATA_DIR, fname)
        df_full  = pd.read_csv(path)
        df       = clean_numeric_columns(df_full.copy())

        # 2) Determine BFV plaintext modulus bound from SUM/AVG columns
        sum_cols = []
        for q in queries:
            m = re.match(r'SELECT\s+(SUM|AVG)\(\s*"?([\w\s\.]+)"?\)', q, re.IGNORECASE)
            if m:
                sum_cols.append(m.group(2).strip().strip('"'))
        max_int = max((int(df[c].abs().sum()) for c in sum_cols), default=0) + 1

        # 3) Launch BFV microservice
        initialize("int", max_int=max_int)
        pub, priv, relin = generate_keypair()
        set_public_key(pub); set_relin_keys(relin); set_private_key(priv)
        sf_port = 10000 + idx
        start_simplefhe_server_async(df, sf_port, logger)

        # 4) Launch Paillier-FE authority & server
        start_authority_async(logger)
        start_server_async(path, logger)
        rsa_pub = load_ta_rsa_pub()
        fe_pub  = fe_load_pub()

        # 5) Run each query once
        for q in queries:
            h    = hashlib.sha256(q.encode()).hexdigest()
            resp = send_query(get_fkey(h), q)
            obj  = json.loads(resp)

            # parse operation and column from q
            m2   = re.match(
                r'SELECT\s+(SUM|COUNT|AVG)\(\s*(\*|"?([\w\s\.]+)"?)\)',
                q, re.IGNORECASE
            )
            op   = m2.group(1).upper()
            raw  = m2.group(2)
            col  = None if (op == "COUNT" and raw == "*") else (m2.group(3) or raw).strip().strip('"')
            where = q.split("WHERE",1)[1].strip() if "WHERE" in q else None

            # Paillier-FE path
            if obj.get("mode") == "FE":
                if op in ("SUM","COUNT"):
                    fe_val = fe_decrypt(
                        int(obj["cipher"]),
                        verify_fkey(get_fkey(h), rsa_pub, h),
                        fe_pub
                    )
                else:  # AVG
                    s   = int(obj["sum"])
                    cnt = obj["count"]
                    s_val = fe_decrypt(
                        s,
                        verify_fkey(get_fkey(h), rsa_pub, h),
                        fe_pub
                    )
                    fe_val = (s_val / cnt) if cnt else 0.0

            # SSE fallback inside Paillier-FE
            elif obj.get("mode") == "SSE_TABLE":
                sk   = get_sse_key()
                cols = obj["columns"]
                rows = obj["rows"]
                # decrypt rows by XOR
                decs = [{c: (int(v) ^ sk) for c,v in zip(cols,row)} for row in rows]
                if where:
                    fld, sym, lit = parse_condition(where)
                    decs = [r for r in decs if eval(f"{r[fld]}{sym}{lit}")]
                if op == "COUNT":
                    fe_val = len(decs)
                elif op == "SUM":
                    fe_val = sum(r[col] for r in decs)
                else:  # AVG
                    fe_val = sum(r[col] for r in decs)/len(decs) if decs else 0.0

            else:
                fe_val = None

            # SimpleFHE baseline
            sf_val = send_simplefhe_query(q, sf_port)

            # print side by side
            print(f"Query: {q!r}")
            print(f"  Paillier-FE result = {fe_val}")
            print(f"  SimpleFHE   result = {sf_val}\n")

        # 6) Teardown both services
        stop_server()
        stop_authority()
        stop_simplefhe_server()

# ── Full Benchmark + Plotting ──────────────────────────────────────────────────
def run_metrics():
    """
    Runs each query N_RUNS times on both systems, records timings
    (key fetch, execution, decryption for FE; key fetch for SSE;
    execution for FHE), computes averages, and produces bar plots.
    """
    from codes.authority import start_authority_async, stop_authority
    from codes.ServerFE    import start_server_async, stop_server
    from codes.ClientFE    import (
        get_fkey, send_query, verify_fkey,
        load_ta_rsa_pub, load_public_key as fe_load_pub, get_sse_key
    )
    from codes.fe_scheme   import decrypt as fe_decrypt

    records = []
    for idx, (fname, queries) in enumerate(DATASETS.items()):
        # 1) Load & clean
        path     = os.path.join(DATA_DIR, fname)
        df_full  = pd.read_csv(path)
        df_clean = clean_numeric_columns(df_full.copy())

        # 2) Determine BFV max_int from SUM+AVG columns & total count
        sum_cols  = []
        for q in queries:
            m = re.match(r'SELECT\s+(SUM|AVG)\(\s*"?([\w\s\.]+)"?\)', q, re.IGNORECASE)
            if m:
                sum_cols.append(m.group(2).strip().strip('"'))
        max_sum   = max((df_clean[c].abs().sum() for c in sum_cols), default=0)
        max_count = len(df_clean)
        max_int   = max(max_sum, max_count) + 1

        # 3) Start BFV microservice
        initialize("int", max_int=max_int)
        pub, priv, relin = generate_keypair()
        set_public_key(pub); set_relin_keys(relin); set_private_key(priv)
        sf_port = 10000 + idx
        start_simplefhe_server_async(df_clean, sf_port, logger)

        # 4) Start Paillier-FE authority & server
        start_authority_async(logger)
        start_server_async(path, logger)
        rsa_pub = load_ta_rsa_pub()
        fe_pub  = fe_load_pub()

        # 5) Run each query N_RUNS times
        for q in queries:
            h = hashlib.sha256(q.encode()).hexdigest()

            # arrays to collect timings & values
            fe_key_t, fe_q_rt = [], []
            fe_exec, fe_dec, fe_val = [], [], []
            sse_key_t, sse_q_rt = [], []
            sse_exec, sse_val = [], []
            fhe_rt, true_val  = [], []

            # split out WHERE clause if any
            parts       = q.split("WHERE", 1)
            cond_clause = parts[1].strip() if len(parts) == 2 else None

            for _ in range(N_RUNS):
                # Paillier-FE key fetch timing
                t0    = time.time()
                token = get_fkey(h)
                fe_key_t.append(time.time() - t0)

                # Paillier-FE vs SSE request timing
                t1       = time.time()
                resp_json= send_query(token, q)
                rtt      = time.time() - t1
                obj      = json.loads(resp_json)

                # FE vs SSE branch
                if obj.get("mode") == "FE":
                    fe_q_rt.append(rtt)
                    fn = obj["fn"]
                    if fn in ("SUM", "COUNT"):
                        # decrypt homomorphic ciphertext
                        dt0  = time.time()
                        val  = fe_decrypt(int(obj["cipher"]),
                                         verify_fkey(token, rsa_pub, h),
                                         fe_pub)
                        fe_dec.append(time.time() - dt0)
                    else:  # AVG
                        s, c = int(obj["sum"]), obj["count"]
                        dt0  = time.time()
                        sd   = fe_decrypt(s,
                                         verify_fkey(token, rsa_pub, h),
                                         fe_pub)
                        fe_dec.append(time.time() - dt0)
                        val = sd / c if c else 0.0

                    fe_exec.append(rtt - fe_dec[-1])
                    fe_val.append(val)

                else:
                    # SSE fallback decrypt-by-XOR
                    sse_q_rt.append(rtt)
                    t4 = time.time()
                    sk = get_sse_key()
                    sse_key_t.append(time.time() - t4)

                    cols, rows = obj["columns"], obj["rows"]
                    decs = [{c: (int(v) ^ sk) for c, v in zip(cols, row)} for row in rows]
                    if cond_clause:
                        fld, sym, lit = parse_condition(cond_clause)
                        decs = [r for r in decs if eval(f"{r[fld]}{sym}{lit}")]

                    # local aggregate
                    if q.upper().startswith("SELECT COUNT"):
                        val = len(decs)
                    else:
                        m2 = re.match(r'SELECT\s+(SUM|AVG)\(\s*"?([\w\s\.]+)"?\s*\)', q, re.IGNORECASE)
                        op, col = m2.group(1).upper(), m2.group(2)
                        if op == "SUM":
                            val = sum(r[col] for r in decs)
                        else:
                            cnt = len(decs)
                            val = (sum(r[col] for r in decs) / cnt) if cnt else 0.0

                    sse_exec.append(time.time() - t4)
                    sse_val.append(val)

                # SimpleFHE baseline timing & true_val
                tf0 = time.time()
                tv  = send_simplefhe_query(q, sf_port)
                fhe_rt.append(time.time() - tf0)
                true_val.append(tv)

            # 6) Compute averages & errors
            tvm     = np.mean(true_val)
            fe_k    = np.mean(fe_key_t) if fe_key_t else np.nan
            fe_q    = np.mean(fe_q_rt)  if fe_q_rt else np.nan
            fe_e    = np.mean(fe_exec)  if fe_exec else np.nan
            fe_d    = np.mean(fe_dec)   if fe_dec else np.nan
            fe_v    = np.mean(fe_val)   if fe_val else np.nan
            err_fe  = abs(fe_v - tvm)   if fe_val else np.nan
            acc_fe  = (1 - err_fe / tvm) if (tvm and fe_val) else np.nan

            sse_k   = np.mean(sse_key_t) if sse_key_t else np.nan
            sse_q   = np.mean(sse_q_rt)  if sse_q_rt else np.nan
            sse_e   = np.mean(sse_exec)  if sse_exec else np.nan
            sse_v   = np.mean(sse_val)   if sse_val else np.nan
            err_sse = abs(sse_v - tvm)   if sse_val else np.nan
            acc_sse = (1 - err_sse / tvm) if (tvm and sse_val) else np.nan

            fhe_e   = np.mean(fhe_rt)
            mode    = "SSE" if sse_val else "FE"

            # record one line per query
            records.append({
                "dataset":           fname,
                "query":             q,
                "mode":              mode,
                "fe_key_fetch_avg":  fe_k,
                "fe_query_rt_avg":   fe_q,
                "fe_exec_avg":       fe_e,
                "fe_decrypt_avg":    fe_d,
                "sse_key_fetch_avg": sse_k,
                "sse_query_rt_avg":  sse_q,
                "sse_exec_avg":      sse_e,
                "fhe_exec_avg":      fhe_e,
                "true_value":        tvm,
                "err_fe":            err_fe,
                "acc_fe":            acc_fe,
                "err_sse":           err_sse,
                "acc_sse":           acc_sse
            })

            logger(f"Q={shorten_label(q)!r} → mode={mode}, true={tvm:.2f}, err_FE={err_fe:.2e}, err_SSE={err_sse:.2e}")

        # 7) Teardown services
        stop_server()
        stop_authority()
        stop_simplefhe_server()

    # 8) Build DataFrame for plotting
    df = pd.DataFrame(records)

    # ── FE plots ────────────────────────────────────────────────────────────────
    for ds, grp in df.groupby("dataset"):
        fe = grp[grp["mode"] == "FE"]
        if not fe.empty:
            x, w = np.arange(len(fe)), 0.25
            fig, ax = plt.subplots(figsize=(10,4))
            ax.set_yscale("log")
            ax.grid(True, axis="y", which="major", linestyle="--", linewidth=0.7, alpha=0.7)
            ax.bar(x-w, fe["fe_exec_avg"],    width=w, label="Paillier-FE: Exec")
            ax.bar(x  , fe["fe_decrypt_avg"], width=w, label="Paillier-FE: Decrypt")
            ax.bar(x+w, fe["fhe_exec_avg"],   width=w, label="SimpleFHE: Exec")
            for i, acc in enumerate(fe["acc_fe"]):
                if not np.isnan(acc):
                    y = fe[["fe_exec_avg","fe_decrypt_avg","fhe_exec_avg"]].iloc[i].max()
                    ax.text(i, y*1.05, f"{acc*100:.1f}%", ha="center", va="bottom", fontsize=8)
            ax.set_xticks(x)
            ax.set_xticklabels([shorten_label(q) for q in fe["query"]], rotation=45, ha="right")
            ax.set_xlabel("Query")
            ax.set_ylabel("Time (s, log scale)")
            ax.set_title(f"{ds} — Paillier-FE vs SimpleFHE")
            ax.legend(title="Method", loc="upper left")
            plt.tight_layout()
            fig.subplots_adjust(top=0.88)
            fig.savefig(os.path.join(FIG_DIR, f"{ds.replace('.csv','')}_FE_vs_SFHE.png"))

    # ── SSE plots ──────────────────────────────────────────────────────────────
    for ds, grp in df.groupby("dataset"):
        ss = grp[grp["mode"] == "SSE"]
        if not ss.empty:
            x, w = np.arange(len(ss)), 0.4
            fig, ax = plt.subplots(figsize=(10,4))
            ax.set_yscale("log")
            ax.grid(True, axis="y", which="major", linestyle="--", linewidth=0.7, alpha=0.7)
            ax.bar(x-w/2, ss["sse_exec_avg"], width=w, label="SSE: Exec")
            ax.bar(x+w/2, ss["fhe_exec_avg"], width=w, label="SimpleFHE: Exec")
            for i, acc in enumerate(ss["acc_sse"]):
                if not np.isnan(acc):
                    y = max(ss["sse_exec_avg"].iloc[i], ss["fhe_exec_avg"].iloc[i])
                    ax.text(i, y*1.05, f"{acc*100:.1f}%", ha="center", va="bottom", fontsize=8)
            ax.set_xticks(x)
            ax.set_xticklabels([shorten_label(q) for q in ss["query"]], rotation=45, ha="right")
            ax.set_xlabel("Query")
            ax.set_ylabel("Time (s, log scale)")
            ax.set_title(f"{ds} — SSE vs SimpleFHE WHERE")
            ax.legend(title="Method", loc="upper left")
            plt.tight_layout()
            fig.subplots_adjust(top=0.88)
            fig.savefig(os.path.join(FIG_DIR, f"{ds.replace('.csv','')}_SSE_vs_SFHE.png"))

    return df

if __name__ == "__main__":
    # Uncomment to do a quick one-shot comparison:
    # compare_systems()

    # Run full benchmark & plotting
    results = run_metrics()
    # Optionally save results CSV:
    # results.to_csv("metrics_results.csv", index=False)
    # logger("Saved metrics to metrics_results.csv")
