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

# ── simple-fhe imports ────────────────────────────────────────────────────────
from simplefhe import (
    initialize,
    generate_keypair,
    set_public_key,
    set_private_key,
    set_relin_keys,
    encrypt,
    decrypt
)  # simple-fhe usage :contentReference[oaicite:0]{index=0}

# ── Configuration ──────────────────────────────────────────────────────────────

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
FIG_DIR  = os.path.join(os.path.dirname(__file__), "figures")
os.makedirs(FIG_DIR, exist_ok=True)

N_RUNS = 5

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
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

# ── Short label helper (fixed f-string) ───────────────────────────────────────

def shorten_label(q: str) -> str:
    parts = q.split("WHERE", 1)
    sel  = parts[0].strip()
    cond = parts[1].strip() if len(parts) == 2 else None

    m = re.match(
        r'SELECT\s+(SUM|COUNT|AVG)\(\s*(\*|"?([\w\s\.]+)"?)\)',
        sel, re.IGNORECASE
    )
    if not m:
        return q

    op       = m.group(1).upper()
    col_expr = m.group(2)

    if op == "COUNT" and col_expr.strip() == "*":
        base = "COUNT"
    else:
        # strip any quotes, then abbreviate
        col    = col_expr.strip().strip('"')
        words  = re.findall(r"[A-Za-z]+", col)
        abbr   = "".join(w[0] for w in words if len(w) > 2) or col[:3]
        base   = f"{op}({abbr})"

    if cond:
        cm = re.match(
            r'^\s*"?([\w\s\.]+)"?\s*(>=|<=|!=|<>|=|<|>)\s*(.+)$',
            cond
        )
        if cm:
            fld  = cm.group(1)
            sym  = cm.group(2).replace("<>", "!=")
            lit  = cm.group(3).strip().strip("'\"")
            words2 = re.findall(r"[A-Za-z]+", fld)
            fabbr  = "".join(w[0] for w in words2 if len(w) > 2) or fld[:3]
            return f"{base}|{fabbr}{sym}{lit}"

    return base

# ── SQL parsing for WHERE ──────────────────────────────────────────────────────

def parse_condition(cond: str):
    pat = r'^\s*"?([\w\s\.]+)"?\s*(>=|<=|!=|<>|=|<|>)\s*(.+)$'
    m = re.match(pat, cond)
    if not m:
        raise ValueError(f"Cannot parse WHERE: {cond!r}")
    fld = m.group(1).strip()
    sym = m.group(2).replace("<>", "!=")
    lit = m.group(3).strip().strip("'\"")
    return fld, sym, float(lit) if re.fullmatch(r"[\d\.]+", lit) else lit

# ── SimpleFHE microservice ─────────────────────────────────────────────────────

_simplefhe_thread   = None
_simplefhe_shutdown = None

def start_simplefhe_server_async(df: pd.DataFrame, port: int, logger):
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
                        conn.sendall(b'{"error":"bad format"}')
                        continue
                    sql = lines[1]
                    res = _simplefhe_handle_query(sql, df)
                    conn.sendall(json.dumps({"result": res}).encode())

    _simplefhe_thread = threading.Thread(target=serve, daemon=True)
    _simplefhe_thread.start()

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
    global _simplefhe_thread, _simplefhe_shutdown
    if _simplefhe_shutdown:
        _simplefhe_shutdown.set()
    if _simplefhe_thread:
        _simplefhe_thread.join()
    _simplefhe_thread   = None
    _simplefhe_shutdown = None

def send_simplefhe_query(sql: str, port: int) -> float:
    msg = f"QUERY\n{sql}"
    with socket.socket() as s:
        s.connect(("localhost", port))
        s.sendall(msg.encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    obj = json.loads(data.decode())
    if "result" in obj:
        return float(obj["result"])
    raise RuntimeError(f"SimpleFHE error: {obj}")

def _simplefhe_handle_query(sql: str, df: pd.DataFrame) -> float:
    q     = sql.strip().rstrip(";")
    parts = q.split("WHERE", 1)
    sel   = parts[0].strip()
    cond  = parts[1].strip() if len(parts)==2 else None

    # build the row mask as before
    if cond:
        fld, sym, lit = parse_condition(cond)
        col = df[fld].astype(float)
        mask = col.apply(lambda x: eval(f"x {sym} {lit}"))
    else:
        mask = pd.Series(True, index=df.index)

    # COUNT(*) path unchanged …
    if re.match(r"SELECT\s+COUNT\s*\(\s*\*\s*\)\s+FROM\s+data",
                sel, re.IGNORECASE):
        csum = None
        for _ in mask[mask].index:
            e = encrypt(1)
            csum = e if csum is None else (csum + e)
        return 0.0 if csum is None else float(decrypt(csum))

    # SUM/AVG path — **only this block changes**:
    m = re.match(r'SELECT\s+(SUM|AVG)\(\s*"?([\w\s\.]+)"?\)',
                 sel, re.IGNORECASE)
    if not m:
        raise ValueError(f"Unrecognized query for SimpleFHE: {sql!r}")
    op, colname = m.group(1).upper(), m.group(2)

    # ← HERE: drop NaNs before encrypting
    vals = df.loc[mask, colname].astype(float).dropna().tolist()

    csum = None
    for v in vals:
        e = encrypt(int(v))     # now guaranteed v is a real number
        csum = e if csum is None else (csum + e)
    total = 0.0 if csum is None else float(decrypt(csum))

    if op == "SUM":
        return total
    cnt = len(vals)
    return (total / cnt) if cnt else 0.0

# ── Main runner ────────────────────────────────────────────────────────────────

def run_metrics():
    records = []

    # existing FE/SSE imports
    from codes.authority import start_authority_async, stop_authority
    from codes.ServerFE    import start_server_async, stop_server
    from codes.ClientFE    import (
        get_fkey, send_query, verify_fkey,
        load_ta_rsa_pub, load_public_key as fe_load_pub,
        get_sse_key
    )
    from codes.fe_scheme   import decrypt as fe_decrypt

    for idx, (fname, queries) in enumerate(DATASETS.items()):
        path = os.path.join(DATA_DIR, fname)
        logger(f"\n=== Dataset: {fname} ===")

        df_full    = pd.read_csv(path)
        df_numeric = df_full.select_dtypes(include="number")

        # init SimpleFHE context & keypair per-dataset
        initialize("int")
        pub, priv, relin = generate_keypair()
        set_public_key(pub)
        set_relin_keys(relin)
        set_private_key(priv)

        # start SimpleFHE server on a new port
        SF_PORT = 10000 + idx
        start_simplefhe_server_async(df_numeric, SF_PORT, logger)

        # start existing Paillier FE authority & server
        start_authority_async(logger)
        start_server_async(path, logger)

        rsa_pub = load_ta_rsa_pub()
        fe_pub  = fe_load_pub()

        for q in queries:
            h = hashlib.sha256(q.encode()).hexdigest()

            fe_key_t, fe_q_rt = [], []
            fe_exec, fe_dec, fe_val = [], [], []
            sse_key_t, sse_q_rt = [], []
            sse_exec, sse_val = [], []
            fhe_rt, true_val  = [], []

            parts = q.split("WHERE", 1)
            cond_clause = parts[1].strip() if len(parts)==2 else None

            for run_idx in range(N_RUNS):
                # FE key fetch
                t0 = time.time()
                token = get_fkey(h)
                t1 = time.time()
                fe_key_t.append(t1 - t0)

                # FE vs SSE request
                t2 = time.time()
                resp_json = send_query(token, q)
                t3 = time.time()
                rtt = t3 - t2

                obj = json.loads(resp_json)
                if obj.get("mode") == "FE":
                    fe_q_rt.append(rtt)
                    fn = obj["fn"]
                    if fn in ("SUM","COUNT"):
                        ciph = int(obj["cipher"])
                        dt0  = time.time()
                        val  = fe_decrypt(ciph,
                                         verify_fkey(token, rsa_pub, h),
                                         fe_pub)
                        dt1  = time.time()
                        fe_dec.append(dt1 - dt0)
                    else:
                        s, c = int(obj["sum"]), obj["count"]
                        dt0   = time.time()
                        sd    = fe_decrypt(s,
                                           verify_fkey(token, rsa_pub, h),
                                           fe_pub)
                        dt1   = time.time()
                        fe_dec.append(dt1 - dt0)
                        val   = sd / c if c else 0.0

                    fe_exec.append(rtt - fe_dec[-1])
                    fe_val.append(val)

                else:
                    sse_q_rt.append(rtt)
                    t4 = time.time()
                    sk = get_sse_key()
                    t5 = time.time()
                    sse_key_t.append(t5 - t4)

                    cols, rows = obj["columns"], obj["rows"]
                    decs = [{c: (int(v) ^ sk) for c,v in zip(cols,row)}
                            for row in rows]
                    if cond_clause:
                        fld,sym,lit = parse_condition(cond_clause)
                        decs = [r for r in decs
                                if eval(f"{r[fld]}{sym}{lit}")]
                    if q.upper().startswith("SELECT COUNT"):
                        val = len(decs)
                    else:
                        m2 = re.match(
                            r'SELECT\s+(SUM|AVG)\(\s*"?([\w\s\.]+)"?\s*\)',
                            q, re.IGNORECASE)
                        op, col = m2.group(1).upper(), m2.group(2)
                        if op=="SUM":
                            val = sum(r[col] for r in decs)
                        else:
                            cnt = len(decs)
                            val = (sum(r[col] for r in decs)/cnt
                                   if cnt else 0.0)

                    t6 = time.time()
                    sse_exec.append(t6 - t5)
                    sse_val.append(val)

                # SimpleFHE baseline
                tf0 = time.time()
                tv  = send_simplefhe_query(q, SF_PORT)
                tf1 = time.time()
                fhe_rt.append(tf1 - tf0)
                true_val.append(tv)

                if run_idx==0 and cond_clause:
                    logger(f"[DEBUG] SimpleFHE baseline for `{q}`: {tv}")

            # compute averages & record
            tvm    = np.mean(true_val)
            fe_k   = np.mean(fe_key_t)   if fe_key_t else np.nan
            fe_q   = np.mean(fe_q_rt)    if fe_q_rt else np.nan
            fe_e   = np.mean(fe_exec)    if fe_exec else np.nan
            fe_d   = np.mean(fe_dec)     if fe_dec else np.nan
            fe_v   = np.mean(fe_val)     if fe_val else np.nan
            err_fe = abs(fe_v - tvm)     if fe_val else np.nan
            acc_fe = (1 - err_fe/tvm)    if (tvm and fe_val) else np.nan

            sse_k   = np.mean(sse_key_t) if sse_key_t else np.nan
            sse_q   = np.mean(sse_q_rt)  if sse_q_rt else np.nan
            sse_e   = np.mean(sse_exec)  if sse_exec else np.nan
            sse_v   = np.mean(sse_val)   if sse_val else np.nan
            err_sse = abs(sse_v - tvm)    if sse_val else np.nan
            acc_sse = (1 - err_sse/tvm)   if (tvm and sse_val) else np.nan

            fhe_e = np.mean(fhe_rt)

            mode = "SSE" if sse_val else "FE"
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
                "acc_sse":           acc_sse,
            })
            logger(
                f"Q={shorten_label(q)!r} → mode={mode}, true={tvm:.2f}, "
                f"err_FE={err_fe:.2e}, err_SSE={err_sse:.2e}"
            )

        # tear down everything
        stop_server()
        stop_authority()
        stop_simplefhe_server()

    df = pd.DataFrame(records)

    # ── Plotting with nicer grid and unclipped annotations ───────────────────
    for ds, grp in df.groupby("dataset"):
        # --- Paillier-FE vs SimpleFHE ---
        fe = grp[grp["mode"]=="FE"]
        if not fe.empty:
            x, w = np.arange(len(fe)), 0.25
            fig, ax = plt.subplots(figsize=(10,4))
            # log y-axis
            ax.set_yscale("log")
            # only major grid, light and dashed
            ax.grid(True, axis="y", which="major", linestyle="--", linewidth=0.7, alpha=0.7)

            # bars
            ax.bar(x - w, fe["fe_exec_avg"],    width=w, label="Paillier-FE: Execution")
            ax.bar(x    , fe["fe_decrypt_avg"], width=w, label="Paillier-FE: Decryption")
            ax.bar(x + w, fe["fhe_exec_avg"],   width=w, label="SimpleFHE: Execution")

            # annotations just above each tallest bar
            for i, acc in enumerate(fe["acc_fe"]):
                if not np.isnan(acc):
                    y = fe[["fe_exec_avg","fe_decrypt_avg","fhe_exec_avg"]].iloc[i].max()
                    ax.text(i, y * 1.05, f"Acc: {acc*100:.1f}%",
                            ha="center", va="bottom", fontsize=8)

            # labels, legend, title
            ax.set_xticks(x)
            ax.set_xticklabels([shorten_label(q) for q in fe["query"]],
                               rotation=45, ha="right")
            ax.set_xlabel("Query")
            ax.set_ylabel("Time (s, log scale)")
            ax.set_title(f"{ds} — Paillier-FE vs SimpleFHE Execution Times")
            ax.legend(title="Method", loc="upper left")

            # ensure annotations & title aren’t cut off
            plt.tight_layout()
            fig.subplots_adjust(top=0.88)

            fig.savefig(os.path.join(FIG_DIR,
                                     f"{ds.replace('.csv','')}_FE_vs_SFHE.png"))
            #plt.show()

        # --- SSE vs SimpleFHE for WHERE clauses ---
        ss = grp[grp["mode"]=="SSE"]
        if not ss.empty:
            x, w = np.arange(len(ss)), 0.4
            fig, ax = plt.subplots(figsize=(10,4))
            ax.set_yscale("log")
            ax.grid(True, axis="y", which="major", linestyle="--", linewidth=0.7, alpha=0.7)

            ax.bar(x - w/2, ss["sse_exec_avg"], width=w, label="SSE: Execution")
            ax.bar(x + w/2, ss["fhe_exec_avg"], width=w, label="SimpleFHE: Execution")

            for i, acc in enumerate(ss["acc_sse"]):
                if not np.isnan(acc):
                    y = max(ss["sse_exec_avg"].iloc[i],
                            ss["fhe_exec_avg"].iloc[i])
                    ax.text(i, y * 1.05, f"Acc: {acc*100:.1f}%",
                            ha="center", va="bottom", fontsize=8)

            ax.set_xticks(x)
            ax.set_xticklabels([shorten_label(q) for q in ss["query"]],
                               rotation=45, ha="right")
            ax.set_xlabel("Query (abbreviated)")
            ax.set_ylabel("Time (s, log scale)")
            ax.set_title(f"{ds} — SSE vs SimpleFHE WHERE-Clause Execution")
            ax.legend(title="Method", loc="upper left")

            plt.tight_layout()
            fig.subplots_adjust(top=0.88)

            fig.savefig(os.path.join(FIG_DIR,
                                     f"{ds.replace('.csv','')}_SSE_vs_SFHE.png"))
            #plt.show()



    return df

if __name__ == "__main__":
    results = run_metrics()
    #results.to_csv("metrics_results.csv", index=False)
    #logger("Saved metrics to metrics_results.csv")
