# ClientFE.py
import socket, sys, hashlib, sqlparse, json
from fe_scheme import decrypt

def load_public_key():
    with open("public_key.txt") as f:
        n, g = map(int, f.read().split())
    return (n, g)

def load_ta_rsa_pub():
    with open("ta_rsa_pub.txt") as f:
        N, e = map(int, f.read().split())
    return (N, e)

def get_fkey():
    with socket.socket() as s:
        s.connect(("localhost",8000))
        s.sendall(b"GET_FKEY AGG")
        return s.recv(4096).decode().strip()

def verify_fkey(token, rsa_pub):
    if "|" not in token:
        return None
    data, sig = token.split("|",1)
    try:
        sig = int(sig)
    except:
        return None
    N, e = rsa_pub
    h = int(hashlib.sha256(data.encode()).hexdigest(),16)%N
    if pow(sig,e,N)!=h or "FKEY:AGG" not in data:
        return None
    parts = dict(p.split(":",1) for p in data.split(";") if ":" in p)
    return (int(parts["lam"]), int(parts["mu"]))

def send_query(fkey, sql):
    msg = "QUERY\n"+fkey+"\n"+sql
    with socket.socket() as s:
        s.connect(("localhost",9000))
        s.sendall(msg.encode())
        return s.recv(65536).decode()

def validate_select(q):
    parsed = sqlparse.parse(q)
    if not parsed or parsed[0].get_type()!="SELECT":
        raise ValueError("Only SELECT allowed.")

def handle_response(resp, fkey, pk):
    try:
        obj = json.loads(resp)
    except:
        print("[Client] Bad response:", resp)
        return

    mode = obj.get("mode")
    if mode=="FE":
        fn = obj["fn"]
        if fn=="AVG":
            s = decrypt(int(obj["sum"]), fkey, pk)
            c = obj["count"]
            print(f"AVG = {s}/{c} = {s/c:.2f}")
        else:
            cipher = int(obj["cipher"])
            val = decrypt(cipher, fkey, pk)
            print(f"{fn} = {val}")

    elif mode=="SSE":
        cols = obj["columns"]
        nums = obj["numeric_cols"]
        rows = obj["results"]
        print("[Client] SSE‐fallback results:")
        print("\t".join(cols))
        for r in rows:
            out = []
            for c,cell in zip(cols,r):
                if c in nums:
                    out.append(str(decrypt(int(cell), fkey, pk)))
                else:
                    out.append(str(cell))
            print("\t".join(out))

    else:
        print("[Client] Error or unknown mode:", obj)

def main():
    print("[Client] Starting…")
    public_key = load_public_key()
    rsa_pub    = load_ta_rsa_pub()
    fkey_full  = get_fkey()
    fkey       = verify_fkey(fkey_full, rsa_pub)
    if fkey is None:
        print("Failed to verify FE key."); sys.exit(1)

    while True:
        try:
            q = input("SQL> ").strip()
            if not q: 
                continue
            try:
                validate_select(q)
            except ValueError as e:
                print(e); continue
            resp = send_query(fkey_full, q)
            handle_response(resp, fkey, public_key)
        except KeyboardInterrupt:
            print("\nGoodbye.")
            sys.exit(0)

if __name__=="__main__":
    main()
