import hashlib, os, threading, csv, re, tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from codes import authority, ServerFE, ClientFE
import contextlib, sys, io

class TextRedirector:
    def __init__(self, widget):
        self.widget = widget
    def write(self, s):
        self.widget.insert(tk.END, s)
        self.widget.see(tk.END)
    def flush(self):
        pass

@contextlib.contextmanager
def redirected_stdout(widget):
    old_stdout = sys.stdout
    sys.stdout = TextRedirector(widget)
    try:
        yield
    finally:
        sys.stdout = old_stdout

class AuthorityWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Authority")
        tk.Label(self, text="(starting…)").pack()
        self.log = scrolledtext.ScrolledText(self, height=12)
        self.log.pack(fill=tk.BOTH, expand=True)
        threading.Thread(target=self._run, daemon=True).start()

    def logger(self, s):
        self.log.insert(tk.END, s + "\n")
        self.log.see(tk.END)

    def _run(self):
        authority.start_authority_server(logger=self.logger)

class ServerWindow(tk.Toplevel):
    def __init__(self, master, on_ready):
        super().__init__(master)
        self.on_ready = on_ready
        self.title("Encrypted DB Server")
        tk.Button(self, text="Choose CSV…", command=self.choose).pack(pady=5)
        self.log = scrolledtext.ScrolledText(self, height=12)
        self.log.pack(fill=tk.BOTH, expand=True)

    def logger(self, s):
        self.log.insert(tk.END, s + "\n")
        self.log.see(tk.END)

    def choose(self):
        p = filedialog.askopenfilename(
            initialdir=os.path.join(os.getcwd(), "data"),
            filetypes=[("CSV","*.csv")]
        )
        if not p: 
            return
        threading.Thread(target=lambda: self._serve(p), daemon=True).start()

    def _serve(self, path):
        self.on_ready(path)
        ServerFE.start_server(path, logger=self.logger)

class ClientWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Client")
        self.public_key = None
        self.rsa_pub    = None
        self.numeric_cols = []

        frm = tk.Frame(self)
        tk.Label(frm, text="Op:").pack(side=tk.LEFT)
        self.op_var = tk.StringVar(value="SUM")
        tk.OptionMenu(frm, self.op_var, "SUM","COUNT","AVG",
                      command=self._rebuild).pack(side=tk.LEFT)
        tk.Label(frm, text="Col:").pack(side=tk.LEFT, padx=5)
        self.col_var = tk.StringVar(value="*")
        self.col_menu = tk.OptionMenu(frm, self.col_var, "*")
        self.col_menu.pack(side=tk.LEFT)
        self.send_btn = tk.Button(frm, text="Send", state=tk.DISABLED,
                                  command=self._send_async)
        self.send_btn.pack(side=tk.LEFT, padx=5)
        frm.pack(pady=5, padx=5, fill=tk.X)

        self.log = scrolledtext.ScrolledText(self, height=12)
        self.log.pack(fill=tk.BOTH, expand=True)

    def _rebuild(self, *_):
        op = self.op_var.get()
        cols = ["*"] if op=="COUNT" else self.numeric_cols
        m = self.col_menu["menu"]
        m.delete(0, "end")
        for c in cols:
            m.add_command(label=c, command=lambda v=c: self.col_var.set(v))
        if cols: 
            self.col_var.set(cols[0])

    def enable(self, csv_path):
        with open(csv_path, newline="", encoding="utf-8") as f:
            rdr = csv.reader(f)
            hdr = next(rdr); hdr[0]=hdr[0].lstrip('\ufeff')
            rows = [r for r in rdr if any(r)]
        def is_num(s):
            try: float(s); return True
            except: return False
        self.numeric_cols = [
            hdr[i] for i in range(len(hdr))
            if all(is_num(r[i].strip().strip('"\'')) for r in rows if r[i].strip())
        ]

        try:
            self.public_key = ClientFE.load_public_key()
            self.rsa_pub    = ClientFE.load_ta_rsa_pub()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        self._rebuild()
        self.send_btn.config(state=tk.NORMAL)

    def _send_async(self):
        op  = self.op_var.get()
        col = self.col_var.get()
        if op=="COUNT" and col=="*":
            q = "SELECT COUNT(*) FROM data;"
        else:
            cs = col if re.match(r"^\w+$", col) else f'"{col}"'
            q = f"SELECT {op}({cs}) FROM data;"
        threading.Thread(target=self._send, args=(q,), daemon=True).start()

    def _send(self, q):
        qhash = hashlib.sha256(q.encode()).hexdigest()
        self.log.insert(tk.END, f"[Client] ↔ TA: GET_FKEY AGG {qhash[:8]}…\n")
        raw = ClientFE.get_fkey(qhash)
        self.log.insert(tk.END, f"[Client] ← TA token:\n    {raw}\n")
        fk = ClientFE.verify_fkey(raw, self.rsa_pub, qhash)
        if fk is None:
            self.log.insert(tk.END, "[Client] ❌ invalid FKEY\n\n")
            return
        lam, mu = fk
        self.log.insert(tk.END, f"[Client] ✔ FKEY ok: lam={lam}, mu={mu}\n")
        self.log.insert(tk.END, f"[Client] → Server: {q}\n")
        resp = ClientFE.send_query(raw, q)
        self.log.insert(tk.END, f"[Client] ← Server raw response:\n    {resp}\n")
        out = ClientFE.handle_response(resp, fk, self.public_key)
        self.log.insert(tk.END, f"> {q}\n{out}\n\n")
        self.log.see(tk.END)

def main():
    root = tk.Tk()
    root.withdraw()
    AuthorityWindow(root)
    cw = ClientWindow(root)
    ServerWindow(root, on_ready=cw.enable)
    root.mainloop()

if __name__=="__main__":
    main()
