# main_ui.py

import hashlib
import os
import threading
import csv
import re
import json
import sys
import contextlib
import shutil
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from codes import authority, ServerFE, ClientFE

# ─── Delete codes/__pycache__ on startup ───────────────────────────────────
CACHE_DIR = os.path.join(os.path.dirname(__file__), "codes", "__pycache__")
if os.path.isdir(CACHE_DIR):
    shutil.rmtree(CACHE_DIR)

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
    old, sys.stdout = sys.stdout, TextRedirector(widget)
    try:
        yield
    finally:
        sys.stdout = old

class AuthorityWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Authority")
        self.geometry("450x300")
        self.log = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Segoe UI",9))
        self.log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        threading.Thread(target=self._run, daemon=True).start()

    def logger(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.insert(tk.END, f"[{ts}] [TA] {msg}\n")
        self.log.see(tk.END)

    def _run(self):
        with redirected_stdout(self.log):
            authority.start_authority_server(logger=self.logger)

class ServerWindow(tk.Toplevel):
    def __init__(self, master, client):
        super().__init__(master)
        self.title("Encrypted-DB Server")
        self.geometry("450x300")
        self.client = client

        self.upload_btn = tk.Button(self, text="Upload Data", command=self.choose_csv)
        self.upload_btn.pack(pady=(10,0))

        self.log = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Segoe UI",9))
        self.log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def choose_csv(self):
        path = filedialog.askopenfilename(
            initialdir=os.getcwd()+"/data",
            filetypes=[("CSV","*.csv")]
        )
        if not path:
            return

        # disable the button once data is selected
        self.upload_btn.config(state=tk.DISABLED)

        self.client.prepare(path)
        self.client.show_loading()

        def wrap(msg):
            ts = datetime.now().strftime("%H:%M:%S")
            self.log.insert(tk.END, f"[{ts}] [Server] {msg}\n")
            self.log.see(tk.END)
            if "listening on localhost:9000" in msg.lower():
                self.client.on_server_ready()

        threading.Thread(
            target=lambda: ServerFE.start_server(path, logger=wrap),
            daemon=True
        ).start()

class ClientWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Data Client")
        self.geometry("900x600")
        self.minsize(800, 500)

        self.public_key    = None
        self.rsa_pub       = None
        self.headers       = []
        self.display_names = {}
        self.numeric_cols  = []
        self._ov           = None

        # ── Box‐view vars ───────────────────────────────────────
        self.query_var     = tk.StringVar()
        self.fkey_var      = tk.StringVar()
        self.lam_var       = tk.StringVar()
        self.mu_var        = tk.StringVar()
        self.cipher_var    = tk.StringVar()
        self.result_var    = tk.StringVar()

        # ── Top controls ────────────────────────────────────────
        top = tk.Frame(self)
        self.mode_var = tk.StringVar(value="console")
        tk.Radiobutton(top, text="Console View", variable=self.mode_var,
                       value="console", command=self._switch).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(top, text="Box View", variable=self.mode_var,
                       value="boxes", command=self._switch).pack(side=tk.LEFT, padx=5)

        tk.Label(top, text="Operation:", font=("Segoe UI",10)).pack(side=tk.LEFT, padx=(20,0))
        self.op_var = tk.StringVar(value="SUM")
        self.op_menu = tk.OptionMenu(top, self.op_var, "SUM","COUNT","AVG", command=self._rebuild_columns)
        self.op_menu.pack(side=tk.LEFT, padx=5)

        tk.Label(top, text="Column:", font=("Segoe UI",10)).pack(side=tk.LEFT, padx=(20,0))
        self.col_frame = tk.Frame(top); self.col_frame.pack(side=tk.LEFT, padx=5)
        self.col_var   = tk.StringVar(value="*")
        self._build_col_menu(["*"])

        tk.Label(top, text="Filter:", font=("Segoe UI",10)).pack(side=tk.LEFT, padx=(20,0))
        self.where_entry = tk.Entry(top); self.where_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        self.send_btn = tk.Button(top, text="Send", state="disabled", command=self._send_async)
        self.send_btn.pack(side=tk.RIGHT)
        top.pack(fill=tk.X, pady=(10,5), padx=10)

        # ── Console View ─────────────────────────────────────────
        self.console_frame = tk.Frame(self)
        self.console = scrolledtext.ScrolledText(self.console_frame, wrap=tk.WORD, font=("Segoe UI",9))
        self.console.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.console_frame.pack(fill=tk.BOTH, expand=True)

        # ── Box View ────────────────────────────────────────────
        self.box_frame = tk.Frame(self)
        for title,var,r,c,cs in [
            ("Query Sent",       self.query_var,   0,0,1),
            ("Function Key",     self.fkey_var,    0,1,1),
            ("Key λ (λ)",        self.lam_var,     1,0,1),
            ("Key μ (μ)",        self.mu_var,      1,1,1),
            ("Server Cipher",    self.cipher_var,  2,0,2),
            ("Decrypted Result", self.result_var,  3,0,2),
        ]:
            lf = tk.LabelFrame(self.box_frame, text=title,
                               font=("Segoe UI",10,"bold"),
                               bg="#f5f5f5", bd=1, relief="solid",
                               labelanchor="n")
            lf.grid(row=r, column=c, columnspan=cs,
                    sticky="nsew", padx=5, pady=5)
            lf.grid_columnconfigure(0, weight=1)
            tk.Label(lf, textvariable=var, bg="#ffffff",
                     anchor="nw", justify="left",
                     wraplength=(300 if cs==1 else 650),
                     font=("Segoe UI",9), padx=5, pady=5).pack(fill=tk.BOTH, expand=True)

        # new: Available Columns box
        cols_lf = tk.LabelFrame(self.box_frame, text="Available Columns",
                                font=("Segoe UI",10,"bold"),
                                bg="#f5f5f5", bd=1, relief="solid",
                                labelanchor="n")
        cols_lf.grid(row=0, column=2, rowspan=4, sticky="nsew", padx=5, pady=5)
        cols_lf.grid_columnconfigure(0, weight=1)
        self.cols_label = tk.Label(cols_lf, text="", bg="#ffffff",
                                   anchor="nw", justify="left",
                                   font=("Segoe UI",9), padx=5, pady=5)
        self.cols_label.pack(fill=tk.BOTH, expand=True)

        for c in (0,1,2): self.box_frame.grid_columnconfigure(c, weight=1)
        for r in (2,3):   self.box_frame.grid_rowconfigure(r, weight=1)

        self.box_frame.pack_forget()
        self._set_controls_state("disabled")

    def _build_col_menu(self, options):
        if not options:
            options = [""]
        for w in self.col_frame.winfo_children():
            w.destroy()
        default, rest = options[0], options[1:]
        self.col_menu = tk.OptionMenu(self.col_frame, self.col_var, default, *rest)
        self.col_menu.pack()
        self.col_var.set(default)

    def _set_controls_state(self, s):
        self.op_menu.config(state=s)
        self.col_menu.config(state=s)
        self.send_btn.config(state=s)

    def _switch(self):
        if self.mode_var.get() == "console":
            self.box_frame.pack_forget()
            self.console_frame.pack(fill=tk.BOTH, expand=True)
        else:
            self.console_frame.pack_forget()
            self.box_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))

    def _rebuild_columns(self, *_):
        op = self.op_var.get()
        if op == "COUNT":
            opts = ["*"] + self.headers
        elif op in ("SUM", "AVG"):
            # original behavior: only numeric columns
            opts = self.numeric_cols or []
        else:
            opts = []
        if not opts:
            opts = [""]  # avoid empty list
        self._build_col_menu(opts)

    def prepare(self, path):
        with open(path, newline="", encoding="utf-8") as f:
            rdr = csv.reader(f)
            header = next(rdr)
            header[0] = header[0].lstrip('\ufeff')
            rows = [r for r in rdr if any(cell.strip() for cell in r)]
        self.headers = header
        self.display_names = {c: c.replace("_"," ").title() for c in header}

        self.numeric_cols = [
            col for i,col in enumerate(header)
            if all(re.match(r"^-?\d+(\.\d+)?$", r[i].strip()) for r in rows if r[i].strip())
        ]

        # update Available Columns display
        friendly = [self.display_names[c] for c in self.headers]
        self.cols_label.config(text="\n".join(friendly))

        self._rebuild_columns()

        try:
            self.public_key = ClientFE.load_public_key()
            self.rsa_pub    = ClientFE.load_ta_rsa_pub()
        except Exception as e:
            messagebox.showerror("Key Load Error", str(e))

    def on_server_ready(self):
        self.hide_loading()
        self._set_controls_state("normal")

    def show_loading(self):
        if getattr(self, "_ov", None):
            return
        ov = tk.Toplevel(self)
        ov.overrideredirect(True)
        ov.attributes("-alpha", 0.4)
        ov.configure(bg="gray")
        x, y = self.winfo_rootx(), self.winfo_rooty()
        w, h = self.winfo_width(), self.winfo_height()
        ov.geometry(f"{w}x{h}+{x}+{y}")
        tk.Label(ov, text="Loading…", font=("Segoe UI",12,"bold"),
                 bg="gray").place(relx=0.5, rely=0.5, anchor="center")
        self._ov = ov

    def hide_loading(self):
        if getattr(self, "_ov", None):
            self._ov.destroy()
            self._ov = None

    def _log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{ts}] [Client] {msg}\n")
        self.console.see(tk.END)

    def _send_async(self):
        threading.Thread(target=self._send, daemon=True).start()

    def _send(self):
        import re
        op, col = self.op_var.get(), self.col_var.get()

        # build SELECT
        if op == "COUNT" and col == "*":
            q = "SELECT COUNT(*) FROM data;"
        else:
            if col == "*" or re.match(r"^\w+$", col):
                col_expr = col
            else:
                col_expr = f'"{col}"'
            q = f"SELECT {op}({col_expr}) FROM data;"

        # optional WHERE
        filt = self.where_entry.get().strip()
        if filt:
            q = q.rstrip(";") + f" WHERE {filt};"

        # validate
        try:
            ClientFE.validate_select(q)
        except ValueError as e:
            messagebox.showerror("Invalid Query", str(e))
            return

        self._log(f"→ Server: {q}")
        self.query_var.set(q)

        # get FKEY
        h = hashlib.sha256(q.encode()).hexdigest()
        self._log(f"↔ TA: GET_FKEY AGG {h[:8]}…")
        raw = ClientFE.get_fkey(h)
        self._log(f"← TA token: {raw}")
        self.fkey_var.set(raw)

        fk = ClientFE.verify_fkey(raw, self.rsa_pub, h)
        if not fk:
            self._log("❌ invalid FKEY; SSE fallback")
            self.lam_var.set("–")
            self.mu_var.set("–")
        else:
            lam, mu = fk
            self._log(f"✔ FKEY ok: λ={lam}, μ={mu}")
            self.lam_var.set(str(lam))
            self.mu_var.set(str(mu))

        resp = ClientFE.send_query(raw, q)
        self._log(f"← Server response ({len(resp)} bytes)")

        try:
            j = json.loads(resp)
        except:
            self.cipher_var.set(resp)
            self.result_var.set("ERROR parsing response")
            return

        mode = j.get("mode")

        if mode == "FE":
            self.cipher_var.set(str(j.get("cipher", j.get("sum", ""))))
            out = ClientFE.handle_response(resp, fk, self.public_key)
            self.result_var.set(out)
            self._log(out)

        elif mode == "SSE_TABLE":
            out = ClientFE.handle_response(
                resp,
                fk or (None, None),
                self.public_key,
                op=op,
                col=col,
                where=self.where_entry.get().strip() or None
            )
            self.cipher_var.set("")  # no ciphertext box
            self.result_var.set(out)
            self._log(out)

        else:
            self._log(f"⚠ Unknown response mode: {mode}")

def main():
    root = tk.Tk()
    root.withdraw()

    # on exit, delete __pycache__ again
    def on_close():
        if os.path.isdir(CACHE_DIR):
            shutil.rmtree(CACHE_DIR)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)

    AuthorityWindow(root)
    client = ClientWindow(root)
    ServerWindow(root, client)
    root.mainloop()

if __name__ == "__main__":
    main()
