import hashlib
import os
import threading
import csv
import re
import json
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from codes import authority, ServerFE, ClientFE
import contextlib
import sys

# ─── Redirect stdout into a Text widget (for Authority) ─────────────────────

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
    old = sys.stdout
    sys.stdout = TextRedirector(widget)
    try:
        yield
    finally:
        sys.stdout = old

# ─── Trusted Authority Window ───────────────────────────────────────────────

class AuthorityWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Authority")
        self.geometry("450x300")
        self.log = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Segoe UI", 9))
        self.log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        threading.Thread(target=self._run, daemon=True).start()

    def logger(self, msg):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def _run(self):
        with redirected_stdout(self.log):
            authority.start_authority_server(logger=self.logger)

# ─── Encrypted-DB Server Window ──────────────────────────────────────────────

class ServerWindow(tk.Toplevel):
    def __init__(self, master, client):
        super().__init__(master)
        self.title("Encrypted-DB Server")
        self.geometry("450x300")
        self.client = client

        tk.Button(self, text="Choose CSV…", command=self.choose_csv).pack(pady=(10,0))
        self.log = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Segoe UI", 9))
        self.log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def logger(self, msg):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def choose_csv(self):
        path = filedialog.askopenfilename(
            initialdir=os.path.join(os.getcwd(), "data"),
            filetypes=[("CSV Files", "*.csv")]
        )
        if not path:
            return
        self.client.prepare(path)
        self.client.show_loading()
        threading.Thread(target=lambda: self._serve(path), daemon=True).start()

    def _serve(self, path):
        def wrap(msg):
            self.logger(msg)
            if "Listening on localhost:9000" in msg:
                self.client.on_server_ready()
        ServerFE.start_server(path, logger=wrap)

# ─── Client Window ───────────────────────────────────────────────────────────

class ClientWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Data Client")
        self.geometry("700x500")
        self.public_key = None
        self.rsa_pub    = None
        self.numeric_cols = []
        self._ov = None

        # Variables for Box View
        self.query_var    = tk.StringVar()
        self.fkey_var     = tk.StringVar()
        self.lam_var      = tk.StringVar()
        self.mu_var       = tk.StringVar()
        self.cipher_var   = tk.StringVar()
        self.result_var   = tk.StringVar()

        # ─── Mode toggle ───────────────────────────────────────
        m = tk.Frame(self)
        self.mode_var = tk.StringVar(value="console")
        tk.Radiobutton(
            m, text="Console View",
            variable=self.mode_var, value="console",
            command=self._switch
        ).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(
            m, text="Box View",
            variable=self.mode_var, value="boxes",
            command=self._switch
        ).pack(side=tk.LEFT, padx=5)
        m.pack(fill=tk.X, pady=(10,5), padx=10)

        # ─── Operation & Column ─────────────────────────────────
        of = tk.Frame(self)
        tk.Label(of, text="Operation:", font=("Segoe UI",10)).pack(side=tk.LEFT)
        self.op_var = tk.StringVar(value="SUM")
        self.op_menu = tk.OptionMenu(
            of, self.op_var, "SUM","COUNT","AVG", command=self._rebuild
        )
        self.op_menu.pack(side=tk.LEFT, padx=5)

        tk.Label(of, text="Column:", font=("Segoe UI",10)).pack(side=tk.LEFT, padx=(20,0))
        self.col_var = tk.StringVar(value="*")
        self.col_menu = tk.OptionMenu(of, self.col_var, "*")
        self.col_menu.pack(side=tk.LEFT, padx=5)

        self.send_btn = tk.Button(of, text="Send", state="disabled", command=self._send_async)
        self.send_btn.pack(side=tk.RIGHT)
        of.pack(fill=tk.X, padx=10, pady=(0,10))

        # ─── Console View ─────────────────────────────────────────
        self.console_frame = tk.Frame(self)
        self.console = scrolledtext.ScrolledText(
            self.console_frame, wrap=tk.WORD, font=("Segoe UI",9)
        )
        self.console.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.console_frame.pack(fill=tk.BOTH, expand=True)

        # ─── Box View ────────────────────────────────────────────
        self.box_frame = tk.Frame(self)
        # two columns of LabelFrames
        # 1st row: Query | Function Key
        self._card(self.box_frame, "Query Sent",    self.query_var, 0,0)
        self._card(self.box_frame, "Function Key",  self.fkey_var,  0,1)
        # 2nd row: λ  | μ
        self._card(self.box_frame, "Key λ (λ)",     self.lam_var,    1,0)
        self._card(self.box_frame, "Key μ (μ)",     self.mu_var,     1,1)
        # 3rd row: Cipher spans 2 cols
        self._card(self.box_frame, "Server Cipher", self.cipher_var,2,0, colspan=2)
        # 4th row: Result spans 2 cols
        self._card(self.box_frame, "Decrypted Result", self.result_var,3,0, colspan=2)

        # grid config
        for c in (0,1):
            self.box_frame.grid_columnconfigure(c, weight=1)
        for r in (2,3):
            self.box_frame.grid_rowconfigure(r, weight=1)

        self.box_frame.pack_forget()
        self._set_state("disabled")

    def _card(self, parent, title, var, row, col, colspan=1):
        bg = "#f5f5f5"
        inner = "#ffffff"
        lf = tk.LabelFrame(
            parent, text=title, font=("Segoe UI",10,"bold"),
            bg=bg, fg="#333333", bd=1, relief="solid", labelanchor="n"
        )
        lf.grid(row=row, column=col, columnspan=colspan,
                sticky="nsew", padx=5, pady=5)
        lf.grid_columnconfigure(0, weight=1)
        lbl = tk.Label(
            lf, textvariable=var, bg=inner, anchor="nw", justify="left",
            wraplength= (650 if colspan==2 else 300),
            font=("Segoe UI",9), bd=1, relief="flat", padx=5, pady=5
        )
        lbl.pack(fill=tk.BOTH, expand=True)

    def _set_state(self, st):
        self.op_menu.config(state=st)
        self.col_menu.config(state=st)
        self.send_btn.config(state=st)

    def _switch(self):
        if self.mode_var.get() == "console":
            self.box_frame.pack_forget()
            self.console_frame.pack(fill=tk.BOTH, expand=True)
        else:
            self.console_frame.pack_forget()
            self.box_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))

    def _rebuild(self, *_):
        opts = ["*"] if self.op_var.get()=="COUNT" else self.numeric_cols
        m = self.col_menu["menu"]; m.delete(0, "end")
        for o in opts:
            m.add_command(label=o, command=lambda v=o: self.col_var.set(v))
        if opts:
            self.col_var.set(opts[0])

    def prepare(self, path):
        # detect numeric cols
        with open(path, newline="", encoding="utf-8") as f:
            rdr = csv.reader(f)
            hdr = next(rdr); hdr[0]=hdr[0].lstrip('\ufeff')
            rows=[r for r in rdr if any(r)]
        self.numeric_cols = [
            hdr[i] for i in range(len(hdr))
            if all(re.match(r"^-?\d+(\.\d+)?$", r[i].strip())
                   for r in rows if r[i].strip())
        ]
        try:
            self.public_key = ClientFE.load_public_key()
            self.rsa_pub    = ClientFE.load_ta_rsa_pub()
        except Exception as e:
            messagebox.showerror("Key Load Error", str(e))
            return
        self._rebuild()

    def on_server_ready(self):
        self.hide_loading()
        self._set_state("normal")

    def show_loading(self):
        if getattr(self, "_ov", None): return
        ov = tk.Toplevel(self); ov.overrideredirect(True)
        ov.attributes("-alpha", 0.4); ov.configure(bg="gray")
        x,y = self.winfo_rootx(), self.winfo_rooty()
        w,h = self.winfo_width(), self.winfo_height()
        ov.geometry(f"{w}x{h}+{x}+{y}")
        tk.Label(ov, text="Loading…", font=("Segoe UI",12,"bold"), bg="gray")\
          .place(relx=0.5, rely=0.5, anchor="center")
        self._ov = ov

    def hide_loading(self):
        if getattr(self, "_ov", None):
            self._ov.destroy()
            self._ov = None

    def _send_async(self):
        threading.Thread(target=self._send, daemon=True).start()

    def _send(self):
        # Build SQL
        op, col = self.op_var.get(), self.col_var.get()
        if op=="COUNT" and col=="*":
            q = "SELECT COUNT(*) FROM data;"
        else:
            col_expr = col if re.match(r'^\w+$', col) else f'"{col}"'
            q = f"SELECT {op}({col_expr}) FROM data;"

        # 1) Query
        self.console.insert(tk.END, f"[Client] → Server: {q}\n")
        self.console.see(tk.END)
        self.query_var.set(q)

        # 2) GET_FKEY
        h = hashlib.sha256(q.encode()).hexdigest()
        self.console.insert(tk.END, f"[Client] ↔ TA: GET_FKEY AGG {h[:8]}…\n")
        raw = ClientFE.get_fkey(h)
        self.console.insert(tk.END, f"[Client] ← TA token: {raw}\n\n")
        self.console.see(tk.END)
        self.fkey_var.set(raw)

        # 3) Verify
        fk = ClientFE.verify_fkey(raw, self.rsa_pub, h)
        if not fk:
            self.console.insert(tk.END, "[Client] ❌ invalid FKEY\n\n")
            self.console.see(tk.END)
            self.lam_var.set("Invalid")
            self.mu_var.set("Invalid")
            return
        lam, mu = fk
        self.console.insert(
            tk.END, f"[Client] ✔ FKEY ok: λ={lam}, μ={mu}\n"
        )
        self.console.see(tk.END)
        self.lam_var.set(str(lam))
        self.mu_var.set(str(mu))

        # 4) Server response
        resp = ClientFE.send_query(raw, q)
        self.console.insert(
            tk.END, f"[Client] ← Server raw response: {resp}\n"
        )
        self.console.see(tk.END)
        try:
            j = json.loads(resp)
            cipher = j["sum"] if j.get("fn")=="AVG" else j.get("cipher", resp)
        except:
            cipher = resp
        self.cipher_var.set(str(cipher))

        # 5) Decrypted result
        out = ClientFE.handle_response(resp, fk, self.public_key)
        self.console.insert(tk.END, f"[Client] Result: {out}\n\n")
        self.console.see(tk.END)
        self.result_var.set(out)

# ─── Main entrypoint ─────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    root.withdraw()
    AuthorityWindow(root)
    client = ClientWindow(root)
    ServerWindow(root, client)
    root.mainloop()

if __name__ == "__main__":
    main()
