import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import http.server
import socketserver
import threading
import json
import os
import socket
import ssl
import shutil
from pathlib import Path
import webbrowser
import subprocess

# ----------  OpenSSL auto-finder  ----------
def find_openssl():
    """Return full path to openssl.exe; raise RuntimeError if not found."""
    for pf in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if not pf:
            continue
        candidate = Path(pf) / "OpenSSL-Win64" / "bin" / "openssl.exe"
        if candidate.is_file():
            return str(candidate)
    winget_default = Path(r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe")
    if winget_default.is_file():
        return str(winget_default)
    portable = Path(__file__).with_name("openssl.exe")
    if portable.is_file():
        return str(portable)
    user = filedialog.askopenfilename(
        title="Locate openssl.exe",
        filetypes=[("EXE", "*.exe"), ("All files", "*.*")]
    )
    if user and Path(user).is_file():
        return user
    raise RuntimeError("OpenSSL not found. Please install it or place openssl.exe beside this script.")


OPENSSL_EXE = find_openssl()
# -------------------------------------------

# ----------  Secure HTTP Request Handler ----------
class SecureHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP handler:
    - Serves only allowed file types
    - Blocks dangerous extensions
    - Auto-serves index.html / index.htm / index.web for directories
    """
    ALLOWED_EXTENSIONS = {
        '.html', '.htm', '.css', '.js', '.png', '.jpg', '.jpeg',
        '.gif', '.ico', '.svg', '.web', '.pdf', '.txt', '.md'
    }
    BLOCKED_EXTENSIONS = {
        '.py', '.pyc', '.pem', '.key', '.crt', '.config', '.json',
        '.db', '.sqlite', '.log'
    }
    INDEX_FILES = ['index.html', 'index.htm', 'index.web']

    def do_GET(self):
        # Translate URL to filesystem path
        path = self.translate_path(self.path)
        print(f"[DEBUG] Requested path: {path}")

        # Handle directory requests
        if os.path.isdir(path):
            served = False
            for index_name in self.INDEX_FILES:
                index_path = os.path.join(path, index_name)
                if os.path.exists(index_path):
                    self.path = f"/{index_name}"
                    served = True
                    break
            if not served:
                self.send_error(403, "Directory listing forbidden")
                return
            path = self.translate_path(self.path)

        _, ext = os.path.splitext(path)
        ext = ext.lower()

        # Block dangerous extensions
        if ext in self.BLOCKED_EXTENSIONS:
            self.send_error(403, f"Access to {ext} files is forbidden")
            return

        # Serve allowed extensions
        if ext in self.ALLOWED_EXTENSIONS:
            return super().do_GET()

        self.send_error(403, "File type not allowed")

    def log_message(self, format, *args):
        print(f"[ACCESS] {self.client_address[0]} - {format % args}")


# ----------  Server Instance ----------
class ServerInstance:
    def __init__(self, name, port, www_folder, ip_mode="network", custom_ip="0.0.0.0",
                 use_https=False, cert_file=None, key_file=None):
        self.name = name
        self.port = port
        self.www_folder = www_folder
        self.ip_mode = ip_mode
        self.custom_ip = custom_ip
        self.use_https = use_https
        self.cert_file = cert_file
        self.key_file = key_file
        self.is_running = False
        self.server = None
        self.server_thread = None

    def get_effective_ip(self):
        return {"localhost": "127.0.0.1", "custom": self.custom_ip}.get(self.ip_mode, "0.0.0.0")

    def get_display_ip(self):
        proto = "HTTPS" if self.use_https else "HTTP"
        ip = self.get_effective_ip()
        return f"{ip}:{self.port} ({proto})"


# ----------  Config Manager ----------
class ConfigManager:
    def __init__(self, config_file="server_config.json"):
        app_dir = Path(__file__).parent.resolve()
        self.config_file = app_dir / config_file

    def load_server_configs(self):
        if self.config_file.exists():
            try:
                return json.loads(self.config_file.read_text()).get("servers", [])
            except Exception as e:
                print("Config load error:", e)
        return []

    def save_server_configs(self, servers_data):
        self.config_file.write_text(json.dumps({"servers": servers_data}, indent=4))


# ----------  GUI ----------
class WebServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Multi-Server Web Manager")
        self.root.geometry("1050x750")
        self.servers = {}
        self.current_server_name = None
        self.config_manager = ConfigManager()
        self.load_servers_from_config()
        self.build_gui()
        if self.servers:
            first = list(self.servers.keys())[0]
            self.server_listbox.selection_set(0)
            self.select_server(first)

    # ----------  GUI construction ----------
    def build_gui(self):
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # left panel: server list
        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        ttk.Label(left, text="Servers", font=('Arial', 12, 'bold')).pack(pady=(0, 5))
        listbox_frame = ttk.Frame(left)
        listbox_frame.pack(fill=tk.BOTH, expand=True)
        self.server_listbox = tk.Listbox(listbox_frame)
        scroll = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=self.server_listbox.yview)
        self.server_listbox.configure(yscrollcommand=scroll.set)
        self.server_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.server_listbox.bind('<<ListboxSelect>>', self.on_server_select)
        for name in self.servers.keys():
            self.server_listbox.insert(tk.END, name)
        btn_frame = ttk.Frame(left)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="Add Server", command=self.add_server).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Remove Server", command=self.remove_server).pack(side=tk.LEFT, padx=2)

        # right panel: controls
        right = ttk.Frame(paned)
        paned.add(right, weight=3)

        # server control
        control = ttk.LabelFrame(right, text="Server Control", padding=10)
        control.pack(fill=tk.X, pady=5)
        self.build_control(control)

        # certificate frame
        self.cert_frame = ttk.LabelFrame(right, text="SSL Certificate Settings", padding=10)
        self.build_cert(self.cert_frame)
        self.cert_frame_visible = False

        # network info
        net = ttk.LabelFrame(right, text="Network Information", padding=10)
        net.pack(fill=tk.X, pady=5)
        self.build_network(net)

        # www folder
        folder = ttk.LabelFrame(right, text="WWW Folder Settings", padding=10)
        folder.pack(fill=tk.X, pady=5)
        self.www_label = ttk.Label(folder, text="Folder: Not set")
        self.www_label.grid(row=0, column=0, sticky=tk.W)
        ttk.Button(folder, text="Select Folder", command=self.select_www_folder).grid(row=0, column=1, padx=5)
        ttk.Button(folder, text="Open Folder", command=self.open_www_folder).grid(row=0, column=2, padx=5)

        file_frame = ttk.LabelFrame(right, text="File Management", padding=10)
        file_frame.pack(fill=tk.X, pady=5)
        ttk.Button(file_frame, text="Add Files to WWW", command=self.add_files_to_www).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_frame, text="Refresh File List", command=self.refresh_file_list).pack(side=tk.LEFT, padx=2)
        self.file_listbox = tk.Listbox(file_frame, height=5)
        self.file_listbox.pack(fill=tk.X, expand=True, pady=5)

        # editor + log
        nb = ttk.Notebook(right)
        nb.pack(fill=tk.BOTH, expand=True, pady=10)
        editor = ttk.Frame(nb, padding=10)
        nb.add(editor, text="Index File Editor")
        btn = ttk.Frame(editor)
        btn.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(btn, text="Load Index File", command=self.load_index_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn, text="Save File", command=self.save_index_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn, text="Create New Index", command=self.create_new_index).pack(side=tk.LEFT, padx=2)
        self.editor_text = scrolledtext.ScrolledText(editor, height=15)
        self.editor_text.pack(fill=tk.BOTH, expand=True)

        log = ttk.Frame(nb, padding=10)
        nb.add(log, text="Server Log")
        self.log_text = scrolledtext.ScrolledText(log, height=10, state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True)

    # ---------- Control panel ----------
    def build_control(self, parent):
        name_frm = ttk.Frame(parent)
        name_frm.grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=5)
        ttk.Label(name_frm, text="Server Name:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        self.name_label = ttk.Label(name_frm, text="None", font=('Arial', 10))
        self.name_label.pack(side=tk.LEFT, padx=5)

        ttk.Label(parent, text="Protocol:").grid(row=1, column=0, sticky=tk.W)
        self.https_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, text="Enable HTTPS", variable=self.https_var, command=self.on_https_toggle).grid(row=1, column=1, sticky=tk.W, padx=5)

        ttk.Label(parent, text="Access Mode:").grid(row=2, column=0, sticky=tk.W)
        self.ip_mode_var = tk.StringVar(value="network")
        cb = ttk.Combobox(parent, textvariable=self.ip_mode_var,
                          values=["Network Access (All IPs)", "Local Access Only (127.0.0.1)", "Custom IP"],
                          width=25, state="readonly")
        cb.grid(row=2, column=1, columnspan=2, sticky=tk.W, padx=5)
        cb.bind('<<ComboboxSelected>>', self.on_ip_mode_change)

        self.custom_ip_frame = ttk.Frame(parent)
        self.custom_ip_frame.grid(row=3, column=1, columnspan=2, sticky=tk.W, padx=5, pady=5)
        self.custom_ip_frame.grid_remove()
        ttk.Label(self.custom_ip_frame, text="Custom IP:").pack(side=tk.LEFT)
        self.custom_ip_entry = ttk.Entry(self.custom_ip_frame, width=15)
        self.custom_ip_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(parent, text="Port:").grid(row=4, column=0, sticky=tk.W)
        self.port_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.port_var, width=10).grid(row=4, column=1, sticky=tk.W, padx=5)
        self.toggle_btn = ttk.Button(parent, text="Start Server", command=self.toggle_server)
        self.toggle_btn.grid(row=4, column=2, padx=5)
        self.status_label = ttk.Label(parent, text="Status: Stopped", foreground="red")
        self.status_label.grid(row=4, column=3, padx=10)

    # ---------- Cert panel ----------
    def build_cert(self, parent):
        ttk.Label(parent, text="Certificate (.pem):").grid(row=0, column=0, sticky=tk.W)
        self.cert_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.cert_var, width=50).grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Button(parent, text="Browse", command=self.select_cert).grid(row=0, column=2, padx=5)

        ttk.Label(parent, text="Private Key (.key):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.key_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.key_var, width=50).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Button(parent, text="Browse", command=self.select_key).grid(row=1, column=2, padx=5, pady=5)

        ttk.Button(parent, text="Generate Self-Signed Cert", command=self.generate_self_signed_cert).grid(row=2, column=0, columnspan=3, pady=5)

    # ---------- Network info ----------
    def build_network(self, parent):
        local_ip = self.get_network_ip()
        ttk.Label(parent, text="Network IP (for other devices):", font=('Arial', 9, 'bold')).grid(row=0, column=0, sticky=tk.W)
        self.net_ip_label = ttk.Label(parent, text=local_ip, foreground="blue", font=('Arial', 9))
        self.net_ip_label.grid(row=0, column=1, sticky=tk.W, padx=10)
        ttk.Label(parent, text="Localhost IP (this PC only):", font=('Arial', 9, 'bold')).grid(row=1, column=0, sticky=tk.W)
        ttk.Label(parent, text="127.0.0.1", foreground="green", font=('Arial', 9)).grid(row=1, column=1, sticky=tk.W, padx=10)
        self.access_urls_label = ttk.Label(parent, text="", foreground="darkgreen")
        self.access_urls_label.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(5, 0))

    # ---------- Helpers ----------
    def get_network_ip(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    # ---------- Events ----------
    def on_https_toggle(self):
        if self.https_var.get():
            if not self.cert_frame_visible:
                self.cert_frame.pack(fill=tk.X, pady=5, after=self.root.nametowidget(self.toggle_btn.winfo_parent()))
                self.cert_frame_visible = True
        else:
            if self.cert_frame_visible:
                self.cert_frame.pack_forget()
                self.cert_frame_visible = False
        if self.current_server_name:
            self.servers[self.current_server_name].use_https = self.https_var.get()
            self.save_servers_to_config()
            self.log_message(f"HTTPS {'enabled' if self.https_var.get() else 'disabled'}")

    def on_ip_mode_change(self, _=None):
        mode = self.ip_mode_var.get()
        self.custom_ip_frame.grid(row=3, column=1, columnspan=2, sticky=tk.W, padx=5, pady=5) if mode == "Custom IP" else self.custom_ip_frame.grid_remove()
        if self.current_server_name:
            s = self.servers[self.current_server_name]
            s.ip_mode = {"Network Access (All IPs)": "network", "Local Access Only (127.0.0.1)": "localhost"}.get(mode, "custom")
            self.save_servers_to_config()
            self.update_access_urls()

    # ---------- Cert browse ----------
    def select_cert(self):
        f = filedialog.askopenfilename(title="Select SSL Certificate", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if f:
            self.cert_var.set(f)
            if self.current_server_name:
                self.servers[self.current_server_name].cert_file = f
                self.save_servers_to_config()

    def select_key(self):
        f = filedialog.askopenfilename(title="Select Private Key", filetypes=[("Key files", "*.key"), ("All files", "*.*")])
        if f:
            self.key_var.set(f)
            if self.current_server_name:
                self.servers[self.current_server_name].key_file = f
                self.save_servers_to_config()

    # ---------- Self-signed cert ----------
    def generate_self_signed_cert(self):
        if not self.current_server_name:
            return
        srv = self.servers[self.current_server_name]
        www = Path(srv.www_folder)
        www.mkdir(parents=True, exist_ok=True)
        cert = www / "server.pem"
        key = www / "server.key"
        if cert.exists() and key.exists():
            if not messagebox.askyesno("Files Exist", "Overwrite existing cert/key?"):
                return
        try:
            subprocess.run([
                OPENSSL_EXE, "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key), "-out", str(cert), "-days", "365", "-nodes",
                "-subj", f"/CN={srv.name}/O=LocalDev/C=US"
            ], check=True, capture_output=True, text=True)
            srv.cert_file, srv.key_file = str(cert), str(key)
            self.cert_var.set(str(cert))
            self.key_var.set(str(key))
            self.save_servers_to_config()
            messagebox.showinfo("Success", f"Self-signed certificate created:\n{cert}\n{key}")
            self.log_message(f"Generated self-signed cert for '{srv.name}'")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("OpenSSL Error", e.stderr or str(e))
            self.log_message(f"Cert generation failed: {e.stderr or e}")

    # ---------- WWW folder / files ----------
    def select_www_folder(self):
        if not self.current_server_name:
            return
        f = filedialog.askdirectory(title="Select WWW Folder")
        if f:
            self.servers[self.current_server_name].www_folder = f
            self.save_servers_to_config()
            self.update_www_display()
            self.refresh_file_list()

    def open_www_folder(self):
        if not self.current_server_name:
            return
        www = self.servers[self.current_server_name].www_folder
        if Path(www).is_dir():
            webbrowser.open(www)
        else:
            messagebox.showerror("Error", "WWW folder does not exist")

    def add_files_to_www(self):
        if not self.current_server_name:
            return
        files = filedialog.askopenfilenames(title="Select Files to Add")
        if not files:
            return
        www = Path(self.servers[self.current_server_name].www_folder)
        www.mkdir(parents=True, exist_ok=True)
        added = 0
        for src in files:
            dst = www / Path(src).name
            try:
                shutil.copy2(src, dst)
                added += 1
            except Exception as e:
                self.log_message(f"Copy error: {e}")
        self.refresh_file_list()
        messagebox.showinfo("Success", f"Added {added} files")

    def refresh_file_list(self):
        self.file_listbox.delete(0, tk.END)
        if not self.current_server_name:
            return
        www = Path(self.servers[self.current_server_name].www_folder)
        if www.is_dir():
            for f in sorted(www.iterdir()):
                if f.is_file():
                    self.file_listbox.insert(tk.END, f.name)

    # ---------- Index editor ----------
    def load_index_file(self):
        if not self.current_server_name:
            return
        www = Path(self.servers[self.current_server_name].www_folder)
        if not www.is_dir():
            messagebox.showerror("Error", "WWW folder does not exist")
            return
        for name in ("index.html", "index.htm", "index.web"):
            f = www / name
            if f.is_file():
                self.editor_text.delete(1.0, tk.END)
                self.editor_text.insert(1.0, f.read_text(encoding="utf-8"))
                self.log_message(f"Loaded {f.name}")
                return
        messagebox.showinfo("Info", "No index file found. Create a new one?")

    def save_index_file(self):
        if not self.current_server_name:
            return
        www = Path(self.servers[self.current_server_name].www_folder)
        www.mkdir(parents=True, exist_ok=True)
        out = www / "index.html"
        try:
            out.write_text(self.editor_text.get(1.0, tk.END), encoding="utf-8")
            self.log_message(f"Saved {out.name}")
            messagebox.showinfo("Success", f"File saved: {out.name}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def create_new_index(self):
        tpl = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Welcome</title>
  <style>body{font-family:Arial;margin:40px;background:#f4f4f4}.container{max-width:800px;margin:0 auto;background:#fff;padding:20px;border-radius:8px}h1{color:#333}</style>
</head>
<body>
  <div class="container">
    <h1>Welcome to My Web Server!</h1>
    <p>This is a new index file.</p>
    <p>Server is running successfully.</p>
  </div>
</body>
</html>"""
        self.editor_text.delete(1.0, tk.END)
        self.editor_text.insert(1.0, tpl)
        self.log_message("Created new index template")

    # ---------- Server management ----------
    def add_server(self):
        name = simpledialog.askstring("Add Server", "Enter server name:")
        if not name or name in self.servers:
            messagebox.showerror("Error", "Name empty or already exists")
            return
        used = {s.port for s in self.servers.values()}
        port = 8000
        while port in used:
            port += 1
        www = Path(__file__).parent / f"www_{name}"
        self.servers[name] = ServerInstance(name, port, str(www), "network")
        self.server_listbox.insert(tk.END, name)
        self.save_servers_to_config()
        self.log_message(f"Added server '{name}' on port {port}")
        self.server_listbox.selection_clear(0, tk.END)
        self.server_listbox.selection_set(tk.END)
        self.select_server(name)

    def remove_server(self):
        sel = self.server_listbox.curselection()
        if not sel:
            return
        name = self.server_listbox.get(sel[0])
        srv = self.servers[name]
        if srv.is_running:
            if not messagebox.askyesno("Confirm", f"Server '{name}' is running. Stop and remove?"):
                return
            self.stop_server()
        self.server_listbox.delete(sel[0])
        del self.servers[name]
        self.save_servers_to_config()
        self.log_message(f"Removed server '{name}'")
        if self.server_listbox.size():
            self.server_listbox.selection_set(0)
            self.select_server(self.server_listbox.get(0))
        else:
            self.current_server_name = None
            self.name_label.config(text="None")
            self.https_var.set(False)
            self.ip_mode_var.set("Network Access (All IPs)")
            self.port_var.set("")
            self.www_label.config(text="Folder: Not set")
            self.file_listbox.delete(0, tk.END)
            self.access_urls_label.config(text="")

    def toggle_server(self):
        if not self.current_server_name:
            return
        srv = self.servers[self.current_server_name]
        if srv.is_running:
            self.stop_server()
        else:
            self.start_server()

    # ---------- Start / Stop ----------
    def start_server(self):
        if not self.current_server_name:
            return
        srv = self.servers[self.current_server_name]
        try:
            port = int(self.port_var.get())
            if not (1 <= port <= 65535):
                raise ValueError("Port out of range")
            ip_mode = self.ip_mode_var.get()
            srv.use_https = self.https_var.get()
            srv.ip_mode = {"Network Access (All IPs)": "network", "Local Access Only (127.0.0.1)": "localhost"}.get(ip_mode, "custom")
            if srv.ip_mode == "custom":
                srv.custom_ip = self.custom_ip_entry.get().strip()
            srv.port = port

            ip_bind = srv.get_effective_ip()
            socket.inet_aton(ip_bind)  # validate

            # conflict check
            for s in self.servers.values():
                if s != srv and s.is_running and s.port == port and s.get_effective_ip() == ip_bind:
                    raise ValueError(f"Address in use by server '{s.name}'")

            www = Path(srv.www_folder)
            www.mkdir(parents=True, exist_ok=True)

            handler = SecureHTTPRequestHandler
            srv.server = socketserver.TCPServer((ip_bind, port), lambda *a, **k: handler(*a, directory=str(www), **k))

            if srv.use_https:
                if not (srv.cert_file and srv.key_file and Path(srv.cert_file).is_file() and Path(srv.key_file).is_file()):
                    raise ValueError("HTTPS enabled but cert/key files missing")
                ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ctx.load_cert_chain(srv.cert_file, srv.key_file)
                srv.server.socket = ctx.wrap_socket(srv.server.socket, server_side=True)

            srv.server_thread = threading.Thread(target=srv.server.serve_forever, daemon=True)
            srv.server_thread.start()
            srv.is_running = True
            self.update_status()
            self.update_access_urls()
            self.save_servers_to_config()
            self.log_message(f"Server '{srv.name}' started on {srv.get_display_ip()}")
        except Exception as e:
            messagebox.showerror("Start Error", str(e))
            self.log_message(f"Start failed: {e}")

    def stop_server(self):
        if not self.current_server_name:
            return
        srv = self.servers[self.current_server_name]
        if srv.server:
            srv.server.shutdown()
            srv.server.server_close()
            srv.is_running = False
            self.update_status()
            self.update_access_urls()
            self.log_message(f"Server '{srv.name}' stopped")

    # ---------- Config / select ----------
    def load_servers_from_config(self):
        data = self.config_manager.load_server_configs()
        app_dir = Path(__file__).parent.resolve()
        if not data:
            default_www = app_dir / "www"
            self.servers["Default"] = ServerInstance("Default", 8000, str(default_www), "network")
        else:
            for cfg in data:
                www = Path(cfg["www_folder"])
                if not www.is_absolute():
                    www = app_dir / www
                self.servers[cfg["name"]] = ServerInstance(
                    cfg["name"], cfg["port"], str(www),
                    cfg.get("ip_mode", "network"), cfg.get("custom_ip", "0.0.0.0"),
                    cfg.get("use_https", False), cfg.get("cert_file"), cfg.get("key_file")
                )

    def save_servers_to_config(self):
        data = [
            {
                "name": s.name, "port": s.port, "www_folder": s.www_folder,
                "ip_mode": s.ip_mode, "custom_ip": s.custom_ip,
                "use_https": s.use_https, "cert_file": s.cert_file, "key_file": s.key_file
            }
            for s in self.servers.values()
        ]
        self.config_manager.save_server_configs(data)

    def on_server_select(self, _):
        sel = self.server_listbox.curselection()
        if sel:
            self.select_server(self.server_listbox.get(sel[0]))

    def select_server(self, name):
        self.current_server_name = name
        srv = self.servers[name]
        self.name_label.config(text=name)
        self.https_var.set(srv.use_https)
        self.on_https_toggle()
        mode = {"network": "Network Access (All IPs)", "localhost": "Local Access Only (127.0.0.1)", "custom": "Custom IP"}.get(srv.ip_mode, "Custom IP")
        self.ip_mode_var.set(mode)
        self.custom_ip_entry.delete(0, tk.END)
        self.custom_ip_entry.insert(0, srv.custom_ip)
        self.port_var.set(str(srv.port))
        if srv.cert_file:
            self.cert_var.set(srv.cert_file)
        if srv.key_file:
            self.key_var.set(srv.key_file)
        self.update_www_display()
        self.refresh_file_list()
        self.update_status()
        self.update_access_urls()
        self.log_message(f"Selected server '{name}'")

    def update_www_display(self):
        if not self.current_server_name:
            return
        www = Path(self.servers[self.current_server_name].www_folder)
        try:
            rel = www.relative_to(Path(__file__).parent)
        except ValueError:
            rel = www
        self.www_label.config(text=f"Folder: {rel}")

    def update_status(self):
        if not self.current_server_name:
            return
        srv = self.servers[self.current_server_name]
        if srv.is_running:
            self.toggle_btn.config(text="Stop Server")
            self.status_label.config(text=f"Running on {srv.get_display_ip()}", foreground="green")
        else:
            self.toggle_btn.config(text="Start Server")
            self.status_label.config(text="Status: Stopped", foreground="red")

    def update_access_urls(self):
        if not self.current_server_name:
            self.access_urls_label.config(text="")
            return
        srv = self.servers[self.current_server_name]
        if not srv.is_running:
            self.access_urls_label.config(text="")
            return
        proto = "https" if srv.use_https else "http"
        ip = srv.get_effective_ip()
        port = srv.port
        net_ip = self.get_network_ip()
        if ip == "0.0.0.0":
            txt = f"Access: {proto}://localhost:{port}  |  {proto}://{net_ip}:{port} (network)"
        elif ip == "127.0.0.1":
            txt = f"Access: {proto}://127.0.0.1:{port} (local only)"
        else:
            txt = f"Access: {proto}://{ip}:{port} (custom)"
        self.access_urls_label.config(text=txt)

    def log_message(self, msg):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f"{msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')


# ---------- Run ----------
def main():
    root = tk.Tk()
    
    # Set the window icon relative to script location
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(script_dir, 'www', 'favicon.png')
        icon = tk.PhotoImage(file=icon_path)
        root.iconphoto(False, icon)
    except Exception as e:
        print(f"Could not load icon: {e}")
    
    WebServerGUI(root)
    root.mainloop()
if __name__ == "__main__":
    main()
