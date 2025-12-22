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
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# ---------- Secure HTTP Request Handler ----------
class SecureHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    ALLOWED_EXTENSIONS = {'.html', '.htm', '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.web', '.pdf', '.txt', '.md'}
    BLOCKED_EXTENSIONS = {'.py', '.pyc', '.pem', '.key', '.crt', '.config', '.json', '.db', '.sqlite', '.log'}
    INDEX_FILES = ['index.html', 'index.htm', 'index.web']

    def do_GET(self):
        path = self.translate_path(self.path)
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

        if ext in self.BLOCKED_EXTENSIONS:
            self.send_error(403, f"Access to {ext} files is forbidden")
            return

        if ext in self.ALLOWED_EXTENSIONS:
            return super().do_GET()

        self.send_error(403, "File type not allowed")

    def log_message(self, format, *args):
        print(f"[ACCESS] {self.client_address[0]} - {format % args}")

# ---------- Server Instance ----------
class ServerInstance:
    def __init__(self, name, port, www_folder, ip_mode="network", custom_ip="0.0.0.0",
                 use_https=False, cert_file=None, key_file=None, **kwargs):  # **kwargs ignores unknown keys
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

# ---------- Config Manager ----------
class ConfigManager:
    def __init__(self, config_file="server_config.json"):
        self.config_file = Path(__file__).parent / config_file

    def load_config(self):
        if self.config_file.exists():
            try:
                return json.loads(self.config_file.read_text())
            except Exception as e:
                print("Config load error:", e)
        return {"servers": [], "last_server": None}

    def save_config(self, servers_data, last_server=None):
        data = {"servers": servers_data, "last_server": last_server}
        self.config_file.write_text(json.dumps(data, indent=4))

# ---------- Web Server GUI ----------
class WebServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Multi-Server Web Manager")
        self.root.geometry("1050x750")

        self.servers = {}
        self.current_server_name = None
        self.last_server = None
        self.config_manager = ConfigManager()

        # Ensure script folder has a www folder
        script_www = Path(__file__).parent / "www"
        script_www.mkdir(exist_ok=True)

        self.load_servers_from_config()
        self.build_gui()

        # Restore last selected server
        if self.servers:
            if self.last_server and self.last_server in self.servers:
                idx = list(self.servers.keys()).index(self.last_server)
                self.server_listbox.selection_set(idx)
                self.select_server(self.last_server)
            else:
                first = list(self.servers.keys())[0]
                self.server_listbox.selection_set(0)
                self.select_server(first)

    # ---------- GUI Construction ----------
    def build_gui(self):
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left panel: server list
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

        # Right panel
        right = ttk.Frame(paned)
        paned.add(right, weight=3)

        # Server control
        control = ttk.LabelFrame(right, text="Server Control", padding=10)
        control.pack(fill=tk.X, pady=5)
        self.build_control(control)

        # WWW folder
        folder = ttk.LabelFrame(right, text="WWW Folder Settings", padding=10)
        folder.pack(fill=tk.X, pady=5)
        self.www_label = ttk.Label(folder, text="Folder: Not set")
        self.www_label.grid(row=0, column=0, sticky=tk.W)
        ttk.Button(folder, text="Select Folder", command=self.select_www_folder).grid(row=0, column=1, padx=5)
        ttk.Button(folder, text="Open Folder", command=self.open_www_folder).grid(row=0, column=2, padx=5)

        # File management
        file_frame = ttk.LabelFrame(right, text="File Management", padding=10)
        file_frame.pack(fill=tk.X, pady=5)
        ttk.Button(file_frame, text="Add Files to WWW", command=self.add_files_to_www).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_frame, text="Refresh File List", command=self.refresh_file_list).pack(side=tk.LEFT, padx=2)
        self.file_listbox = tk.Listbox(file_frame, height=5)
        self.file_listbox.pack(fill=tk.X, expand=True, pady=5)

        # Editor + log
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

    # ---------- Server Control ----------
    def build_control(self, parent):
        ttk.Label(parent, text="Server Name:").grid(row=0, column=0, sticky=tk.W)
        self.name_label = ttk.Label(parent, text="None")
        self.name_label.grid(row=0, column=1, sticky=tk.W)
        ttk.Label(parent, text="Port:").grid(row=1, column=0, sticky=tk.W)
        self.port_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.port_var, width=10).grid(row=1, column=1, sticky=tk.W)
        self.https_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, text="Enable HTTPS", variable=self.https_var, command=self.toggle_https).grid(row=2, column=0, columnspan=2, sticky=tk.W)
        self.toggle_btn = ttk.Button(parent, text="Start Server", command=self.toggle_server)
        self.toggle_btn.grid(row=3, column=0, columnspan=2)
        self.status_label = ttk.Label(parent, text="Status: Stopped", foreground="red")
        self.status_label.grid(row=4, column=0, columnspan=2)

    # ---------- HTTPS toggle ----------
    def toggle_https(self):
        if not self.current_server_name:
            return
        srv = self.servers[self.current_server_name]
        srv.use_https = self.https_var.get()
        self.save_servers_to_config()

    # ---------- Server start/stop ----------
    def toggle_server(self):
        if not self.current_server_name:
            return
        srv = self.servers[self.current_server_name]
        if srv.is_running:
            self.stop_server()
        else:
            self.start_server()

    def start_server(self):
        srv = self.servers[self.current_server_name]
        try:
            port = int(self.port_var.get())
            srv.port = port
            ip_bind = srv.get_effective_ip()
            handler = SecureHTTPRequestHandler

            # Change working directory
            os.chdir(srv.www_folder)

            srv.server = socketserver.ThreadingTCPServer((ip_bind, port), handler)
            # HTTPS using Python-generated self-signed cert
            if srv.use_https:
                if not srv.cert_file or not srv.key_file:
                    self.generate_self_signed_cert(srv)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=srv.cert_file, keyfile=srv.key_file)
                srv.server.socket = context.wrap_socket(srv.server.socket, server_side=True)

            srv.is_running = True
            srv.server_thread = threading.Thread(target=srv.server.serve_forever, daemon=True)
            srv.server_thread.start()
            self.update_status()
            self.log_message(f"Server '{srv.name}' started at {srv.get_display_ip()}")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.log_message(f"Failed to start server: {e}")

    def stop_server(self):
        srv = self.servers[self.current_server_name]
        if srv.server:
            srv.server.shutdown()
            srv.server.server_close()
            srv.server = None
        srv.is_running = False
        self.update_status()
        self.log_message(f"Server '{srv.name}' stopped")

    def update_status(self):
        srv = self.servers.get(self.current_server_name)
        if not srv:
            return
        if srv.is_running:
            self.status_label.config(text="Status: Running", foreground="green")
            self.toggle_btn.config(text="Stop Server")
        else:
            self.status_label.config(text="Status: Stopped", foreground="red")
            self.toggle_btn.config(text="Start Server")

    # ---------- Self-signed cert generator ----------
    def generate_self_signed_cert(self, srv):
        www = Path(srv.www_folder)
        www.mkdir(exist_ok=True)
        key_path = www / "server.key"
        cert_path = www / "server.pem"

        # Generate private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Generate self-signed cert
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, srv.name),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(key, hashes.SHA256())
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        srv.cert_file = str(cert_path)
        srv.key_file = str(key_path)
        self.https_var.set(True)

    # ---------- Server selection ----------
    def on_server_select(self, event):
        sel = self.server_listbox.curselection()
        if sel:
            self.select_server(self.server_listbox.get(sel[0]))

    def select_server(self, name):
        self.current_server_name = name
        srv = self.servers[name]
        self.port_var.set(str(srv.port))
        self.https_var.set(srv.use_https)
        self.www_label.config(text=f"Folder: {srv.www_folder}")
        self.update_status()
        self.refresh_file_list()

    # ---------- WWW / files ----------
    def select_www_folder(self):
        if not self.current_server_name:
            return
        folder = filedialog.askdirectory(title="Select WWW Folder")
        if folder:
            self.servers[self.current_server_name].www_folder = folder
            self.www_label.config(text=f"Folder: {folder}")
            self.save_servers_to_config()
            self.refresh_file_list()

    def open_www_folder(self):
        if not self.current_server_name:
            return
        folder = self.servers[self.current_server_name].www_folder
        if folder and os.path.isdir(folder):
            os.startfile(folder)

    def add_files_to_www(self):
        if not self.current_server_name:
            return
        files = filedialog.askopenfilenames(title="Select Files")
        if not files:
            return
        folder = self.servers[self.current_server_name].www_folder
        for f in files:
            shutil.copy(f, folder)
        self.refresh_file_list()

    def refresh_file_list(self):
        if not self.current_server_name:
            return
        self.file_listbox.delete(0, tk.END)
        folder = self.servers[self.current_server_name].www_folder
        if os.path.isdir(folder):
            for f in os.listdir(folder):
                self.file_listbox.insert(tk.END, f)

    # ---------- Index editor ----------
    def load_index_file(self):
        if not self.current_server_name:
            return
        folder = self.servers[self.current_server_name].www_folder
        for name in ["index.html", "index.htm", "index.web"]:
            path = os.path.join(folder, name)
            if os.path.exists(path):
                self.editor_text.delete("1.0", tk.END)
                self.editor_text.insert(tk.END, open(path, "r", encoding="utf-8").read())
                return
        messagebox.showinfo("Info", "No index file found.")

    def save_index_file(self):
        if not self.current_server_name:
            return
        folder = self.servers[self.current_server_name].www_folder
        path = os.path.join(folder, "index.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.editor_text.get("1.0", tk.END))
        self.refresh_file_list()
        messagebox.showinfo("Saved", f"Saved to {path}")

    def create_new_index(self):
        self.editor_text.delete("1.0", tk.END)
        self.editor_text.insert("1.0", "<!DOCTYPE html>\n<html>\n<head>\n<title>New Page</title>\n</head>\n<body>\n<h1>Hello World</h1>\n</body>\n</html>")

    # ---------- Config ----------
    def load_servers_from_config(self):
        self.servers.clear()
        data = self.config_manager.load_config()
        self.last_server = data.get("last_server")
        for srv_data in data.get("servers", []):
            srv = ServerInstance(**srv_data)
            self.servers[srv.name] = srv

    def save_servers_to_config(self):
        servers_data = []
        for srv in self.servers.values():
            d = srv.__dict__.copy()
            # Remove runtime-only objects
            d.pop("server", None)
            d.pop("server_thread", None)
            d.pop("is_running", None)
            servers_data.append(d)
        self.config_manager.save_config(servers_data, self.current_server_name)

    def log_message(self, msg):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f"{msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

# ---------- Run ----------
def main():
    root = tk.Tk()
    gui = WebServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", gui.save_servers_to_config)
    root.mainloop()

if __name__ == "__main__":
    main()
