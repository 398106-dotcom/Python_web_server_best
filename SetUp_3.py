# SetUp_3.py — installer & updater (no assets folder)
import pathlib, urllib.request, base64, json, subprocess, sys, os

# -----------------------
SERVER_URL = "https://raw.githubusercontent.com/398106-dotcom/Python_web_server_best/main/assets/start_server.py"

FAVICON_B64 = b"""
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABHNCSVQICAgIfAhkiAAAAAlw
SFlzAAAAdgAAAHYBTnsmCAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoA
AANCSURBVFiFtZVNbBRFEMf/szO7s7
""".strip()

# -----------------------
def download_file(url, dest: pathlib.Path):
    print(f"⬇️ Downloading {dest.name}...")
    try:
        with urllib.request.urlopen(url) as r:
            content = r.read()
        if content.strip().startswith(b"<") or b"Not Found" in content:
            raise ValueError("Downloaded file looks wrong")
        dest.write_bytes(content)
        print(f"✅ {dest.name} downloaded")
    except Exception as e:
        print(f"❌ Failed to download {dest.name}: {e}")
        sys.exit(1)

def create_updater(folder: pathlib.Path):
    updater_path = folder / "update.py"
    updater_code = f"""\
import pathlib, urllib.request, sys

SERVER_URL = "{SERVER_URL}"

def main():
    folder = pathlib.Path(__file__).parent
    server_path = folder / "start_server.py"
    print("⬇️ Updating start_server.py...")
    try:
        with urllib.request.urlopen(SERVER_URL) as r:
            content = r.read()
        if content.strip().startswith(b"<") or b"Not Found" in content:
            raise ValueError("Downloaded file looks wrong")
        server_path.write_bytes(content)
        print("✅ start_server.py updated successfully!")
    except Exception as e:
        print("❌ Failed to update start_server.py:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
"""
    updater_path.write_text(updater_code, encoding="utf-8")
    print(f"✅ update.py created → {updater_path}")

# -----------------------
def main():
    print("=== Python Web Server Installer / Updater ===\n")

    target = input("Install location (full path): ").strip()
    if not target:
        print("❌ No path provided.")
        sys.exit(1)

    folder = pathlib.Path(target).expanduser().resolve()
    folder.mkdir(parents=True, exist_ok=True)

    # ---- download start_server.py ----
    server_path = folder / "start_server.py"
    if server_path.exists():
        print("⚠️ start_server.py exists — updating...")
    download_file(SERVER_URL, server_path)

    # ---- www folder ----
    www = folder / "www"
    www.mkdir(exist_ok=True)
    (www / "index.html").write_text(
        "<!doctype html><html><head><title>It works</title></head>"
        "<body><h1>Python Best Server Hoster</h1></body></html>",
        encoding="utf-8"
    )
    try:
        (www / "favicon.png").write_bytes(base64.b64decode(FAVICON_B64))
    except Exception:
        print("⚠️ favicon skipped (invalid base64)")

    # ---- config ----
    config = {
        "servers":[
            {
                "name":"Default",
                "port":8000,
                "www_folder":"www",
                "ip_mode":"network",
                "custom_ip":"0.0.0.0",
                "use_https":False,
                "cert_file":None,
                "key_file":None
            }
        ]
    }
    (folder / "server_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

    # ---- optional packages ----
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "qrcode[pil]", "pystray"])
        print("✅ Optional packages installed.")
    except Exception as e:
        print("⚠️ Optional packages skipped:", e)
        print(f"Run manually: {sys.executable} -m pip install qrcode[pil] pystray")

    # ---- create updater ----
    create_updater(folder)

    # ---- delete installer itself ----
    script_path = pathlib.Path(__file__)
    try:
        print("🗑️ Deleting installer script...")
        os.remove(script_path)
    except Exception:
        print("⚠️ Could not delete installer script (manual cleanup needed)")

    print("\n✅ Installation complete!")
    print(f"👉 Run: python \"{server_path}\" to start server")
    print(f"👉 Run: python \"{folder / 'update.py'}\" to update start_server.py anytime")

# -----------------------
if __name__ == "__main__":
    main()
