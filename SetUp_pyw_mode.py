# SetUp_3_pyw_smart_installer_wildcard_ignore.py
import pathlib, urllib.request, json, subprocess, sys, os, hashlib
import fnmatch

# -----------------------
GITHUB_USER = "398106-dotcom"
GITHUB_REPO = "Python_web_server_best"
GITHUB_FOLDER = "pyw_mode"
GITHUB_BRANCH = "main"

API_URL = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/contents/{GITHUB_FOLDER}?ref={GITHUB_BRANCH}"

# -----------------------
def sha1_bytes(data: bytes):
    h = hashlib.sha1()
    h.update(data)
    return h.hexdigest()

def download_file_smart(url, dest: pathlib.Path, expected_sha=None):
    try:
        with urllib.request.urlopen(url) as r:
            content = r.read()
    except Exception as e:
        print(f"❌ Failed to download {dest}: {e}")
        return False

    if expected_sha and dest.exists():
        local_sha = sha1_bytes(dest.read_bytes())
        if local_sha == expected_sha:
            print(f"⏭️ Skipping {dest} (unchanged)")
            return True

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    print(f"✅ {dest} downloaded/updated")
    return True

def download_github_folder(api_url, target_folder: pathlib.Path, ignore_patterns=None):
    """Recursively download all files, skipping those that match ignore_patterns."""
    ignore_patterns = ignore_patterns or []
    try:
        with urllib.request.urlopen(api_url) as r:
            files = json.load(r)
    except Exception as e:
        print(f"❌ Failed to get file list from GitHub: {e}")
        sys.exit(1)

    for f in files:
        rel_path = pathlib.Path(f["path"]).relative_to(GITHUB_FOLDER)
        # skip if any pattern matches
        if any(fnmatch.fnmatch(str(rel_path), pattern) for pattern in ignore_patterns):
            print(f"⏭️ Skipping {rel_path} (ignored)")
            continue

        if f["type"] == "file":
            dest = target_folder / rel_path
            download_file_smart(f["download_url"], dest, expected_sha=f.get("sha"))
        elif f["type"] == "dir":
            download_github_folder(f["url"], target_folder, ignore_patterns=ignore_patterns)
        else:
            print(f"⚠️ Unknown type {f['type']} for {f['path']} — skipping")

def create_smart_updater(folder: pathlib.Path):
    updater_path = folder / "update.py"
    updater_code = f"""\
import pathlib, urllib.request, json, hashlib, sys, os, fnmatch

GITHUB_USER = "{GITHUB_USER}"
GITHUB_REPO = "{GITHUB_REPO}"
GITHUB_FOLDER = "{GITHUB_FOLDER}"
GITHUB_BRANCH = "{GITHUB_BRANCH}"
API_URL = f"https://api.github.com/repos/{{GITHUB_USER}}/{{GITHUB_REPO}}/contents/{{GITHUB_FOLDER}}?ref={{GITHUB_BRANCH}}"

# ✅ User can customize this list with filenames, wildcards, or folder patterns
IGNORE_PATTERNS = ["server_config.json", ".gitkeep", "docs/*", "*.md"]

def sha1_bytes(data: bytes):
    h = hashlib.sha1()
    h.update(data)
    return h.hexdigest()

def download_file_smart(url, dest: pathlib.Path, expected_sha=None):
    try:
        with urllib.request.urlopen(url) as r:
            content = r.read()
    except Exception as e:
        print(f"❌ Failed to download {{dest}}: {{e}}")
        return False

    if expected_sha and dest.exists():
        local_sha = sha1_bytes(dest.read_bytes())
        if local_sha == expected_sha:
            print(f"⏭️ Skipping {{dest}} (unchanged)")
            return True

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    print(f"✅ {{dest}} downloaded/updated")
    return True

def download_github_folder(api_url, target_folder: pathlib.Path, ignore_patterns=None):
    ignore_patterns = ignore_patterns or []
    try:
        with urllib.request.urlopen(api_url) as r:
            files = json.load(r)
    except Exception as e:
        print(f"❌ Failed to get file list from GitHub: {{e}}")
        sys.exit(1)

    for f in files:
        rel_path = pathlib.Path(f["path"]).relative_to(GITHUB_FOLDER)
        if any(fnmatch.fnmatch(str(rel_path), pattern) for pattern in ignore_patterns):
            print(f"⏭️ Skipping {{rel_path}} (ignored)")
            continue

        if f["type"] == "file":
            dest = target_folder / rel_path
            download_file_smart(f["download_url"], dest, expected_sha=f.get("sha"))
        elif f["type"] == "dir":
            download_github_folder(f["url"], target_folder, ignore_patterns=ignore_patterns)
        else:
            print(f"⚠️ Unknown type {{f['type']}} for {{f['path']}} — skipping")

def main():
    print("=== Smart Updater for pyw_mode ===\\n")
    folder = pathlib.Path(__file__).parent.resolve()
    print(f"📂 Target folder: {{folder}}\\n")
    download_github_folder(API_URL, folder, ignore_patterns=IGNORE_PATTERNS)

    # ensure www folder exists
    www_folder = folder / "www"
    www_folder.mkdir(exist_ok=True)
    print("\\n✅ Update complete! All files in pyw_mode are now up-to-date (ignored files preserved).")

if __name__ == "__main__":
    main()
"""
    updater_path.write_text(updater_code, encoding="utf-8")
    print(f"✅ Smart updater created → {updater_path}")

# -----------------------
def main():
    print("=== Python Web Server Smart Installer ===\\n")

    target = input("Install location (full path): ").strip()
    if not target:
        print("❌ No path provided.")
        sys.exit(1)

    folder = pathlib.Path(target).expanduser().resolve()
    folder.mkdir(parents=True, exist_ok=True)

    # ---- download all files in pyw_mode, ignore patterns ----
    download_github_folder(API_URL, folder, ignore_patterns=["server_config.json", ".gitkeep"])

    # ---- ensure www folder exists ----
    www_folder = folder / "www"
    www_folder.mkdir(exist_ok=True)

    # ---- create default config if not exists ----
    config_file = folder / "server_config.json"
    if not config_file.exists():
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

    # ---- create smart updater ----
    create_smart_updater(folder)

    # ---- delete installer itself ----
    script_path = pathlib.Path(__file__)
    try:
        print("🗑️ Deleting installer script...")
        os.remove(script_path)
    except Exception:
        print("⚠️ Could not delete installer script (manual cleanup needed)")

    print("\\n✅ Installation complete!")
    print(f"👉 Run: {folder / 'start_server.pyw'} to start server (double-click works!)")
    print(f"👉 Run: python \"{folder / 'update.py'}\" to update all pyw_mode files anytime (ignored files preserved)")

# -----------------------
if __name__ == "__main__":
    main()
