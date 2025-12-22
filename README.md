 
# Python Web Server Best

A simple, one-click Python web server installer and updater.  
This project provides a minimal web server setup with optional packages and a built-in updater.

## Features

- One-file installer (`SetUp_3.py`) that:
  - Downloads `start_server.py` from GitHub
  - Creates a `www/` folder with an index page and favicon
  - Generates a minimal `server_config.json`
  - Installs optional Python packages: `qrcode[pil]`, `pystray`
  - Automatically creates an updater (`update.py`)
  - Deletes itself after successful installation

- Updater (`update.py`) that:
  - Downloads the latest `start_server.py`
  - Keeps your server up-to-date with a single run

## Installation

1. Download `SetUp_3.py` from this repository.
2. Run the installer:

```bash
python SetUp_3.py
````

3. Enter the full path where you want to install the server.
4. After installation, `SetUp_3.py` will delete itself automatically.
5. Run the server:

```bash
python start_server.py
```

## Updating the Server

To update `start_server.py` to the latest version:

```bash
python update.py
```

This will overwrite the old `start_server.py` with the latest release from GitHub.

## Folder Structure

After installation:

```
your_install_folder/
├─ start_server.py
├─ update.py
├─ www/
│  ├─ index.html
│  └─ favicon.png
└─ server_config.json
```

## Optional Packages

To use QR code generation or tray icons, the installer tries to install:

```bash
pip install qrcode[pil] pystray
```

If it fails, you can install them manually.



## Demo

[Python Web Server Demo](https://vimeo.com/1148539000?share=copy&fl=sv&fe=ci)
