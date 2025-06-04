
# 👁 Sixth Eye – GUI Recon Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20WSL-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-yellow)
![GUI](https://img.shields.io/badge/GUI-CustomTkinter-darkgreen)
![Status](https://img.shields.io/badge/status-active-brightgreen)

Welcome to **Sixth Eye**, a powerful GUI-based reconnaissance toolkit for domain analysis, built with Python, multithreading, and CustomTkinter.

🔗 GitHub: [tansique-17/SixthEye-GUI](https://github.com/tansique-17/SixthEye-GUI)

---

## ⚡ Overview

| Module        | Functionality                                 |
|---------------|-----------------------------------------------|
| 🔍 Subdomains | Subdomain enumeration using `subfinder`       |
| 🌐 WHOIS/RDAP | Fetch WHOIS + RDAP info of domains/IPs        |
| 🌍 ASN        | Get ASN & network data                        |
| 🛠 Port Scan  | Scan & detect services on ports               |
| 🧠 Headers    | View HTTP response headers                    |
| 📜 JavaScript | Extract JavaScript file URLs                 |
| 🔗 Links      | Crawl & extract internal/external links       |

---

## 🛠 Requirements

### ✅ Platform Support

- **Runs on Windows + WSL (Windows Subsystem for Linux)**
- Subfinder and related Linux tools are invoked via `subprocess`, so **WSL is mandatory**

---

## 🧰 Setup Guide

### 1️⃣ Install WSL (if not installed)

```powershell
wsl --install
```

Reboot if required and install **Ubuntu** from the Microsoft Store.

---

### 2️⃣ Inside WSL, run the setup script

```bash
git clone https://github.com/tansique-17/SixthEye-GUI/
cd SixthEye-GUI
chmod +x install.sh
./install.sh
```

This will install:
- `subfinder`
- Python dependencies
- Any additional setup (edit `install.sh` as needed)

---

### 3️⃣ Run the Application (from Windows side)

```bash
python main.py
```

Make sure you're using a Python environment with access to `customtkinter`, `Pillow`, `requests`, `ipwhois`, etc.

---

## 🔍 install.sh (sample content)

```bash
#!/bin/bash

# Update packages
sudo apt update && sudo apt install -y subfinder python3-pip

# Install required Python packages
pip3 install -r requirements.txt
```

---

## 🧠 Author

**Tansique Dasari**  
Cybersecurity Analyst & Recon Automation Developer  
- [LinkedIn](https://linkedin.com/in/tansique-dasari)  
- [HackerOne](https://hackerone.com/tansique-17)  
- [Bugcrowd](https://bugcrowd.com/tansique-17)

---

## 📄 License

Licensed under the MIT License – Open source, free to use with credit.

---

## ⚠️ Disclaimer

This tool is for **educational and ethical testing purposes only**.  
Do **not** use it on systems you do not own or have permission to test.

---
