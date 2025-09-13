# Recon-WebUI

**Recon-WebUI** is a modular reconnaissance toolkit with both a **CLI** and a **Flask-based Web UI**.
It was built as part of an offensive security internship assignment and is designed for passive + light active reconnaissance of domains and IPs.

---

## ✨ Features

- 🔍 **DNS Enumeration** — A, AAAA, MX, NS, TXT, and CNAME records.
- 📑 **WHOIS Lookup** — parsed fields (creation/expiry, name servers, status) + raw output.
- 🌐 **Subdomain Discovery** — passive discovery using [crt.sh](https://crt.sh), with **local JSON caching** (24h TTL).
- 🔓 **Port Scanning & Banner Grabbing** — custom TCP socket scanner for open ports and service banners.
- 🕵️ **Technology Detection** — fingerprinting via service banners, HTTP headers, and HTML content.
- 💻 **Dual Interface**
  - CLI (`cli.py`) — fast command-line usage.
  - Web UI (`web.py`) — user-friendly interactive interface.
- 📥 **Report Export** — download results in **JSON**, **TXT**, or **HTML** format.

---

## Quick start (development)

1. Create & activate a Python virtualenv (recommended):

python3 -m venv venv
source venv/bin/activate

2. Install dependencies:

pip install -r requirements.txt

3. Run the web UI (development):

python web.py
Open: http://127.0.0.1:5000/

4. Use the CLI:

python cli.py example.com --dns

python cli.py example.com --whois

python cli.py example.com --subdomains

combine flags: python cli.py example.com --dns --whois --subdomains

📂 Project Structure
recon_webui/
├── app/
│   ├── __init__.py
│   ├── routes.py
│   ├── templates/
│   │   ├── index.html
│   │   └── report.html
│   └── static/
├── modules/
│   ├── dns_enum.py
│   ├── whois_lookup.py
│   ├── subdomain_enum.py
│   ├── port_scanner.py
│   └── tech_detect.py
├── utils/
│   ├── logger.py
│   └── cache.py
├── cache.json          # created automatically for subdomain caching
├── cli.py
├── web.py
├── requirements.txt
└── README.md

📤 Report Export

After running a scan in the Web UI, you can download results as:

JSON → structured & machine-readable.

TXT → plain text summary.

HTML → styled, printable report.

⚠️ Disclaimer

This tool is intended for educational and authorized penetration testing only.
Do not scan or probe systems without proper permission. Unauthorized use may violate laws.

📜 License
MIT License — Copyright (c) 2025 Aashir Waqar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
