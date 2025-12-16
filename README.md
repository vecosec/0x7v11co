# 0x7v11co 🛡️

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

**0x7v11co** is an advanced, modular web vulnerability scanner designed for academic research and professional security assessments. It combines a modern, high-performance CLI with detailed HTML/JSON reporting to identify critical security flaws in web applications.

---

## 🚀 Features

### 🔍 Vulnerability Detection
- **SQL Injection (SQLi)**: Detects error-based and boolean-based injection flaws with PoC generation
- **Cross-Site Scripting (XSS)**: Identifies reflected XSS vulnerabilities in forms and parameters
- **Local File Inclusion (LFI)**: Checks for path traversal and file inclusion issues
- **Security Headers**: Analyzes missing or misconfigured HTTP security headers
- **WordPress Enumeration**: Detects WP installations, versions, and user enumeration

### 🕵️ Reconnaissance
- **Proxy & WAF Detection**: Identifies reverse proxies (Cloudflare, Akamai, Nginx, etc.)
- **Subdomain Enumeration**: Discovers subdomains associated with the target
- **Port Scanning**: Checks for open common web ports
- **Directory Enumeration**: Brute-forces common directory paths
- **Web Crawling**: Recursively discovers pages and forms

### ⚡ Advanced Capabilities
- **Modern CLI**: Beautiful terminal UI with ASCII art, progress bars, and live status
- **High Performance**: Multi-threaded architecture for simultaneous scanning
- **Authentication**: Support for session cookies to scan authenticated areas
- **Input Fuzzing**: Fuzzes forms and parameters to trigger server errors
- **PoC Generation**: Automatically generates exploit URLs and cURL commands

### 📊 Reporting
- **Interactive HTML Dashboard**: Dark-mode, responsive report with grouped findings
- **JSON Export**: Raw data export for integration with other tools
- **OWASP Mapping**: Findings mapped to OWASP Top 10 (2021)

---

## 🛠️ Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/0x7v11co.git
    cd 0x7v11co
    ```

2.  **Set up a virtual environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

---

## 📖 Usage

### Standard Scan
Runs a balanced set of checks (Headers, Forms, SQLi, XSS, WP, Dir Enum, Proxy).
```bash
python3 main.py http://example.com
```

### Full Scan (Deep Analysis)
Runs **all** modules with multi-threading.
```bash
python3 main.py http://example.com --full
```

### Fast Scan
Runs lightweight checks for quick reconnaissance.
```bash
python3 main.py http://example.com --fast
```

### Authenticated Scan
Scan behind login pages by providing session cookies.
```bash
python3 main.py http://example.com --cookie "PHPSESSID=12345; security=low"
```

### Export to JSON
Save results for further analysis.
```bash
python3 main.py http://example.com --json
```

### Custom Scan
Mix and match modules:
```bash
python3 main.py http://example.com --xss --lfi --crawl --threads 10
```

---

## 📂 Project Structure

```
0x7v11co/
├── main.py                 # Entry point and orchestrator
├── modules/                # Vulnerability scanner modules
│   ├── base_scanner.py     # Abstract base class
│   ├── sqli_scan.py        # SQL Injection module
│   ├── xss_scan.py         # XSS module
│   ├── proxy_scan.py       # WAF/Proxy detection
│   └── ...
├── utils/                  # Utility scripts
│   ├── reporter.py         # HTML/JSON report generator
│   └── colors.py           # Rich CLI styling
├── requirements.txt        # Dependencies
└── report.html             # Generated report (output)
```


---
