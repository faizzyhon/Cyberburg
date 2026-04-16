# 🔥 CYBERBURG — Advanced Web Penetration Testing Suite

<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗██████╗  ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║██████╔╝██║  ███╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██║   ██║██╔══██╗██║   ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝╚██████╔╝██║  ██║╚██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝
```

**Version 2.0.0 — PHANTOM BLADE**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Linux](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://linux.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-faizzyhon-red.svg)](https://github.com/faizzyhon)

*The ultimate all-in-one web penetration testing framework for professional pentesters*

[GitHub](https://github.com/faizzyhon) • [Instagram](https://instagram.com/faizzyhon) • [Website](https://faizzyhon.online)

</div>

---

> ⚠️ **LEGAL DISCLAIMER**: Cyberburg is designed for **authorized penetration testing, security research, and educational purposes ONLY**. Using this tool against systems you do not have explicit written permission to test is **illegal** and punishable under computer crime laws (CFAA, Computer Misuse Act, etc.). The developer assumes **zero liability** for any misuse. Always obtain **written authorization** before testing any system.

---

## 📋 Table of Contents

1. [What is Cyberburg?](#what-is-cyberburg)
2. [Features](#features)
3. [Architecture](#architecture)
4. [System Requirements](#system-requirements)
5. [Installation](#installation)
6. [Usage Guide](#usage-guide)
7. [Scan Modes](#scan-modes)
8. [Modules In Detail](#modules-in-detail)
9. [Report System](#report-system)
10. [Vulnerability Categories](#vulnerability-categories)
11. [Attack Methodologies](#attack-methodologies)
12. [Configuration](#configuration)
13. [Wordlists & Payloads](#wordlists--payloads)
14. [Output Formats](#output-formats)
15. [Use Cases & Scenarios](#use-cases--scenarios)
16. [Troubleshooting](#troubleshooting)
17. [Contributing](#contributing)
18. [Developer](#developer)
19. [Changelog](#changelog)

---

## What is Cyberburg?

**Cyberburg** is a comprehensive Python-based Linux penetration testing framework that orchestrates **30+ professional security tools** under a single, beautiful terminal interface. Instead of switching between dozens of tools, memorizing their flags, and manually aggregating results, Cyberburg handles everything automatically — running tools in the right sequence, parsing their output, correlating findings, and generating professional PDF-quality HTML security reports.

### Why Cyberburg?

| Problem | Cyberburg Solution |
|---|---|
| 30+ tools, 30+ different syntaxes | Unified interface, zero tool-switching |
| Manual output parsing | Automated finding extraction & deduplication |
| No correlation between tool results | Cross-module finding correlation |
| No professional reports | 3 report formats: HTML, JSON, TXT |
| Forget steps in methodology | Structured attack methodology per engagement type |
| Inconsistent severity ratings | Standardized CRITICAL/HIGH/MEDIUM/LOW/INFO ratings |

---

## Features

### Core Capabilities

```
┌─────────────────────────────────────────────────────────────────────┐
│  RECONNAISSANCE          │  PORT SCANNING & SERVICES               │
│  ─────────────────────── │  ──────────────────────────────────────  │
│  ✔ WHOIS Domain Intel    │  ✔ Quick Scan (Top 1000 ports)          │
│  ✔ DNS Enumeration       │  ✔ Full Scan (All 65535 ports)          │
│  ✔ Zone Transfer Testing │  ✔ Stealth SYN Scan                     │
│  ✔ Subdomain Discovery   │  ✔ UDP Port Scan                        │
│  ✔ Email Harvesting      │  ✔ Service Version Detection            │
│  ✔ IP Geolocation        │  ✔ OS Fingerprinting                    │
│  ✔ ASN Lookup            │  ✔ Firewall/IDS Detection               │
│  ✔ theHarvester OSINT    │  ✔ Nmap Vuln Script Execution           │
├─────────────────────────────────────────────────────────────────────┤
│  WEB APPLICATION         │  VULNERABILITY SCANNING                 │
│  ─────────────────────── │  ──────────────────────────────────────  │
│  ✔ Nikto Web Scanner     │  ✔ SQL Injection (SQLMap + Manual)      │
│  ✔ WhatWeb Fingerprint   │  ✔ XSS Testing (Dalfox + Manual)       │
│  ✔ WAF Detection         │  ✔ DOM XSS Analysis                     │
│  ✔ HTTP Methods Testing  │  ✔ Directory Bruteforce (Gobuster)      │
│  ✔ Security Headers      │  ✔ File Enumeration (FFuf/Dirb)         │
│  ✔ Cookie Analysis       │  ✔ Nuclei Template Scan                 │
│  ✔ CMS Detection         │  ✔ CVE Detection (2000+ templates)      │
│  ✔ robots.txt Analysis   │  ✔ Admin Panel Discovery                │
├─────────────────────────────────────────────────────────────────────┤
│  SSL/TLS ANALYSIS        │  REPORTING                              │
│  ─────────────────────── │  ──────────────────────────────────────  │
│  ✔ Certificate Analysis  │  ✔ Interactive HTML Report              │
│  ✔ Protocol Support      │  ✔ JSON Machine-Readable Output         │
│  ✔ Cipher Suite Testing  │  ✔ Plain Text Report                    │
│  ✔ Heartbleed (CVE-2014) │  ✔ Severity-Based Finding Grouping     │
│  ✔ POODLE Vulnerability  │  ✔ Security Score Card                  │
│  ✔ Self-Signed Cert Check│  ✔ Auto Recommendations                 │
│  ✔ Certificate Expiry    │  ✔ Attack Vector Documentation          │
└─────────────────────────────────────────────────────────────────────┘
```

### Integrated Tools (30+)

| Category | Tools |
|---|---|
| **Network Scanning** | nmap (quick, full, stealth, UDP, vuln scripts) |
| **Web Scanning** | nikto, whatweb, wafw00f |
| **Subdomain Discovery** | subfinder, amass, sublist3r, theHarvester, dig brute |
| **Directory Fuzzing** | gobuster, dirb, ffuf |
| **SQL Injection** | sqlmap (all techniques), manual error testing |
| **XSS** | dalfox, manual payload testing, DOM analysis |
| **SSL/TLS** | sslscan, testssl.sh, openssl |
| **CMS Scanning** | wpscan, manual Joomla/Drupal detection |
| **Vulnerability Templates** | nuclei (2000+ templates), CVE scanning |
| **OSINT** | theHarvester, whois, dig, dnsenum, fierce |
| **Brute Force** | hydra |
| **DNS** | dig, dnsenum, fierce, amass |

---

## Architecture

```
cyberburg/
├── cyberburg.py              # Main entry point & interactive menu
├── modules/
│   ├── recon.py              # WHOIS, DNS, subdomains, email harvesting
│   ├── port_scanner.py       # Nmap all scan modes
│   ├── web_scanner.py        # Nikto, WhatWeb, WAF, headers, CMS
│   ├── sql_injection.py      # SQLMap + manual SQLi testing
│   ├── xss_scanner.py        # Dalfox + manual XSS + DOM XSS
│   ├── dir_bruteforce.py     # Gobuster/Dirb/FFuf/manual paths
│   ├── ssl_analyzer.py       # SSLScan/testssl/OpenSSL analysis
│   ├── nuclei_scan.py        # Nuclei template scanning
│   └── report_gen.py         # HTML/JSON/TXT report generation
├── utils/
│   ├── banner.py             # ASCII art & terminal styling
│   ├── tool_checker.py       # Tool availability detection
│   └── helpers.py            # Utilities, parsers, validators
├── reports/                  # Generated reports (auto-created)
├── requirements.txt          # Python dependencies
├── install.sh                # Automated installation script
└── README.md                 # This file
```

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|---|---|
| **OS** | Linux (Kali, Ubuntu, Debian, Parrot, Arch, Fedora) |
| **Python** | 3.8 or higher |
| **RAM** | 2 GB (4 GB recommended for full scans) |
| **Storage** | 500 MB free (more for SecLists wordlists) |
| **Network** | Internet access for OSINT modules |
| **Privileges** | Sudo/root for stealth scans, SYN scans |

### Recommended Linux Distributions

```
✔ Kali Linux 2023+        (Best — most tools pre-installed)
✔ Parrot Security OS      (Excellent for pentesting)
✔ Ubuntu 20.04/22.04 LTS  (Good — install tools manually)
✔ Debian 11+              (Good)
✔ Arch Linux              (Advanced users)
✔ Fedora / CentOS         (Supported)
```

---

## Installation

### Method 1: Automated Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/faizzyhon/cyberburg.git
cd cyberburg

# Run the installer as root
sudo bash install.sh
```

The install script will automatically:
- Detect your Linux distribution
- Install all APT/DNF/Pacman packages
- Install Python pip packages
- Install Go-based tools (nuclei, subfinder, dalfox, etc.)
- Download SecLists wordlists
- Create a `cyberburg` command symlink
- Verify all critical tools

### Method 2: Manual Installation

#### Step 1: Install Python dependencies

```bash
pip3 install rich requests
```

#### Step 2: Install core Linux tools (Kali/Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y \
    nmap nikto sqlmap gobuster dirb ffuf wpscan sslscan whatweb \
    wafw00f whois dnsutils curl openssl hydra amass theharvester \
    dnsenum wfuzz git golang-go python3-pip
```

#### Step 3: Install pip tools

```bash
pip3 install wafw00f sublist3r wfuzz dnspython fierce beautifulsoup4
```

#### Step 4: Install Go tools (optional but recommended)

```bash
export PATH="$PATH:$HOME/go/bin"
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

#### Step 5: Install SecLists (wordlists)

```bash
# Via apt (Kali)
sudo apt install seclists

# Or clone from GitHub
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

#### Step 6: Make executable

```bash
chmod +x cyberburg.py
# Optional: add to PATH
sudo ln -s $(pwd)/cyberburg.py /usr/local/bin/cyberburg
```

### Method 3: Kali Linux (Everything Pre-Installed)

```bash
# On Kali, most tools are already installed
git clone https://github.com/faizzyhon/cyberburg.git
cd cyberburg
pip3 install -r requirements.txt
python3 cyberburg.py
```

### Verify Installation

```bash
python3 cyberburg.py --tools
```

This displays a table showing which tools are available and which are missing.

---

## Usage Guide

### Interactive Mode (Recommended)

```bash
python3 cyberburg.py
```

This launches the interactive menu:

```
╔══════════════════════════════════════════╗
║         CYBERBURG MAIN MENU              ║
╠══════════════════════════════════════════╣
║  1.  Full Scan (All Modules)             ║
║  2.  Quick Scan (Recon + Web + Ports)    ║
║  3.  Stealth Scan                        ║
║  4.  Custom Scan (Select Modules)        ║
║  5.  Web Vulnerability Only              ║
║  6.  SSL/TLS Analysis Only              ║
║  7.  Reconnaissance Only                 ║
║  8.  Check Tool Availability             ║
║  9.  View Previous Reports               ║
║  0.  Exit                                ║
╚══════════════════════════════════════════╝
```

### Command-Line Mode

```bash
# Full scan (all modules)
python3 cyberburg.py -t https://example.com

# Quick scan
python3 cyberburg.py -t example.com --quick

# Reconnaissance only
python3 cyberburg.py -t example.com --recon

# Web vulnerability scan
python3 cyberburg.py -t https://example.com --web

# SSL/TLS analysis
python3 cyberburg.py -t example.com --ssl

# Stealth scan (bypass IDS/IPS)
python3 cyberburg.py -t 192.168.1.1 --stealth

# Vulnerability scan only
python3 cyberburg.py -t https://example.com --vuln

# Port scan only
python3 cyberburg.py -t 10.0.0.1 --ports

# Check available tools
python3 cyberburg.py --tools

# Scan without generating reports
python3 cyberburg.py -t example.com --no-report
```

### Help

```bash
python3 cyberburg.py --help
```

Output:
```
usage: cyberburg [-h] [-t TARGET] [--full] [--quick] [--stealth]
                 [--recon] [--web] [--ssl] [--vuln] [--ports]
                 [--tools] [--no-report] [-o OUTPUT] [--version]

Cyberburg — Advanced Web Penetration Testing Suite

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target URL, domain, or IP address
  --full                Run full scan (all modules)
  --quick               Quick scan (recon + ports + web)
  --stealth             Stealth mode scan
  --recon               Reconnaissance only
  --web                 Web vulnerability scan only
  --ssl                 SSL/TLS analysis only
  --vuln                Vulnerability scan only
  --ports               Port scan only
  --tools               Check available tools
  --no-report           Skip report generation
  -o, --output OUTPUT   Custom output directory for reports
  --version             show program's version number and exit
```

---

## Scan Modes

### 1. Full Scan — All Modules

**Duration**: 30 minutes — 2+ hours (target dependent)  
**Use case**: Comprehensive security assessment, bug bounty, full pentest engagement

The Full Scan runs every single module in order:

```
Phase 1: RECONNAISSANCE
├── WHOIS lookup
├── DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
├── Zone transfer attempt (AXFR)
├── SPF/DMARC email security check
├── Subdomain enumeration (subfinder + amass + sublist3r + DNS brute)
├── IP Geolocation & ASN mapping
└── Email harvesting (theHarvester)

Phase 2: PORT SCANNING
├── Full port scan (all 65535 TCP ports)
├── Service & version detection
├── OS fingerprinting
├── Nmap vulnerability scripts
├── UDP scan (top 100)
└── Firewall/IDS detection

Phase 3: SSL/TLS ANALYSIS
├── Certificate validity & expiry
├── Certificate chain analysis
├── Protocol support (SSLv2/3, TLS 1.0/1.1/1.2/1.3)
├── Cipher suite analysis
├── Heartbleed (CVE-2014-0160)
└── POODLE (CVE-2014-3566)

Phase 4: WEB APPLICATION SCANNING
├── Technology fingerprinting (WhatWeb)
├── WAF detection (wafw00f)
├── HTTP security headers audit
├── Cookie security analysis
├── HTTP methods testing (PUT/DELETE/TRACE)
├── robots.txt & sitemap.xml analysis
├── CMS detection & scanning (WordPress/Joomla/Drupal)
└── Nikto web vulnerability scan

Phase 5: VULNERABILITY SCANNING
├── Directory bruteforcing (Gobuster/FFuf/Dirb)
├── Sensitive file enumeration (30+ critical paths)
├── API endpoint discovery
├── SQL injection testing (SQLMap + manual probing)
├── XSS testing (Dalfox + manual payloads)
├── DOM XSS source/sink analysis
├── Nuclei template scan (2000+ templates)
├── CVE scanning (Nuclei CVE templates)
└── Admin panel discovery
```

### 2. Quick Scan

**Duration**: 5–15 minutes  
**Use case**: Initial assessment, quick vulnerability overview, CI/CD integration

Runs: Recon → Quick Port Scan → SSL → Web App Scanning (no SQLi/XSS deep testing)

### 3. Stealth Scan

**Duration**: 15–30 minutes  
**Use case**: Evade IDS/IPS/WAF, minimize footprint

```
- SYN stealth scan with random decoys (-D RND:10)
- Slower timing (-T3 instead of T4)
- Limited request rate
- Reduced scan aggressiveness
- No brute-force modules
```

Requires **root privileges** for SYN scanning:
```bash
sudo python3 cyberburg.py -t target.com --stealth
```

### 4. Custom Scan

Launch interactive menu and select option **4** to pick exactly which modules to run:

```
1. Reconnaissance
2. Port Scan — Quick
3. Port Scan — Full
4. SSL/TLS Analysis
5. Web Vulnerability Scan
6. SQL Injection Testing
7. XSS Testing
8. Directory Bruteforce
9. Nuclei Template Scan
```

Example: select `1,2,6,7` to run Recon + Quick Port Scan + SQLi + XSS only.

---

## Modules In Detail

### Reconnaissance Module (`modules/recon.py`)

#### WHOIS Lookup
Extracts registrar info, creation/expiry dates, registrant details, nameservers.

```bash
# Behind the scenes:
whois target.com
```

**Findings generated:**
- Domain registrar
- Creation/expiry dates (expired domains are flagged)
- Registrant contact information
- Nameserver configuration

#### DNS Enumeration
Queries all DNS record types and attempts zone transfer.

**Records queried:** A, AAAA, MX, NS, TXT, SOA, CNAME, SRV

**Security checks:**
- Zone transfer (AXFR) — CRITICAL if allowed
- SPF record presence — MEDIUM if missing
- DMARC record presence — MEDIUM if missing

#### Subdomain Enumeration
Multi-source subdomain discovery:
1. **subfinder** — passive API-based discovery
2. **amass** — comprehensive passive enumeration
3. **sublist3r** — search engine scraping
4. **theHarvester** — multi-source OSINT
5. **DNS brute force** — 40+ common subdomain names

Results are deduplicated and reported.

#### Email Harvesting
Uses theHarvester with sources: google, bing, yahoo, duckduckgo, hackertarget, urlscan, crtsh

Emails found can be used for password spraying assessment or social engineering risk evaluation.

---

### Port Scanner Module (`modules/port_scanner.py`)

#### Dangerous Port Detection
Automatically flags known dangerous/sensitive ports with risk severity:

| Port | Service | Risk |
|---|---|---|
| 21 | FTP | HIGH — plaintext credentials |
| 22 | SSH | INFO — check brute force protection |
| 23 | Telnet | CRITICAL — plaintext everything |
| 445 | SMB | CRITICAL — EternalBlue/ransomware |
| 3306 | MySQL | CRITICAL — database exposed |
| 3389 | RDP | HIGH — BlueKeep risk |
| 6379 | Redis | CRITICAL — usually no auth |
| 9200 | Elasticsearch | CRITICAL — usually no auth |
| 27017 | MongoDB | CRITICAL — usually no auth |

#### Outdated Software Detection
Nmap version detection feeds into a database of vulnerable versions:

- vsftpd 2.3.4 → CRITICAL (backdoor)
- Apache 2.4.49 → CRITICAL (path traversal CVE-2021-41773)
- PHP 5.x → CRITICAL (EOL, unpatched CVEs)
- OpenSSL 1.0.1 → CRITICAL (Heartbleed)
- MySQL 5.0 → HIGH (EOL)

---

### Web Scanner Module (`modules/web_scanner.py`)

#### Security Header Audit
Checks for all OWASP-recommended security headers:

| Header | Missing Severity | Protection |
|---|---|---|
| Strict-Transport-Security | HIGH | Protocol downgrade attacks |
| Content-Security-Policy | MEDIUM | XSS, injection attacks |
| X-Frame-Options | MEDIUM | Clickjacking |
| X-Content-Type-Options | MEDIUM | MIME sniffing |
| Referrer-Policy | LOW | Information leakage |
| Permissions-Policy | LOW | Browser feature abuse |

Also scores information-disclosure headers:
- `Server: Apache/2.4.52` → LOW (version disclosure)
- `X-Powered-By: PHP/7.4.3` → LOW (technology disclosure)

#### Cookie Security Analysis
Every `Set-Cookie` header is checked for:
- `HttpOnly` flag — missing = MEDIUM (JavaScript cookie theft)
- `Secure` flag — missing = MEDIUM (cookie sent over HTTP)
- `SameSite` attribute — missing = LOW (CSRF via cookie)

#### WAF Detection
Uses wafw00f + heuristic signature matching to detect:
Cloudflare, Sucuri, Akamai, Imperva, ModSecurity, F5, Barracuda, AWS WAF, etc.

If **no WAF is detected**: flagged as HIGH severity.

#### HTTP Methods Testing
Tests for enabled dangerous methods:
- `PUT` — CRITICAL if file upload succeeds
- `DELETE` — HIGH
- `TRACE` — MEDIUM (XST attack)
- `CONNECT` — HIGH (tunneling)

---

### SQL Injection Module (`modules/sql_injection.py`)

#### SQLMap Integration
Runs SQLMap with configurable aggressiveness:

**Quick mode** (level 2, risk 1): Tests the most likely injection points quickly  
**Full mode** (level 5, risk 3): Tests ALL parameters with ALL techniques

Techniques tested (BEUSTQ):
- **B**oolean-based blind
- **E**rror-based
- **U**nion query-based
- **S**tacked queries
- **T**ime-based blind
- **Q**uery/inline injection

If vulnerability confirmed → automatically attempts database enumeration.

#### Manual Error-Based Testing
Even without sqlmap, Cyberburg tests common SQL error patterns with payloads:
```
' → SQL syntax error?
" → SQL syntax error?
' OR 1=1-- → Auth bypass?
1 UNION SELECT NULL-- → Union injection?
1' AND SLEEP(3)-- → Time-based blind?
```

Detects 15+ SQL error signatures: MySQL, PostgreSQL, Oracle, MSSQL, SQLite, etc.

---

### XSS Scanner Module (`modules/xss_scanner.py`)

#### Dalfox Integration
State-of-the-art XSS scanner with:
- 20+ concurrent workers
- DOM XSS detection
- Reflected XSS with 500+ payloads
- Blind XSS payload injection
- Context-aware payload generation

#### Manual XSS Probing
Tests 21 hand-crafted payloads across 10 common parameter names:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
<details/open/ontoggle=alert(1)>
```

Verifies actual reflection in response body (not just parameter echo).

#### DOM XSS Analysis
Fetches page source + up to 10 linked JS files, then analyzes:

**Sources checked** (user-controlled inputs):
`document.URL`, `location.hash`, `location.search`, `window.name`, `document.referrer`

**Sinks checked** (dangerous output):
`innerHTML`, `document.write`, `eval()`, `setTimeout()`, `jQuery.html()`

Source + Sink combination = potential DOM XSS (MEDIUM severity).

---

### SSL Analyzer Module (`modules/ssl_analyzer.py`)

#### Certificate Analysis
- Expiry date: warns 30 days before, critical if expired
- Self-signed detection: flagged HIGH
- Certificate CN/SAN verification
- Issuer chain validation

#### Protocol Testing
Tests each protocol via `openssl s_client`:
- SSLv2 → CRITICAL if supported
- SSLv3 → CRITICAL (POODLE)
- TLS 1.0 → CRITICAL (deprecated since 2020)
- TLS 1.1 → HIGH (deprecated)
- TLS 1.2 → INFO (acceptable)
- TLS 1.3 → INFO (ideal)

#### Cipher Suite Analysis
Flags weak ciphers: NULL, EXPORT, DES, RC4, MD5, 3DES, ANON

#### Known Vulnerabilities
- **Heartbleed** (CVE-2014-0160): Memory leak in OpenSSL TLS heartbeat
- **POODLE** (CVE-2014-3566): SSLv3 padding oracle attack

Both tested via dedicated Nmap scripts.

---

### Nuclei Module (`modules/nuclei_scan.py`)

Nuclei is template-based vulnerability scanner with 7000+ community templates.

**What gets scanned:**
- Known CVEs (2015-present)
- Misconfigurations
- Exposed credentials/config files
- Default passwords
- Admin panel exposures
- Technology-specific vulnerabilities
- Cloud service misconfigurations

**Template categories used:**
`cve`, `tech`, `panel`, `login`, `admin`, `exposure`, `misconfiguration`

---

### Directory Bruteforce Module (`modules/dir_bruteforce.py`)

#### Wordlist Priority
Cyberburg automatically finds the best available wordlist:

```
1. /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
2. /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
3. /usr/share/wordlists/dirb/common.txt
4. Embedded 60-word critical paths list (fallback)
```

#### Manual Critical Path Check
Always checks 30+ high-value paths regardless of wordlist:

```
/.env                 — CRITICAL (credentials)
/.git/config          — CRITICAL (source code)
/wp-config.php        — CRITICAL (WordPress credentials)
/phpinfo.php          — HIGH (server info disclosure)
/phpmyadmin/          — HIGH (database admin panel)
/backup.sql           — CRITICAL (database backup)
/.htpasswd            — CRITICAL (plaintext passwords)
/server-status        — HIGH (Apache status page)
/api/v1/              — MEDIUM (API exposure)
/graphql              — MEDIUM (GraphQL endpoint)
```

---

## Report System

### HTML Report

The flagship report format — a professional, dark-themed HTML document with:

**Executive Summary**
- Target information
- Risk rating (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Scan timeline
- Total finding counts

**Visual Dashboard**
- Doughnut chart (severity distribution)
- Stat cards per severity level
- Color-coded risk banner

**Detailed Findings**
- Grouped by scan module
- Each finding shows: severity badge, finding type, description
- Color-coded by severity (red=critical, orange=high, yellow=medium, cyan=low)

**Attack Vectors Used**
- Documents exactly which attack techniques were applied

**Recommendations**
- Automatically generated based on findings
- Actionable remediation steps

**Legal Footer**
- Authorized testing disclaimer
- Developer attribution

```bash
# Open the report
firefox reports/cyberburg_example.com_20240115_143022.html
```

### JSON Report

Machine-readable output for integration with ticketing systems, dashboards, etc.

```json
{
  "meta": {
    "tool": "Cyberburg",
    "version": "2.0.0",
    "developer": "Faiz Zyhon",
    "github": "github.com/faizzyhon"
  },
  "target": "https://example.com",
  "risk_rating": "HIGH",
  "summary": {
    "CRITICAL": 2,
    "HIGH": 8,
    "MEDIUM": 15,
    "LOW": 23,
    "INFO": 47
  },
  "findings": [
    {
      "type": "SQL Injection Vulnerable Parameter",
      "value": "Parameter 'id' is vulnerable to SQL injection",
      "severity": "CRITICAL",
      "module": "SQL Injection Scan (Quick)"
    }
  ]
}
```

### Text Report

Clean plaintext output suitable for:
- Email attachments
- Copying into ticketing systems
- Terminal review

---

## Vulnerability Categories

### CRITICAL
Immediate exploitation possible. Treat as P0 emergency.

- SQL Injection with data extraction confirmed
- Remote Code Execution
- Exposed `.env` or config files with credentials
- Zone transfer allowed (full DNS enumeration)
- Default credentials accepted
- Heartbleed / known critical CVEs
- SSLv2/SSLv3 support enabled
- Database directly exposed to internet (Redis, MongoDB, MySQL)

### HIGH
Significant risk. Fix within 24–72 hours.

- XSS vulnerability confirmed
- Dangerous ports exposed (SMB, RDP, Telnet)
- Missing HSTS header
- Outdated software (EOL versions)
- Weak TLS 1.0/1.1 support
- Admin panels accessible
- Backup files exposed
- No WAF protection

### MEDIUM
Moderate risk. Fix within 1–2 weeks.

- Missing security headers (CSP, X-Frame-Options)
- Cookie flags missing (HttpOnly, Secure)
- Missing SPF/DMARC records
- HTTP methods (TRACE enabled)
- Directory listing enabled
- Information disclosure headers

### LOW
Low exploitability but should be fixed.

- Server version disclosure
- Missing Referrer-Policy
- Directory structure revealed via robots.txt
- Minor SSL issues

### INFO
Informational findings with no immediate risk.

- Technologies detected
- Open ports (standard services)
- DNS records
- Subdomain inventory

---

## Attack Methodologies

### Web Application Pentest Methodology

Cyberburg follows the OWASP Testing Guide and PTES methodology:

```
1. Information Gathering
   ├── Passive: WHOIS, DNS, OSINT, subdomains
   └── Active: Port scan, service detection, fingerprinting

2. Configuration & Deployment Management
   ├── HTTP methods testing
   ├── Security headers audit
   └── SSL/TLS configuration

3. Authentication Testing
   ├── Default credentials (Nuclei)
   ├── Admin panel discovery
   └── Login form analysis

4. Authorization Testing
   ├── HTTP method abuse (PUT/DELETE)
   └── Directory traversal

5. Session Management
   └── Cookie security flags

6. Input Validation
   ├── SQL Injection
   ├── Cross-Site Scripting (XSS)
   └── DOM-based XSS

7. Error Handling
   └── SQL error messages
   └── Verbose error pages

8. Cryptography
   └── SSL/TLS complete analysis

9. Business Logic
   └── Nuclei custom templates

10. Client-Side Testing
    ├── DOM XSS
    └── eval() usage analysis
```

---

## Configuration

### Environment Variables

```bash
# Customize scan behavior
export CYBERBURG_TIMEOUT=300          # Default command timeout (seconds)
export CYBERBURG_THREADS=50           # Gobuster/FFuf thread count
export CYBERBURG_OUTPUT_DIR=~/reports # Custom reports directory
```

### Custom Wordlists

Place custom wordlists in any of these locations and Cyberburg will auto-detect them:

```
/usr/share/wordlists/dirb/common.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Or pass custom wordlist to gobuster manually and integrate via the modules.

---

## Wordlists & Payloads

### XSS Payloads (Built-in)
21 carefully selected XSS payloads covering:
- Basic script injection
- HTML event handlers
- SVG-based payloads
- URL-encoded variants
- Case-variation bypass
- HTML entity encoding bypass
- Comment-based bypass

### SQL Injection Payloads (Built-in)
11 error-triggering SQLi payloads:
- Basic quote injection
- Boolean-based
- Time-based
- UNION-based
- URL-encoded variants

### Critical Paths (Built-in)
30+ hardcoded sensitive paths always checked:
Config files, git directories, backup files, admin panels, database dumps, etc.

---

## Output Formats

### Report File Naming
```
reports/cyberburg_{target}_{timestamp}.html
reports/cyberburg_{target}_{timestamp}.json
reports/cyberburg_{target}_{timestamp}.txt
```

Example:
```
reports/cyberburg_example_com_20240115_143022.html
reports/cyberburg_example_com_20240115_143022.json
reports/cyberburg_example_com_20240115_143022.txt
```

### Directory Structure After Scan
```
reports/
├── cyberburg_example_com_20240115_143022.html    ← Open in browser
├── cyberburg_example_com_20240115_143022.json    ← API/integration
└── cyberburg_example_com_20240115_143022.txt     ← Plain text
```

---

## Use Cases & Scenarios

### Scenario 1: Bug Bounty Hunting

```bash
# Step 1: Initial recon
python3 cyberburg.py -t target.com --recon

# Step 2: Full web vulnerability scan
python3 cyberburg.py -t https://target.com --web

# Step 3: Nuclei for quick CVE hits
python3 cyberburg.py -t https://target.com --vuln

# Review HTML report for findings to submit
```

### Scenario 2: Client Pentest Engagement

```bash
# Full scan with professional HTML report
sudo python3 cyberburg.py -t https://client.com

# Report is ready at reports/ for client delivery
```

### Scenario 3: Internal Network Assessment

```bash
# Scan internal web server
python3 cyberburg.py -t 192.168.10.50

# Focus on ports and services
python3 cyberburg.py -t 192.168.10.0/24 --ports
```

### Scenario 4: Pre-Production Security Check

```bash
# Quick scan before deployment
python3 cyberburg.py -t https://staging.myapp.com --quick

# Check SSL specifically
python3 cyberburg.py -t staging.myapp.com --ssl
```

### Scenario 5: Red Team Engagement

```bash
# Maximum stealth
sudo python3 cyberburg.py -t target.org --stealth

# Custom modules only — avoid triggering IDS
python3 cyberburg.py -t target.org
# Select option 4 (Custom), then 1,4,5 only
```

### Scenario 6: CTF Competition

```bash
# Full scan on CTF target
python3 cyberburg.py -t 10.10.10.x

# Usually reveals: open ports, web vulnerabilities, SQLi, LFI paths
```

---

## Troubleshooting

### Common Issues & Fixes

#### `rich` module not found
```bash
pip3 install rich
# or
pip install rich
```

#### Tools not found / missing
```bash
# Check what's missing
python3 cyberburg.py --tools

# Install missing tools
sudo apt install nmap nikto sqlmap gobuster
```

#### Permission denied for stealth scan
```bash
# Stealth SYN scans require root
sudo python3 cyberburg.py -t target.com --stealth
```

#### Scan hangs or takes too long
- Use `--quick` instead of full scan
- Use `Ctrl+C` to interrupt — partial results will still be reported
- Reduce nmap timing: edit `port_scanner.py`, change `-T4` to `-T3`

#### No findings on HTTPS target
```bash
# Ensure full URL with https://
python3 cyberburg.py -t https://example.com
# NOT: python3 cyberburg.py -t example.com
```

#### SQLMap not finding injections
SQLMap is conservative by default. Manual testing with `--web` flag uses direct curl probing that may find error-based SQLi even when SQLMap misses it.

#### Reports directory permission error
```bash
mkdir -p reports
chmod 755 reports
```

#### Go tools not in PATH after install
```bash
export PATH="$PATH:$HOME/go/bin"
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc
```

#### wafw00f command not found
```bash
pip3 install wafw00f
# Test: wafw00f --version
```

### Debug Mode
For verbose output and stack traces:
```bash
python3 cyberburg.py -t target.com 2>&1 | tee cyberburg_debug.log
```

---

## Contributing

Contributions are welcome! Here's how to add a new module:

### Adding a New Scan Module

1. Create `modules/your_module.py`
2. Follow the standard return format:
```python
def your_scan(target: str) -> dict:
    return {
        "module": "Your Module Name",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",          # Raw tool output
        "findings": [       # List of findings
            {
                "type": "Finding Type",
                "value": "Finding description",
                "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO"
            }
        ]
    }
```
3. Import and call in `cyberburg.py` inside the appropriate run function
4. Submit a PR to [github.com/faizzyhon](https://github.com/faizzyhon)

### Module Development Guidelines
- Always check if the tool is available using `check_tool()`
- Set reasonable timeouts (never infinite)
- Handle exceptions gracefully
- Provide a fallback when the primary tool is missing
- Parse all severity levels correctly

---

## Developer

<div align="center">

**Faiz Zyhon**

*Security Researcher & Tool Developer*

| Platform | Link |
|---|---|
| GitHub | [github.com/faizzyhon](https://github.com/faizzyhon) |
| Instagram | [instagram.com/faizzyhon](https://instagram.com/faizzyhon) |
| Website | [faizzyhon.online](https://faizzyhon.online) |

</div>

Cyberburg was built out of frustration with switching between 30+ tools during engagements. The vision: one tool, one interface, one report — professional quality output every time.

### Support the Project

If Cyberburg helped you find vulnerabilities, win a CTF, or deliver a better pentest report:
- ⭐ Star the repository on GitHub
- Share with your security community
- Submit issues or pull requests
- Follow on Instagram for updates

---

## Changelog

### v2.0.0 — PHANTOM BLADE (Current)
- Complete rewrite in Python with Rich TUI
- Added 8 scan modules (recon, ports, web, SSL, SQLi, XSS, dir, nuclei)
- Professional HTML report with Chart.js visualization
- JSON + TXT report formats
- Interactive menu + CLI argument modes
- 30+ tool integrations
- Automatic tool availability detection
- Stealth scan mode
- Custom scan module selection

### v1.0.0 — INITIAL RELEASE
- Basic reconnaissance
- Port scanning via nmap
- Nikto web scan
- Simple text output

---

## License

MIT License — see [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Faiz Zyhon (github.com/faizzyhon)

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
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

<div align="center">

**⚠️ AUTHORIZED SECURITY TESTING ONLY ⚠️**

*Cyberburg is a tool for professional security researchers and pentesters.*  
*Always obtain written permission before testing any system.*  
*Unauthorized testing is illegal and unethical.*

---

Made with ❤️ by **Faiz Zyhon**

[github.com/faizzyhon](https://github.com/faizzyhon) • [instagram.com/faizzyhon](https://instagram.com/faizzyhon) • [faizzyhon.online](https://faizzyhon.online)

*"The best security comes from understanding the attacker's perspective"*

</div>
