# CYBERBURG — Advanced Web Penetration Testing Suite

<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗██████╗  ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║██████╔╝██║  ███╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██║   ██║██╔══██╗██║   ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝╚██████╔╝██║  ██║╚██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝
```

**Version 5.0.0 — PHANTOM PROTOCOL**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Linux](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-orange.svg)](https://linux.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-faizzyhon-red.svg)](https://github.com/faizzyhon)
[![Modules](https://img.shields.io/badge/Modules-22-brightgreen.svg)](#)
[![Tools](https://img.shields.io/badge/Tools-40%2B-blue.svg)](#)

*The ultimate all-in-one web penetration testing framework for professional pentesters*

[GitHub](https://github.com/faizzyhon) • [Instagram](https://instagram.com/faizzyhon) • [Website](https://faizzyhon.online)

</div>

---

> **LEGAL DISCLAIMER**: Cyberburg is designed for **authorized penetration testing, security research, and educational purposes ONLY**. Using this tool against systems you do not have explicit written permission to test is **illegal** and punishable under computer crime laws (CFAA, Computer Misuse Act, etc.). The developer assumes **zero liability** for any misuse. Always obtain **written authorization** before testing any system.

---

## Table of Contents

1. [What is Cyberburg?](#what-is-cyberburg)
2. [Version History Overview](#version-history-overview)
3. [Features at a Glance](#features-at-a-glance)
4. [Architecture](#architecture)
5. [System Requirements](#system-requirements)
6. [Installation](#installation)
7. [Usage Guide](#usage-guide)
8. [Interactive Menu Reference](#interactive-menu-reference)
9. [CLI Reference](#cli-reference)
10. [Scan Modes (1–8)](#scan-modes-18)
11. [v3 Modules — GHOST PROTOCOL](#v3-modules--ghost-protocol)
12. [v4 Modules — DARK MATTER](#v4-modules--dark-matter)
13. [v5 Modules — PHANTOM PROTOCOL](#v5-modules--phantom-protocol)
14. [Output Folder System](#output-folder-system)
15. [Report System](#report-system)
16. [Threat Intelligence API Keys](#threat-intelligence-api-keys)
17. [Attack Methodology](#attack-methodology)
18. [Use Cases & Scenarios](#use-cases--scenarios)
19. [Troubleshooting](#troubleshooting)
20. [Developer](#developer)
21. [Changelog](#changelog)

---

## What is Cyberburg?

**Cyberburg** is a comprehensive Python-based penetration testing framework that orchestrates **40+ professional security tools** under a single, unified terminal interface. Instead of switching between dozens of tools, memorizing their flags, and manually aggregating results, Cyberburg handles everything automatically — running tools in the right sequence, parsing their output, correlating findings, and generating professional HTML security reports.

Starting from a basic web scanner (v1), Cyberburg has evolved through 5 major versions into a full-spectrum offensive security platform covering everything from passive OSINT to active exploitation, database dumping, AI-powered analysis, network-wide discovery, WAF evasion, and threat intelligence enrichment.

---

## Version History Overview

| Version | Codename | Added |
|---------|----------|-------|
| v1.0.0 | Initial Release | 9 scan modes, 30+ tool integrations, HTML/JSON/TXT reports |
| v2.0.0 | PHANTOM BLADE | Web dashboard, authentication tester, bug bounty report auto-generation |
| v3.0.0 | GHOST PROTOCOL | Exploit engine (SQLi dump, admin takeover, LFI, CMDi, file upload), data harvester (JS secrets, config leaks, git exposure, backup files), organized output folder system |
| v4.0.0 | DARK MATTER | God Mode 12-vector elite attack chain, CVE intelligence lookup, Claude AI expert analysis, screenshot capture, Metasploit resource script generation |
| **v5.0.0** | **PHANTOM PROTOCOL** | **Network mapper (CIDR scan), API security tester, WAF bypass engine, threat intelligence (AbuseIPDB/Shodan/crt.sh), password auditor (hash cracking + spray)** |

---

## Features at a Glance

```
┌────────────────────────────────────────────────────────────────────────────┐
│  CORE SCANNING (v1-v2)          │  EXPLOITATION (v3)                       │
│  ─────────────────────────────  │  ──────────────────────────────────────  │
│  WHOIS / DNS / Subdomains        │  SQLMap full DB dump                     │
│  Port Scan (quick/full/stealth)  │  Admin panel default-cred takeover       │
│  SSL/TLS complete analysis       │  LFI / Path Traversal exploitation       │
│  WAF detection                   │  Command injection testing               │
│  Security headers audit          │  File upload / webshell detection        │
│  SQL injection (SQLMap+manual)   │  JS secrets & API key harvesting         │
│  XSS (Dalfox+DOM+manual)        │  Config file exposure (.env, wp-config)  │
│  Directory bruteforce            │  Git repo exposure & git-dumper          │
│  Nuclei template scanning        │  Backup file detection & download        │
│  Authentication testing          │  Sensitive endpoint discovery            │
│  Bug Bounty report auto-gen      │  Organized output/<target>/ folder       │
├────────────────────────────────────────────────────────────────────────────┤
│  ELITE ATTACKS (v4)             │  PHANTOM PROTOCOL (v5) — NEW             │
│  ─────────────────────────────  │  ──────────────────────────────────────  │
│  GOD MODE: 12-vector chain       │  Network Mapper (CIDR/ARP/OS detect)    │
│   SSRF cloud metadata            │  API Security Tester                     │
│   XXE injection                  │   BOLA/IDOR numeric ID fuzzing           │
│   IDOR numeric ID fuzzing        │   Mass assignment (isAdmin, role)        │
│   JWT alg:none + HMAC brute      │   Rate limiting bypass check             │
│   CORS misconfiguration          │   GraphQL introspection + injection      │
│   Open redirect (16 params)      │   Sensitive data leak scan               │
│   Host header injection          │  WAF Bypass Engine                       │
│   HTTP verb tampering            │   8 encoding techniques (URL/hex/etc)    │
│   Request smuggling probe        │   HTTP parameter pollution               │
│   Business logic flaws           │   IP-spoofing header bypass              │
│   Subdomain takeover check       │  Threat Intelligence                     │
│   Prototype pollution            │   IP reputation (AbuseIPDB)              │
│  CVE Intelligence (NVD API)      │   Certificate transparency (crt.sh)      │
│  Claude AI expert analysis       │   Passive DNS (HackerTarget)             │
│  Screenshot capture              │   Shodan InternetDB (free)               │
│  Metasploit .rc script gen       │   DNS blacklist check (7 lists)          │
│                                  │   VirusTotal (optional API key)          │
│                                  │  Password Auditor                        │
│                                  │   Hash extraction from findings          │
│                                  │   John the Ripper / Hashcat integration  │
│                                  │   150+ default credential pairs          │
│                                  │   Password spray (slow, safe)            │
│                                  │   Password policy weakness check         │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Architecture

```
cyberburg/
├── cyberburg.py                    # Main entry point, interactive menu, CLI
│
├── modules/
│   ├── recon.py                    # WHOIS, DNS, subdomains, email harvesting
│   ├── port_scanner.py             # Nmap: quick/full/stealth/UDP/vuln/firewall
│   ├── web_scanner.py              # Nikto, WhatWeb, WAF, headers, CMS, robots
│   ├── ssl_analyzer.py             # SSLScan, testssl, OpenSSL, Heartbleed, POODLE
│   ├── sql_injection.py            # SQLMap (quick/full/POST) + manual probing
│   ├── xss_scanner.py              # Dalfox, DOM XSS, manual payloads
│   ├── dir_bruteforce.py           # Gobuster/Dirb/FFuf, manual critical paths
│   ├── nuclei_scan.py              # Nuclei CVE + panel + exposure templates
│   ├── report_gen.py               # HTML/JSON/TXT report generation
│   ├── auth_tester.py              # Login brute-force, default creds, MFA check [v2]
│   ├── bug_bounty_report.py        # Auto bug bounty report on CRITICAL finds [v2]
│   ├── exploit_engine.py           # SQLi dump, admin takeover, LFI, CMDi [v3]
│   ├── data_harvester.py           # JS secrets, configs, git, backups, endpoints [v3]
│   ├── god_mode.py                 # 12-vector elite attack chain [v4]
│   ├── cve_lookup.py               # CVE intelligence + NVD API [v4]
│   ├── ai_analyst.py               # Claude AI expert analysis [v4]
│   ├── screenshot.py               # Headless screenshot capture [v4]
│   ├── metasploit_integration.py   # Metasploit .rc resource script [v4]
│   ├── network_mapper.py           # CIDR scan, ARP, OS fingerprint [v5]
│   ├── api_tester.py               # REST/GraphQL API security [v5]
│   ├── waf_bypass.py               # WAF evasion engine [v5]
│   ├── threat_intel.py             # IP rep, crt.sh, Shodan, DNSBL [v5]
│   └── password_auditor.py         # Hash cracking, spray, default creds [v5]
│
├── utils/
│   ├── banner.py                   # ASCII art & terminal styling
│   ├── tool_checker.py             # Tool availability detection
│   └── helpers.py                  # Utilities, parsers, validators, output_dir
│
├── dashboard/                      # Flask web dashboard [v2]
├── templates/                      # HTML report templates
├── wordlists/                      # Built-in wordlists
├── output/                         # Auto-created scan output folders
├── reports/                        # Generated reports
├── bug_bounty_reports/             # Auto-generated bug bounty reports
├── requirements.txt
├── install.sh
└── README.md
```

---

## System Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Linux (Kali, Ubuntu, Debian, Parrot) or Windows 10/11 |
| **Python** | 3.8 or higher |
| **RAM** | 2 GB minimum (4 GB recommended for full scans) |
| **Storage** | 1 GB free (more for wordlists and output) |
| **Network** | Internet access for OSINT, CVE, and threat intel modules |
| **Privileges** | Root/sudo required for stealth scans and ARP scanning |

### Recommended Distributions

```
Kali Linux 2023+        — Best (most tools pre-installed)
Parrot Security OS      — Excellent
Ubuntu 20.04/22.04 LTS  — Good (install tools manually)
Debian 11+              — Good
Windows 10/11           — Supported (Python-only modules work fully)
```

---

## Installation

### Method 1: Automated Install (Linux, Recommended)

```bash
git clone https://github.com/faizzyhon/cyberburg.git
cd cyberburg
sudo bash install.sh
```

The script auto-installs all APT packages, Go tools, pip packages, and SecLists wordlists, then creates a `cyberburg` symlink.

### Method 2: Manual Install

```bash
# 1. Python dependencies
pip3 install rich requests flask beautifulsoup4 anthropic

# 2. Core tools (Kali / Ubuntu / Debian)
sudo apt install -y \
    nmap nikto sqlmap gobuster dirb ffuf wpscan sslscan whatweb \
    wafw00f whois dnsutils curl openssl hydra amass theharvester \
    dnsenum wfuzz git golang-go arp-scan john hashcat

# 3. Go tools
export PATH="$PATH:$HOME/go/bin"
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/OJ/gobuster/v3@latest

# 4. SecLists wordlists
sudo apt install seclists
# or: sudo git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists

# 5. Make executable
chmod +x cyberburg.py
sudo ln -s $(pwd)/cyberburg.py /usr/local/bin/cyberburg
```

### Method 3: Windows (Python modules only)

```cmd
pip install rich requests flask beautifulsoup4 anthropic
python cyberburg.py
```

> On Windows, modules that wrap Linux CLI tools (nmap, sqlmap, gobuster, etc.) require those tools to be installed and in PATH. Pure-Python modules (data harvester, API tester, WAF bypass, threat intel, password auditor) work natively.

### Verify Installation

```bash
python3 cyberburg.py --tools
```

---

## Usage Guide

### Interactive Mode (Recommended)

```bash
python3 cyberburg.py
```

### CLI Mode

```bash
# Full scan (all modules)
python3 cyberburg.py -t https://example.com

# Quick scan
python3 cyberburg.py -t example.com --quick

# Specific module
python3 cyberburg.py -t example.com --recon
python3 cyberburg.py -t example.com --web
python3 cyberburg.py -t example.com --ssl
python3 cyberburg.py -t example.com --vuln
python3 cyberburg.py -t example.com --ports
python3 cyberburg.py -t example.com --stealth
python3 cyberburg.py -t example.com --auth

# v3 modules
python3 cyberburg.py -t example.com --exploit
python3 cyberburg.py -t example.com --harvest

# v4 modules
python3 cyberburg.py -t example.com --god-mode
python3 cyberburg.py -t example.com --cve
python3 cyberburg.py -t example.com --ai
python3 cyberburg.py -t example.com --screenshot
python3 cyberburg.py -t example.com --msf

# v5 modules
python3 cyberburg.py -t example.com --network
python3 cyberburg.py -t example.com --api
python3 cyberburg.py -t example.com --waf-bypass
python3 cyberburg.py -t example.com --threat
python3 cyberburg.py -t example.com --passwords

# Utility
python3 cyberburg.py --tools
python3 cyberburg.py --dashboard
python3 cyberburg.py -t example.com --no-report
python3 cyberburg.py -t example.com -o /custom/output/path
python3 cyberburg.py --version
```

---

## Interactive Menu Reference

```
╔═════════════════════════════════════════════╗
║      CYBERBURG v5 — PHANTOM PROTOCOL        ║
╠═════════════════════════════════════════════╣
║  1.   Full Scan (All Modules)               ║
║  2.   Quick Scan (Recon + Web + Ports)      ║
║  3.   Stealth Scan                          ║
║  4.   Custom Scan (Select Modules)          ║
║  5.   Web Vulnerability Only                ║
║  6.   SSL/TLS Analysis Only                 ║
║  7.   Reconnaissance Only                   ║
║  8.   Authentication Testing                ║
╠═════════════════════════════════════════════╣
║  11.  Exploit Mode (v3 Auto Attacks)        ║
║  12.  Data Harvesting (v3 Secrets & Loot)   ║
║  13.  GOD MODE — Elite Attack Chain (v4)    ║
║  14.  CVE Intelligence Lookup (v4)          ║
║  15.  AI Analysis — Claude Expert (v4)      ║
║  16.  Screenshot Capture (v4)               ║
║  17.  Metasploit Integration (v4)           ║
╠═════════════════════════════════════════════╣
║  18.  Network Mapper — CIDR Scan (v5)       ║
║  19.  API Security Tester (v5)              ║
║  20.  WAF Bypass Engine (v5)                ║
║  21.  Threat Intelligence (v5)              ║
║  22.  Password Auditor (v5)                 ║
╠═════════════════════════════════════════════╣
║  9.   Check Tool Availability               ║
║  10.  View Previous Reports                 ║
║  O.   Open Output Folder                    ║
║  K.   Configure AI API Key                  ║
║  D.   Launch Web Dashboard (localhost)      ║
║  0.   Exit                                  ║
╚═════════════════════════════════════════════╝
```

### Custom Scan (Option 4)

Option 4 lets you cherry-pick any combination of all 22 modules:

```
Enter selection: 1,2,5,14,21
→ Runs: Recon + Quick Port Scan + Web Vuln + CVE Lookup + Threat Intel
```

---

## CLI Reference

| Flag | Version | Description |
|------|---------|-------------|
| `-t`, `--target` | v1 | Target URL, domain, or IP |
| `--full` | v1 | Run all scan modules |
| `--quick` | v1 | Recon + ports + web (fast) |
| `--stealth` | v1 | Low-noise SYN scan mode |
| `--recon` | v1 | Reconnaissance only |
| `--web` | v1 | Web vulnerability scan |
| `--ssl` | v1 | SSL/TLS analysis only |
| `--vuln` | v1 | Vulnerability scan (SQLi, XSS, dirs, nuclei) |
| `--ports` | v1 | Port scan only |
| `--auth` | v2 | Authentication testing |
| `--login-url` | v2 | Login page URL for auth testing |
| `--username` | v2 | Username for auth testing |
| `--password` | v2 | Password for auth testing |
| `--exploit` | v3 | Automated exploitation (SQLi dump, LFI, CMDi) |
| `--harvest` | v3 | Data harvesting (JS secrets, configs, git, backups) |
| `--god-mode` | v4 | Elite 12-vector attack chain |
| `--cve` | v4 | CVE intelligence lookup |
| `--ai` | v4 | Claude AI expert analysis |
| `--screenshot` | v4 | Screenshot all discovered pages |
| `--msf` | v4 | Generate Metasploit .rc resource script |
| `--network` | v5 | Network/CIDR range mapping |
| `--api` | v5 | REST/GraphQL API security testing |
| `--waf-bypass` | v5 | WAF bypass engine |
| `--threat` | v5 | Threat intelligence sweep |
| `--passwords` | v5 | Password auditor (hashes + spray) |
| `--tools` | v1 | Check tool availability |
| `--dashboard` | v2 | Launch web dashboard |
| `--no-report` | v1 | Skip report generation |
| `-o`, `--output` | v3 | Custom output directory |
| `--version` | v1 | Show version |

---

## Scan Modes (1–8)

### 1. Full Scan

**Duration**: 30 min – 2+ hours | **Use case**: Full pentest engagement, bug bounty

Runs all base modules in sequence:

```
Phase 1: RECONNAISSANCE
  WHOIS → DNS (all record types + zone transfer) → Subdomain enum
  → IP geolocation → Email harvesting

Phase 2: PORT SCANNING
  Full scan (65535 ports) → Service version detection
  → OS fingerprinting → Nmap vuln scripts → UDP scan → Firewall detection

Phase 3: SSL/TLS
  Certificate analysis → Protocol testing (SSLv2/3, TLS 1.0–1.3)
  → Cipher suites → Heartbleed → POODLE

Phase 4: WEB APPLICATION
  WhatWeb → WAF detection → Security headers → Cookie flags
  → HTTP methods → robots.txt → CMS scan → Nikto

Phase 5: VULNERABILITY SCANNING
  Gobuster dir brute → Manual critical paths → API fuzzing
  → SQLMap → Manual SQLi probes → Dalfox XSS → DOM XSS
  → Nuclei CVE templates → Nuclei panel templates
```

### 2. Quick Scan

**Duration**: 5–15 min | **Use case**: Initial triage, CI/CD

Recon → Quick port scan (top 1000) → SSL → Web scan (no deep SQLi/XSS)

### 3. Stealth Scan

**Duration**: 15–30 min | **Requires**: root/sudo

```bash
sudo python3 cyberburg.py -t target.com --stealth
```

Uses: SYN stealth scan, slow timing (-T3), random decoys, no brute force. Minimizes IDS/IPS detection.

### 4. Custom Scan

Interactive module picker. Select any combination from all 22 available modules by number:

```
Example: 1,5,6,7,19,21
→ Recon + Web vuln + SQLi + XSS + API tester + Threat intel
```

### 5. Web Vulnerability Only

Web scanner + full vulnerability scan (SQLi, XSS, dirs, nuclei) — skips port scan and recon.

### 6. SSL/TLS Analysis Only

Deep SSL/TLS analysis: certificates, protocols, ciphers, Heartbleed, POODLE.

### 7. Reconnaissance Only

WHOIS, DNS, subdomain enumeration, IP geolocation, email harvesting — completely passive.

### 8. Authentication Testing

Discovers login panels → tests configurable credential pairs → checks MFA signals → checks lockout policy.

```bash
# With known credentials
python3 cyberburg.py -t https://example.com --auth \
  --login-url https://example.com/login \
  --username admin --password password123
```

---

## v3 Modules — GHOST PROTOCOL

### 11. Exploit Mode (`--exploit`)

Automated post-discovery exploitation chain:

| Sub-module | What it does |
|-----------|--------------|
| **SQLi DB Dump** | SQLMap full exploitation → enumerate DBs → find credential tables → dump to `loot/sqlmap_dump/` |
| **Admin Takeover** | Discover admin panels → test 24 default credential pairs → save session cookies on success |
| **LFI Exploit** | Test 14 path traversal payloads × 16 parameters → save extracted files (`/etc/passwd`, etc.) |
| **Command Injection** | Test 10 CMDi payloads (reflected + blind timing) → confirm `uid=` output |
| **File Upload** | Detect upload endpoints → test `.txt` and `.php` uploads → flag RCE |

All loot saved to `output/<target>/loot/`.

Bug bounty report auto-generated when CRITICAL findings occur.

### 12. Data Harvesting (`--harvest`)

Automated sensitive data collection:

| Sub-module | What it finds |
|-----------|---------------|
| **JS Secrets** | Crawls all JS files (page + 16 common paths) → extracts 20 secret types: AWS keys, GitHub tokens, Stripe keys, JWT, private keys, DB connection strings, etc. |
| **Config Exposure** | Checks 30+ paths: `.env`, `wp-config.php`, `web.config`, `settings.py`, `docker-compose.yml`, `phpinfo.php`, etc. |
| **Git Exposure** | Checks `.git/HEAD`, `.git/config`, `.svn/entries` → runs `git-dumper` if available |
| **Backup Files** | Scans for `.zip`, `.sql`, `.tar.gz`, `.bak`, log files, `.bash_history` → downloads files < 5 MB |
| **Sensitive Endpoints** | Probes `/graphql`, `/actuator/env`, `/swagger`, `/api/users`, Jolokia, debug endpoints |

---

## v4 Modules — DARK MATTER

### 13. GOD MODE (`--god-mode`)

Elite 12-vector attack chain executed sequentially:

```
1.  SSRF          → Cloud metadata (AWS/GCP/Azure), localhost, Redis, SMTP via gopher
2.  XXE           → XML external entity injection on XML-accepting endpoints
3.  IDOR          → Numeric ID fuzzing on 12 API resource paths
4.  JWT Attacks   → alg:none bypass + HMAC brute-force (30 weak secrets)
5.  CORS          → Arbitrary origin reflection + credentials flag check
6.  Open Redirect → 16 redirect params × 5 payloads (javascript:, data:, //)
7.  Host Header   → X-Forwarded-Host, X-Host, Forwarded injection
8.  Verb Tamper   → TRACE/PUT/DELETE/PATCH on protected paths
9.  Smuggling     → TE:CL / CL:TE probe via curl (desync detection)
10. Business Logic → Negative values, int overflow, mass assignment PUT /api/profile
11. Subdomain TKO → Dangling CNAME fingerprint check (12 providers)
12. Proto Pollution → URL param + JSON body `__proto__` injection
```

Critical findings auto-generate a bug bounty report.

### 14. CVE Intelligence (`--cve`)

- Extracts detected technologies + versions from all prior scan results (20 patterns)
- Checks offline CVE database (30+ CVEs across 10 technology families with CVSS scores)
- Queries live NVD API (rate-limited, no key required)
- Saves `loot/cve_report.json`

### 15. AI Analysis (`--ai`)

Claude AI (claude-sonnet-4-6) expert security analysis:

- Executive summary for stakeholders
- Risk assessment with business impact
- Attack chain reconstruction from findings
- Next recommended attack vectors
- Remediation roadmap (prioritized)
- Existing compromise detection from indicators

**Setup API key:**
```bash
# Option 1: environment variable
export ANTHROPIC_API_KEY=sk-ant-...

# Option 2: interactive (menu option K)
python3 cyberburg.py   # → press K

# Option 3: key file
echo "sk-ant-..." > ~/.cyberburg_api_key
```

Output saved to `loot/ai_analysis.md`.

### 16. Screenshot Capture (`--screenshot`)

Captures screenshots of: main target + all discovered admin panels + config file URLs + API endpoints.

Uses (in order): `chromium --headless`, `wkhtmltoimage`, HTML snapshot fallback.

Saved to `output/<target>/screenshots/`.

### 17. Metasploit Integration (`--msf`)

- Maps all findings to corresponding Metasploit modules (20+ mappings)
- Auto-detects LHOST and target OS type
- Generates `msfvenom` payload suggestions per OS
- Outputs ready-to-run `.rc` resource script to `loot/<target>.rc`

```bash
# Run the generated script:
msfconsole -r output/<target>/loot/<target>.rc
```

---

## v5 Modules — PHANTOM PROTOCOL

### 18. Network Mapper (`--network`)

Full network range discovery — prompts for CIDR (defaults to target IP /24):

| Feature | Detail |
|---------|--------|
| **ARP Scan** | `arp-scan <cidr>` or nmap ARP ping fallback — discovers MAC + vendor |
| **Ping Sweep** | Parallel ICMP sweep via `ThreadPoolExecutor` (64 workers, max /16) |
| **Nmap Discovery** | `-sn --open` host discovery with MAC/vendor parsing |
| **Service Sweep** | Top 100 ports across all discovered hosts (up to 50 hosts) |
| **OS Fingerprint** | `nmap -O --osscan-guess` on first 5 live hosts |

```bash
python3 cyberburg.py -t 192.168.1.1 --network
# Prompts: Enter CIDR range [192.168.1.0/24]:
```

Live hosts saved to `loot/live_hosts_<cidr>.txt`.

### 19. API Security Tester (`--api`)

Full REST and GraphQL API security audit:

| Test | Detail |
|------|--------|
| **Endpoint Discovery** | Probes 50 common API paths — saves list to `loot/api_endpoints.txt` |
| **BOLA / IDOR** | IDs 1, 2, 3, 100, 999 on 11 resource paths — flags divergent 200 responses |
| **Mass Assignment** | PUT with `isAdmin`, `role`, `privilege`, `verified`, `balance` etc. — flags reflection |
| **Rate Limiting** | 20 rapid POST requests to auth endpoints — flags absence of 429 |
| **GraphQL** | Introspection query → saves schema; injection payloads for user/password/isAdmin |
| **Sensitive Data** | Scans 200-response bodies for API keys, passwords, SSN, credit cards, AWS keys |

### 20. WAF Bypass Engine (`--waf-bypass`)

WAF detection + automated evasion testing:

**Detected WAFs:** Cloudflare, AWS WAF, Akamai, Sucuri, ModSecurity, Imperva/Incapsula, F5 BIG-IP, Barracuda, Fortinet, Nginx NAXSI

**8 Encoding Techniques:**

| Technique | Example |
|-----------|---------|
| URL Encode | `%27%20OR%201%3D1--` |
| Double URL Encode | `%2527%2520OR%25201%253D1--` |
| HTML Entities | `&#39;&#32;OR&#32;1&#61;1--` |
| Hex Encode | `%27%20%4f%52%20%31%3d%31%2d%2d` |
| Case Mutation | `' Or 1=1--` |
| SQL Comment Spaces | `'/**/OR/**/1=1--` |
| Null Byte Suffix | `' OR 1=1--%00` |
| Tab/Newline | `' OR\n1=1--` |

Plus: HTTP Parameter Pollution + IP-spoofing header bypass (X-Forwarded-For, X-Real-IP, etc.)

```bash
python3 cyberburg.py -t https://example.com --waf-bypass
# Prompts: Target GET parameter [id]:
```

Bypass results saved to `loot/waf_bypasses.json`.

### 21. Threat Intelligence (`--threat`)

Passive intelligence sweep using free + optional paid APIs:

| Source | Key Required | What it provides |
|--------|-------------|-----------------|
| **ipinfo.io** | No | ISP, country, ASN, hostname |
| **AbuseIPDB** | Optional (`ABUSEIPDB_API_KEY`) | Abuse confidence score, report count, usage type |
| **crt.sh** | No | All subdomains from certificate transparency logs |
| **HackerTarget** | No | Passive DNS — historical hostname → IP mappings |
| **Shodan InternetDB** | No | Open ports, known CVEs, hostnames (free tier) |
| **Shodan Full API** | Optional (`SHODAN_API_KEY`) | Full host details, OS, org, all CVEs with CVSS |
| **DNSBL** | No | 7 blacklists: Spamhaus, SpamCop, SORBS, Barracuda, UCEProtect |
| **VirusTotal** | Optional (`VIRUSTOTAL_API_KEY`) | Malicious/suspicious vendor flags |

```bash
# Set API keys (optional — all free-tier sources work without keys)
export ABUSEIPDB_API_KEY=your_key
export SHODAN_API_KEY=your_key
export VIRUSTOTAL_API_KEY=your_key

python3 cyberburg.py -t example.com --threat
```

### 22. Password Auditor (`--passwords`)

Full password lifecycle audit:

| Feature | Detail |
|---------|--------|
| **Hash Extraction** | Scans all session findings for hash patterns: MD5, SHA-1, SHA-256, SHA-512, bcrypt, NTLM, NetNTLMv2, MySQL |
| **Hash Identification** | Identifies hash type automatically from format |
| **John the Ripper** | Runs `john --wordlist=<rockyou>` against extracted hashes |
| **Hashcat** | Runs with auto-detected mode if John finds nothing |
| **Default Creds** | Tests 150+ pairs across: generic, web frameworks (WP/Joomla/Drupal), DBs (MySQL/MongoDB/Redis), CMS, network devices (Cisco/MikroTik/Ubiquiti), monitoring tools (Grafana/Zabbix/Nagios), container tools (Portainer/Proxmox) |
| **Password Spray** | Slow spray (0.5s delay) with SPRAY_PASSWORDS list × provided usernames |
| **Policy Check** | Tests registration endpoint with 3-char password — flags no minimum length |

```bash
python3 cyberburg.py -t https://example.com --passwords
# Prompts:
#   Login endpoint path [/login]:
#   Usernames for spray (comma-separated, blank to skip):
```

CRITICAL finds auto-generate a bug bounty report.

---

## Output Folder System

Every scan session creates an isolated folder under `output/`:

```
output/
└── example_com_20250418_143022/       ← auto-created per scan session
    ├── session.json                   ← live snapshot (updated after each module)
    ├── loot/
    │   ├── sqlmap_quick/
    │   │   └── sqlmap_quick_output.txt
    │   ├── sqlmap_dump/
    │   │   ├── dump_mydb_users.txt    ← dumped credentials
    │   │   └── databases.txt
    │   ├── js_secrets/
    │   │   └── app.js_secrets.txt
    │   ├── configs/
    │   │   └── .env.txt               ← downloaded exposed config
    │   ├── git_exposure/
    │   │   └── .git_HEAD.txt
    │   ├── backups/
    │   │   └── backup.sql             ← downloaded backup file
    │   ├── endpoints/
    │   │   └── actuator_env.json
    │   ├── screenshots/               ← from module 16
    │   ├── api_endpoints.txt          ← from module 19
    │   ├── waf_bypasses.json          ← from module 20
    │   ├── crtsh_subdomains.txt       ← from module 21
    │   ├── shodan_1_2_3_4.json
    │   ├── extracted_hashes.txt       ← from module 22
    │   ├── ai_analysis.md             ← from module 15
    │   ├── cve_report.json            ← from module 14
    │   └── <target>.rc                ← Metasploit script (module 17)
    └── screenshots/
        ├── main_page.png
        └── admin_panel.png

reports/
└── cyberburg_example_com_20250418_143022.html   ← full HTML report
bug_bounty_reports/
└── exploit_example_com_20250418.html            ← auto-generated on CRITICAL
```

**Open output folder** from within the tool: press `O` in the main menu.

---

## Report System

### HTML Report

Professional dark-themed report with:
- Executive summary + risk rating banner (CRITICAL / HIGH / MEDIUM / LOW)
- Doughnut chart (severity distribution)
- All findings grouped by module with severity badges
- Auto-generated remediation recommendations
- Attack vectors documentation

```bash
# View the report
firefox output/<target>/reports/*.html
```

### JSON Report

Machine-readable for integration with SIEM, ticketing systems, or dashboards:

```json
{
  "meta": { "tool": "Cyberburg", "version": "5.0.0" },
  "target": "https://example.com",
  "risk_rating": "CRITICAL",
  "summary": { "CRITICAL": 3, "HIGH": 9, "MEDIUM": 12 },
  "findings": [
    {
      "type": "BOLA/IDOR",
      "severity": "HIGH",
      "url": "https://example.com/api/users/{id}",
      "detail": "IDs 1 and 2 return 200 with different body sizes",
      "module": "API Tester — BOLA/IDOR"
    }
  ]
}
```

### Bug Bounty Reports

Auto-generated HTML reports formatted for HackerOne / Bugcrowd submission when CRITICAL findings occur. Saved to `bug_bounty_reports/`.

---

## Threat Intelligence API Keys

All threat intel works without API keys using free tiers. Keys unlock more data:

```bash
# Add to ~/.bashrc or ~/.zshrc for persistence
export ANTHROPIC_API_KEY=sk-ant-...        # Required for AI analysis (module 15)
export ABUSEIPDB_API_KEY=...               # Full abuse score + report history
export SHODAN_API_KEY=...                  # Full Shodan host data + all CVEs
export VIRUSTOTAL_API_KEY=...             # VirusTotal domain/IP reputation

# Or configure AI key interactively (stores in ~/.cyberburg_api_key)
python3 cyberburg.py   # → press K
```

---

## Attack Methodology

Cyberburg follows the OWASP Testing Guide v4, PTES, and OWASP API Security Top 10:

```
Phase 1 — Passive Intelligence
  OSINT: WHOIS, DNS, subdomains, emails, certificate transparency,
         passive DNS, IP reputation, Shodan, blacklist checks

Phase 2 — Active Discovery
  Port scan, service fingerprint, OS detect, firewall probe,
  web tech fingerprint, WAF detect, CMS detect, SSL/TLS audit

Phase 3 — Vulnerability Identification
  Security headers, cookie flags, HTTP methods, robots.txt,
  Nikto, Nuclei (CVE + panels + exposure), directory brute,
  SQLi (SQLMap + manual), XSS (Dalfox + DOM), API endpoint enum

Phase 4 — Exploitation
  SQLi → DB dump → credential harvest
  Admin panel → default cred takeover
  LFI → /etc/passwd / file extraction
  Command injection → OS command execution
  File upload → PHP webshell → RCE

Phase 5 — Elite Attacks
  SSRF, XXE, IDOR, JWT abuse, CORS, open redirect,
  host header injection, verb tampering, smuggling,
  business logic, subdomain takeover, prototype pollution

Phase 6 — Intelligence Enrichment
  CVE lookup against detected tech versions
  Threat intel (AbuseIPDB, Shodan, DNSBL)
  AI-powered analysis and attack chain reconstruction

Phase 7 — Post-Exploitation
  Network mapping (CIDR, ARP, service sweep)
  Password auditing (hash cracking, spray)
  Screenshot documentation
  Metasploit resource script generation
  Report generation (HTML + JSON + TXT + Bug Bounty)
```

---

## Use Cases & Scenarios

### Bug Bounty Hunting (Recommended Workflow)

```bash
# 1. Passive recon
python3 cyberburg.py -t target.com --recon

# 2. Threat intelligence
python3 cyberburg.py -t target.com --threat

# 3. Full web + vuln scan
python3 cyberburg.py -t https://target.com --web

# 4. API surface attack
python3 cyberburg.py -t https://target.com --api

# 5. God Mode for quick wins
python3 cyberburg.py -t https://target.com --god-mode

# 6. CVE check detected tech
python3 cyberburg.py -t https://target.com --cve

# 7. AI analysis for report writing
python3 cyberburg.py -t https://target.com --ai
```

### Full Pentest Engagement (Single Command)

```bash
sudo python3 cyberburg.py -t https://client.com
# Prompts for target confirmation, then runs all base modules
# HTML report auto-generated at output/<target>/
```

### Network Penetration Test

```bash
# Discover all hosts in a subnet
python3 cyberburg.py -t 192.168.1.1 --network
# Prompts: Enter CIDR range [192.168.1.0/24]: 10.0.0.0/16

# Then scan a specific discovered host
python3 cyberburg.py -t 10.0.0.45
```

### Post-Exploitation — DB Dump

```bash
# After initial scan confirms SQLi:
python3 cyberburg.py -t https://target.com --exploit
# Runs: sqlmap dump → admin panel takeover → LFI → CMDi → file upload
# All credentials saved to output/<target>/loot/
```

### WAF-Protected Target

```bash
# Step 1: identify WAF
python3 cyberburg.py -t https://waf-protected.com --web

# Step 2: find bypass techniques
python3 cyberburg.py -t https://waf-protected.com --waf-bypass
# Prompts: Target GET parameter [id]:
# Tries 8 encoding techniques across SQLi + XSS payloads
```

### Password-Focused Engagement

```bash
# Combine harvest (extracts hashes) then password audit (cracks them)
python3 cyberburg.py -t https://target.com --harvest
python3 cyberburg.py -t https://target.com --passwords
# Pass any emails/usernames found during recon for the spray module
```

### Red Team Engagement

```bash
# Maximum stealth initial footprint
sudo python3 cyberburg.py -t target.org --stealth

# Custom minimal module set (recon + SSL + passive intel only)
python3 cyberburg.py -t target.org
# Select 4 → enter: 1,4,21
```

### CTF Competition

```bash
# Full scan — usually reveals: open ports, admin panels, SQLi, LFI, default creds
python3 cyberburg.py -t 10.10.10.100

# OR targeted:
python3 cyberburg.py -t 10.10.10.100 --exploit
```

---

## Troubleshooting

### `rich` library not found

```bash
pip3 install rich
```

### Tools missing / not found

```bash
# Check what's available
python3 cyberburg.py --tools

# Install missing tools
sudo apt install nmap nikto sqlmap gobuster john hashcat arp-scan
```

### Permission denied (stealth scan / ARP scan)

```bash
# SYN scan and ARP scan require root
sudo python3 cyberburg.py -t target.com --stealth
sudo python3 cyberburg.py -t 192.168.1.1 --network
```

### AI analysis not working

```bash
# Verify API key is set
echo $ANTHROPIC_API_KEY

# Set it permanently
echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> ~/.bashrc
source ~/.bashrc

# Or use the interactive key setup
python3 cyberburg.py  # → press K
```

### SQLMap not finding injections

SQLMap is conservative by default. The manual error-based testing in `--web` uses direct curl probing that may find error-based SQLi even when SQLMap misses it. Also try `--exploit` which uses higher risk/level settings.

### Scan hangs or takes too long

- Use `--quick` for a faster initial assessment
- Press `Ctrl+C` — partial results are saved to `session.json` and a partial report is offered
- For nmap: edit `port_scanner.py` and change `-T4` to `-T3`

### Reports not showing in `View Previous Reports` (option 10)

Reports are now scanned recursively from `output/` and `reports/` directories. If they were generated before v5, check `reports/` manually.

### Go tools not in PATH after install

```bash
export PATH="$PATH:$HOME/go/bin"
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc
```

### Shodan/AbuseIPDB returning limited data

These services work without API keys via free-tier endpoints (Shodan InternetDB, ipinfo.io). For full data, set the environment variables listed in the [Threat Intelligence API Keys](#threat-intelligence-api-keys) section.

### Windows compatibility

Pure-Python modules work fully on Windows: data harvester, API tester, WAF bypass, threat intel, password auditor, god mode, CVE lookup, AI analysis. Modules wrapping Linux CLI tools (nmap, sqlmap, gobuster, etc.) require those tools installed in your Windows PATH or running under WSL.

---

## Developer

<div align="center">

**Faiz Zyhon**

*Security Researcher & Tool Developer*

| Platform | Link |
|----------|------|
| GitHub | [github.com/faizzyhon](https://github.com/faizzyhon) |
| Instagram | [instagram.com/faizzyhon](https://instagram.com/faizzyhon) |
| Website | [faizzyhon.online](https://faizzyhon.online) |

</div>

Cyberburg was built out of frustration with switching between 30+ tools during engagements. The vision: one tool, one interface, one report — professional quality output every time.

If Cyberburg helped you find vulnerabilities, win a CTF, or deliver a better pentest report:
- Star the repository on GitHub
- Share with your security community
- Submit issues or pull requests
- Follow on Instagram for updates

---

## Changelog

### v5.0.0 — PHANTOM PROTOCOL
- **NEW Module 18**: Network Mapper — CIDR ping sweep, ARP scan, nmap host discovery, OS fingerprinting, service sweep across all live hosts
- **NEW Module 19**: API Security Tester — endpoint discovery (50 paths), BOLA/IDOR, mass assignment, rate limiting, GraphQL introspection + injection, sensitive data scan
- **NEW Module 20**: WAF Bypass Engine — WAF detection (10 signatures), 8 encoding techniques, HTTP parameter pollution, IP-spoofing header bypass
- **NEW Module 21**: Threat Intelligence — AbuseIPDB, crt.sh certificate transparency, HackerTarget passive DNS, Shodan InternetDB (free) + full API, DNSBL (7 lists), VirusTotal optional
- **NEW Module 22**: Password Auditor — hash extraction + identification, John the Ripper + Hashcat, 150+ default credential pairs, slow password spray, password policy check
- **FIX**: `sqlmap_quick/full/post` hardcoded `/tmp/` paths — now uses `output/<target>/loot/sqlmap_*/` with `tempfile` fallback (was broken on Windows)
- **FIX**: `sqlmap_full` broken DB-name fallback regex removed; primary regex extended to capture hyphenated DB names
- **FIX**: SQLMap raw output now saved to loot folder on every run
- **FIX**: `harvest_js_secrets` content-type check now accepts `application/javascript` and `ecmascript` (was skipping most CDN-served JS files)
- **FIX**: `harvest_backup_files` first-chunk data loss bug — first 1024 bytes were consumed for HTML detection then discarded when writing; now prepended correctly
- **FIX**: `harvest_config_files` `<html>` false-positive filter removed — was incorrectly blocking valid `phpinfo.php` responses
- **FIX**: `exploit_engine` DB name regex extended to `[\w\-]+` for hyphenated database names
- **FIX**: `admin_panel_takeover` false positive reduction — now diffs response against login-page baseline before declaring success
- **FIX**: `_view_reports()` now recursively walks `output/` and `reports/` (was only showing `./reports/`)
- **FIX**: Custom scan menu (option 4) now includes all v3/v4/v5 modules
- **FIX**: Removed unused `from rich.prompt import Prompt as P` import in `_run_auth`
- Version bumped to v5.0.0

### v4.0.0 — DARK MATTER
- God Mode 12-vector elite attack chain (SSRF, XXE, IDOR, JWT, CORS, open redirect, host header, verb tampering, smuggling, business logic, subdomain takeover, prototype pollution)
- CVE intelligence lookup with offline DB + live NVD API
- Claude AI expert analysis (claude-sonnet-4-6, streaming)
- Screenshot capture (chromium headless / wkhtmltoimage / HTML fallback)
- Metasploit .rc resource script generation (20+ module mappings)

### v3.0.0 — GHOST PROTOCOL
- Automated exploitation engine (SQLi DB dump, admin panel takeover, LFI exploitation, command injection, file upload)
- Data harvesting (JS secrets 20 patterns, config file exposure 30+ paths, git repository exposure, backup file detection, sensitive endpoint discovery)
- Organized output folder system: `output/<target>_<timestamp>/loot/`
- Session auto-snapshot (session.json updated after every module)

### v2.0.0 — PHANTOM BLADE
- Flask web dashboard (localhost:5000)
- Authentication tester (login brute-force, default creds, MFA check, lockout detection)
- Bug bounty report auto-generation on CRITICAL findings
- `bug_bounty_reports/` folder

### v1.0.0 — Initial Release
- 9 scan modes, 30+ tool integrations
- Interactive menu + full CLI argument mode
- Modules: recon, port scanner, web scanner, SSL analyzer, SQL injection, XSS scanner, directory bruteforce, nuclei scan
- Report generation: HTML (Chart.js), JSON, TXT
- Automated tool availability detection

---

<div align="center">

**AUTHORIZED SECURITY TESTING ONLY**

*Cyberburg is a tool for professional security researchers and pentesters.*
*Always obtain written permission before testing any system.*
*Unauthorized testing is illegal and unethical.*

---

Made with passion by **Faiz Zyhon**

[github.com/faizzyhon](https://github.com/faizzyhon) • [instagram.com/faizzyhon](https://instagram.com/faizzyhon) • [faizzyhon.online](https://faizzyhon.online)

*"The best security comes from understanding the attacker's perspective"*

</div>
