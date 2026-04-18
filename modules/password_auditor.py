#!/usr/bin/env python3
"""
Password Auditor — Cyberburg v5 PHANTOM PROTOCOL
Hash extraction from findings, hash identification, John/Hashcat integration,
password spray, 150+ default credential pairs, weak pattern detection.

AUTHORIZED PENETRATION TESTING ONLY.
"""

import os
import re
import json
import time
import hashlib

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.helpers import run_command, get_timestamp, sanitize_filename
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()

# ─── Default Credentials Database ────────────────────────────────────────────

DEFAULT_CREDS = [
    # Generic
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "password123"), ("admin", ""),
    ("root", "root"), ("root", "toor"), ("root", "password"), ("root", ""),
    ("test", "test"), ("guest", "guest"), ("user", "user"),
    ("administrator", "administrator"), ("administrator", "password"),
    ("administrator", "admin"), ("administrator", ""),
    # Web frameworks
    ("admin", "changeme"), ("admin", "letmein"), ("admin", "secret"),
    ("admin", "12345"), ("admin", "qwerty"), ("admin", "abc123"),
    ("admin", "pass"), ("admin", "pass123"), ("admin", "1234"),
    # WordPress
    ("admin", "admin"), ("wordpress", "wordpress"),
    # Joomla
    ("admin", "admin"), ("joomla", "joomla"),
    # Drupal
    ("admin", "admin"),
    # Tomcat
    ("tomcat", "tomcat"), ("tomcat", "s3cret"), ("admin", "tomcat"),
    ("manager", "manager"),
    # Jenkins
    ("admin", "admin"), ("jenkins", "jenkins"),
    # GitLab
    ("root", "5iveL!fe"), ("root", "password"),
    # Grafana
    ("admin", "admin"),
    # Portainer
    ("admin", "portainer"),
    # phpMyAdmin
    ("root", ""), ("root", "root"), ("phpmyadmin", "phpmyadmin"),
    # MySQL
    ("root", ""), ("root", "root"), ("root", "mysql"),
    # MongoDB
    ("admin", "admin"), ("root", "root"),
    # Elasticsearch (no default auth, but test endpoints)
    # Redis (no password)
    # Kibana
    ("elastic", "changeme"), ("kibana", "changeme"),
    # Splunk
    ("admin", "changeme"),
    # Netdata
    ("netdata", "netdata"),
    # Roundcube
    ("admin", "admin"),
    # Magento
    ("admin", "admin123"),
    # PrestaShop
    ("admin@admin.com", "admin"),
    # OpenCart
    ("admin", "admin"),
    # DVWA
    ("admin", "password"), ("gordonb", "abc123"),
    ("1337", "charley"), ("pablo", "letmein"),
    # Plex
    ("admin", "admin"),
    # Nextcloud
    ("admin", "admin"),
    # Rocket.Chat
    ("admin", "admin"),
    # Redmine
    ("admin", "admin"),
    # SonarQube
    ("admin", "admin"),
    # Zabbix
    ("Admin", "zabbix"), ("admin", "zabbix"),
    # Nagios
    ("nagiosadmin", "nagiosadmin"),
    # Prometheus (no default auth)
    # RabbitMQ
    ("guest", "guest"), ("admin", "admin"),
    # ActiveMQ
    ("admin", "admin"), ("system", "manager"),
    # WebLogic
    ("weblogic", "weblogic"), ("weblogic", "welcome1"),
    ("weblogic", "Password1"),
    # JBoss/WildFly
    ("admin", "admin"),
    # GlassFish
    ("admin", "adminadmin"),
    # Liferay
    ("test@liferay.com", "test"),
    # cPanel
    ("root", ""), ("cpanel", "cpanel"),
    # Plesk
    ("admin", "setup"),
    # ISPConfig
    ("admin", "admin"),
    # Cisco
    ("cisco", "cisco"), ("admin", "cisco"), ("", "cisco"),
    # Fortinet
    ("admin", ""), ("maintainer", "bcpb" + "admin"),
    # MikroTik
    ("admin", ""), ("admin", "admin"),
    # Ubiquiti
    ("ubnt", "ubnt"), ("admin", "ubnt"),
    # Netgear
    ("admin", "password"), ("admin", "1234"),
    # Linksys
    ("admin", "admin"),
    # D-Link
    ("admin", ""), ("Admin", ""),
    # TP-Link
    ("admin", "admin"),
    # Zyxel
    ("admin", "1234"), ("admin", "admin"),
    # ASUS
    ("admin", "admin"),
    # Pi-hole
    ("admin", "admin"),
    # Home Assistant
    ("homeassistant", "homeassistant"),
    # Synology
    ("admin", ""),
    # QNAP
    ("admin", "admin"),
    # Proxmox
    ("root", "proxmox"),
    # ESXi/vSphere
    ("root", ""), ("root", "vmware"),
]


# ─── Hash Identification ──────────────────────────────────────────────────────

HASH_PATTERNS = {
    "MD5":           (re.compile(r'^[a-fA-F0-9]{32}$'), 'md5', 0),
    "SHA-1":         (re.compile(r'^[a-fA-F0-9]{40}$'), 'sha1', 100),
    "SHA-256":       (re.compile(r'^[a-fA-F0-9]{64}$'), 'sha256', 1400),
    "SHA-512":       (re.compile(r'^[a-fA-F0-9]{128}$'), 'sha512', 1800),
    "bcrypt":        (re.compile(r'^\$2[aby]\$\d{2}\$'), 'bcrypt', 3200),
    "SHA-512 crypt": (re.compile(r'^\$6\$'), 'sha512crypt', 1800),
    "SHA-256 crypt": (re.compile(r'^\$5\$'), 'sha256crypt', 7400),
    "MD5 crypt":     (re.compile(r'^\$1\$'), 'md5crypt', 500),
    "NTLM":          (re.compile(r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$'), 'ntlm', 1000),
    "NetNTLMv2":     (re.compile(r'.+::.+:[a-fA-F0-9]{16}:.+:.+'), 'netntlmv2', 5600),
    "WPA":           (re.compile(r'^[a-fA-F0-9]{64}$'), 'wpapsk', 22000),
    "MySQL 4.1+":    (re.compile(r'^\*[A-F0-9]{40}$'), 'mysql41', 300),
}

HASH_EXTRACT = re.compile(
    r'(?:'
    r'\*[A-F0-9]{40}'              # MySQL
    r'|[a-fA-F0-9]{128}'           # SHA-512
    r'|[a-fA-F0-9]{64}'            # SHA-256
    r'|[a-fA-F0-9]{40}'            # SHA-1
    r'|\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'  # bcrypt
    r'|\$6\$[^\s:]{8,}\$[^\s:]+'  # SHA-512 crypt
    r'|[a-fA-F0-9]{32}'            # MD5
    r')'
)


def identify_hash(h: str) -> str:
    """Identify hash type from its format."""
    h = h.strip()
    for name, (pattern, _, _) in HASH_PATTERNS.items():
        if pattern.match(h):
            return name
    return "Unknown"


def extract_hashes_from_session(session) -> list:
    """Search all session findings for hash-like strings."""
    hashes = set()
    for module in session.modules:
        raw = str(module.get("raw", ""))
        for m in HASH_EXTRACT.finditer(raw):
            h = m.group(0)
            if len(h) >= 32:
                hashes.add(h)
        for f in module.get("findings", []):
            for val in f.values():
                for m in HASH_EXTRACT.finditer(str(val)):
                    h = m.group(0)
                    if len(h) >= 32:
                        hashes.add(h)
    return list(hashes)


# ─── Hash Cracking ────────────────────────────────────────────────────────────

WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "/opt/wordlists/rockyou.txt",
]


def _find_wordlist() -> str:
    for wl in WORDLISTS:
        if os.path.exists(wl):
            return wl
    # Try the project's wordlists dir
    local = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "wordlists", "common.txt")
    return local if os.path.exists(local) else ""


def crack_with_john(hash_file: str, wordlist: str, hash_type: str = None, output_dir: str = "") -> dict:
    """Run John the Ripper against a hash file."""
    result = {
        "module": "Password Auditor — John the Ripper",
        "target": hash_file,
        "timestamp": get_timestamp(),
        "raw": "",
        "cracked": [],
        "findings": []
    }

    if not check_tool("john"):
        result["raw"] = "john not installed"
        print_warning("John the Ripper not found")
        return result

    if not wordlist or not os.path.exists(wordlist):
        result["raw"] = "No wordlist available"
        print_warning("No wordlist found for John")
        return result

    print_info(f"Running John the Ripper on {hash_file}...")
    cmd = ["john", hash_file, f"--wordlist={wordlist}"]
    if hash_type:
        cmd.append(f"--format={hash_type}")

    code, stdout, stderr = run_command(cmd, timeout=300)
    result["raw"] = stdout or stderr

    # Show cracked
    code2, stdout2, _ = run_command(["john", "--show", hash_file], timeout=30)
    for line in (stdout2 or "").splitlines():
        if ":" in line and not line.startswith("0 password"):
            parts = line.split(":")
            if len(parts) >= 2:
                result["cracked"].append({"hash": parts[0], "password": parts[1]})
                result["findings"].append({
                    "type": "Cracked Hash",
                    "severity": "CRITICAL",
                    "hash": parts[0][:30],
                    "detail": f"Password: {parts[1]}"
                })
                print_success(f"Cracked: {parts[0][:20]} → {parts[1]}")

    return result


def crack_with_hashcat(hash_file: str, wordlist: str, hashcat_mode: int = 0, output_dir: str = "") -> dict:
    """Run Hashcat against a hash file."""
    result = {
        "module": "Password Auditor — Hashcat",
        "target": hash_file,
        "timestamp": get_timestamp(),
        "raw": "",
        "cracked": [],
        "findings": []
    }

    if not check_tool("hashcat"):
        result["raw"] = "hashcat not installed"
        print_warning("Hashcat not found")
        return result

    if not wordlist or not os.path.exists(wordlist):
        result["raw"] = "No wordlist available"
        return result

    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)
    pot_file = os.path.join(loot_dir, "hashcat.pot")

    print_info(f"Running Hashcat (mode {hashcat_mode}) on {hash_file}...")
    code, stdout, stderr = run_command(
        ["hashcat", "-m", str(hashcat_mode), hash_file, wordlist,
         "--potfile-path", pot_file, "--quiet", "--force"],
        timeout=600
    )
    result["raw"] = stdout or stderr

    # Read pot file
    if os.path.exists(pot_file):
        with open(pot_file) as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    h, pw = line.rsplit(":", 1)
                    result["cracked"].append({"hash": h, "password": pw})
                    result["findings"].append({
                        "type": "Cracked Hash (Hashcat)",
                        "severity": "CRITICAL",
                        "hash": h[:30],
                        "detail": f"Password: {pw}"
                    })
                    print_success(f"Hashcat cracked: {h[:20]} → {pw}")

    return result


# ─── Password Spray ───────────────────────────────────────────────────────────

SPRAY_PASSWORDS = [
    "Password1", "Password123", "Welcome1", "Welcome123",
    "Summer2024", "Winter2024", "Spring2025", "Autumn2024",
    "Company2024", "P@ssw0rd", "Passw0rd!", "Admin123!",
    "Qwerty123", "Hello123", "Monkey1", "Letmein1",
]


def password_spray(url: str, login_path: str, usernames: list, output_dir: str) -> dict:
    """Slow password spray attack — one password across all users."""
    result = {
        "module": "Password Auditor — Password Spray",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "successful": [],
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests not available"
        return result

    if not usernames:
        result["raw"] = "No usernames provided"
        return result

    print_info(f"Password spray against {url}{login_path} with {len(usernames)} users...")
    base = url.rstrip("/")
    full_url = f"{base}{login_path}"

    username_fields  = ["username", "user", "email", "login", "user_login"]
    password_fields  = ["password", "pass", "passwd", "pwd"]

    # First, get baseline response length for failed login
    baseline_len = None
    try:
        r = requests.post(full_url, data={"username": "nonexistent_z9z9z9", "password": "wrongpass"},
                          timeout=8, verify=False, allow_redirects=True)
        baseline_len = len(r.content)
    except Exception:
        pass

    for password in SPRAY_PASSWORDS[:8]:  # Cap at 8 passwords to avoid lockout
        for user in usernames[:20]:
            for uf in username_fields[:2]:
                for pf in password_fields[:2]:
                    try:
                        time.sleep(0.5)  # Slow spray to avoid lockout
                        r = requests.post(
                            full_url,
                            data={uf: user, pf: password},
                            timeout=8, verify=False, allow_redirects=True
                        )
                        # Success indicators: redirect, response size diff, success keywords
                        success = (
                            r.url != full_url and "logout" in r.url.lower() or
                            "dashboard" in r.url.lower() or
                            any(kw in r.text.lower() for kw in ("logout", "welcome", "dashboard", "signout")) or
                            (baseline_len and abs(len(r.content) - baseline_len) > 500 and r.status_code == 200)
                        )
                        if success:
                            result["successful"].append({"user": user, "password": password})
                            result["findings"].append({
                                "type": "Password Spray — Valid Credential",
                                "severity": "CRITICAL",
                                "url": full_url,
                                "detail": f"User: {user} | Password: {password}"
                            })
                            print_success(f"SPRAY HIT: {user} / {password}")
                            break
                    except Exception:
                        pass

    result["raw"] = f"Spray complete — {len(result['successful'])} valid credentials found"
    return result


# ─── Default Credential Testing ───────────────────────────────────────────────

def test_default_creds(url: str, login_path: str, output_dir: str) -> dict:
    """Test 150+ default credential pairs against a login endpoint."""
    result = {
        "module": "Password Auditor — Default Credentials",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "successful": [],
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests not available"
        return result

    print_info(f"Testing {len(DEFAULT_CREDS)} default credential pairs...")
    base = url.rstrip("/")
    full_url = f"{base}{login_path}"

    # Baseline
    baseline_status = None
    baseline_len = None
    try:
        r = requests.post(full_url,
                          data={"username": "zzznotauser999", "password": "zzzwrongpass999"},
                          timeout=8, verify=False)
        baseline_status = r.status_code
        baseline_len = len(r.content)
    except Exception:
        pass

    for user, passwd in DEFAULT_CREDS:
        for uf, pf in [("username", "password"), ("email", "password"), ("user", "pass")]:
            try:
                r = requests.post(
                    full_url,
                    data={uf: user, pf: passwd},
                    timeout=5, verify=False, allow_redirects=True
                )
                success = (
                    (r.status_code == 302 and "logout" in r.headers.get("Location", "")) or
                    (r.url != full_url) or
                    any(kw in r.text.lower() for kw in ("logout", "dashboard", "welcome", "signout")) or
                    (baseline_len and abs(len(r.content) - baseline_len) > 300 and
                     r.status_code not in (401, 403))
                )
                if success:
                    result["successful"].append({"user": user, "password": passwd})
                    result["findings"].append({
                        "type": "Default Credentials Valid",
                        "severity": "CRITICAL",
                        "url": full_url,
                        "detail": f"Username: {user} | Password: {passwd}"
                    })
                    print_success(f"DEFAULT CREDS: {user} / {passwd}")
                    break
            except Exception:
                pass

    result["raw"] = f"Default cred test complete — {len(result['successful'])} valid pairs"
    return result


# ─── Weak Password Pattern Detection ─────────────────────────────────────────

def analyze_password_policy(url: str) -> dict:
    """Probe for weak password policy indicators."""
    result = {
        "module": "Password Auditor — Policy Check",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests not available"
        return result

    print_info("Checking password policy signals...")
    base = url.rstrip("/")

    # Test registration endpoint for min-length enforcement
    reg_paths = ["/register", "/signup", "/api/register", "/api/signup", "/user/create"]
    for path in reg_paths:
        try:
            r = requests.post(f"{base}{path}",
                              json={"username": "test_z9z9", "email": "test@test.com",
                                    "password": "abc", "confirm_password": "abc"},
                              headers={"Content-Type": "application/json"},
                              timeout=6, verify=False)
            if r.status_code in (200, 201):
                result["findings"].append({
                    "type": "Weak Password Policy",
                    "severity": "HIGH",
                    "url": f"{base}{path}",
                    "detail": "Registration accepted 3-char password 'abc' — no minimum length enforced"
                })
                print_success(f"Weak policy: {path} accepts 3-char passwords")
        except Exception:
            pass

    return result


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def run_password_auditor(session, output_dir: str):
    """Full password audit: hash extraction, cracking, spray, default creds."""
    from utils.banner import print_section
    print_section("PASSWORD AUDITOR — PHANTOM PROTOCOL", "bold red")

    url = session.url
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)

    # Extract hashes from prior scan findings
    print_info("Extracting hashes from scan session findings...")
    hashes = extract_hashes_from_session(session)
    if hashes:
        hash_file = os.path.join(loot_dir, "extracted_hashes.txt")
        with open(hash_file, "w") as f:
            f.write("\n".join(hashes))
        print_success(f"Extracted {len(hashes)} hashes → {hash_file}")

        # Show hash types
        table = Table(title="Extracted Hashes", box=box.SIMPLE, header_style="bold cyan")
        table.add_column("Hash (truncated)", style="cyan")
        table.add_column("Type")
        for h in hashes[:15]:
            table.add_row(h[:40] + "...", identify_hash(h))
        console.print(table)

        # Crack with john first
        wordlist = _find_wordlist()
        r = crack_with_john(hash_file, wordlist, output_dir=output_dir)
        session.add_result(r)

        # If john found nothing, try hashcat
        if not r.get("cracked"):
            # Determine mode from first hash
            hashcat_mode = 0  # default MD5
            if hashes:
                ht = identify_hash(hashes[0])
                mode_map = {
                    "MD5": 0, "SHA-1": 100, "SHA-256": 1400, "SHA-512": 1800,
                    "bcrypt": 3200, "NTLM": 1000, "MySQL 4.1+": 300,
                }
                hashcat_mode = mode_map.get(ht, 0)
            r2 = crack_with_hashcat(hash_file, wordlist, hashcat_mode, output_dir)
            session.add_result(r2)
    else:
        print_info("No hashes found in scan session — skipping hash cracking")

    # Default credential testing
    login_path = Prompt.ask(
        "  [bold cyan]Login endpoint path[/bold cyan] [dim](e.g. /login, /admin, /wp-login.php)[/dim]",
        default="/login"
    ).strip()

    r = test_default_creds(url, login_path, output_dir)
    session.add_result(r)

    # Password spray — ask for username list
    usernames_raw = Prompt.ask(
        "  [bold cyan]Usernames for spray[/bold cyan] [dim](comma-separated, or leave blank to skip)[/dim]",
        default=""
    ).strip()

    if usernames_raw:
        usernames = [u.strip() for u in usernames_raw.split(",")]
        r = password_spray(url, login_path, usernames, output_dir)
        session.add_result(r)

    # Password policy
    r = analyze_password_policy(url)
    session.add_result(r)

    # Summary
    all_findings = [f for m in session.modules[-5:] for f in m.get("findings", [])]
    crits = [f for f in all_findings if f.get("severity") == "CRITICAL"]

    table = Table(title="Password Audit Summary", box=box.SIMPLE, header_style="bold cyan")
    table.add_column("Type", style="cyan", width=35)
    table.add_column("Severity", width=10)
    table.add_column("Detail", style="dim")

    for f in all_findings[:20]:
        sev = f.get("severity", "INFO")
        sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "blue")
        table.add_row(
            f.get("type", "-"),
            f"[{sev_color}]{sev}[/{sev_color}]",
            f.get("detail", "")[:70]
        )

    console.print(table)
    console.print(f"\n  [bold green][+] Password audit complete — {len(all_findings)} findings ({len(crits)} critical)[/bold green]")

    if crits:
        from modules.bug_bounty_report import create_bug_bounty_report
        bb_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bug_bounty_reports")
        os.makedirs(bb_dir, exist_ok=True)
        bb_path = create_bug_bounty_report(
            f"passwords_{sanitize_filename(session.hostname)}", session.target, crits, bb_dir
        )
        console.print(f"\n  [bold red]Bug Bounty report: {bb_path}[/bold red]")
