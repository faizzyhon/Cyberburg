#!/usr/bin/env python3
"""
Data Harvester — Cyberburg v3
Automated sensitive data collection: JS secrets, config leaks,
git exposure, backup files, sensitive endpoints.

AUTHORIZED USE ONLY — Responsible disclosure required for any findings.
"""

import os
import re
import json
import base64

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.helpers import run_command, get_timestamp, extract_urls, sanitize_filename
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ─── Regex Patterns for Secret Detection ──────────────────────────────────────

SECRET_PATTERNS = {
    "AWS Access Key":         r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":         r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+=]{40}["\']',
    "Google API Key":         r'AIza[0-9A-Za-z\-_]{35}',
    "GitHub Token":           r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}',
    "Stripe Secret Key":      r'sk_live_[A-Za-z0-9]{24,}',
    "Stripe Publishable Key": r'pk_live_[A-Za-z0-9]{24,}',
    "Twilio API Key":         r'SK[0-9a-fA-F]{32}',
    "SendGrid API Key":       r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
    "JWT Token":              r'eyJ[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=_\-]{10,}',
    "Private Key (PEM)":      r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    "Password in JS":         r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,50}["\']',
    "API Key in JS":          r'(?i)(?:api_?key|apikey|access_?key|secret_?key)\s*[=:]\s*["\'][A-Za-z0-9\-_]{8,50}["\']',
    "DB Connection String":   r'(?i)(?:mysql|postgres|mongodb|sqlserver|mssql):\/\/[^\s\'"<>]+',
    "Basic Auth Header":      r'(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}',
    "Bearer Token":           r'(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-_\.]{20,}',
    "Hardcoded Password":     r'(?i)(?:password|passwd)\s*=\s*["\'][^"\']{6,}["\']',
    "Firebase URL":           r'https://[a-z0-9-]+\.firebaseio\.com',
    "Slack Webhook":          r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    "Mailchimp API Key":      r'[0-9a-f]{32}-us\d{1,2}',
    "SSH Private Key":        r'-----BEGIN OPENSSH PRIVATE KEY-----',
}

# ─── JS File Harvesting ───────────────────────────────────────────────────────

def harvest_js_secrets(url: str, output_dir: str) -> dict:
    """Crawl and extract secrets from JavaScript files."""
    result = {
        "module": "JavaScript Secrets Harvesting",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": [],
        "loot": []
    }

    if not HAS_REQUESTS:
        print_warning("requests not installed — skipping JS harvesting")
        return result

    print_info(f"Harvesting secrets from JavaScript files on {url}...")
    loot_dir = os.path.join(output_dir, "loot", "js_secrets")
    os.makedirs(loot_dir, exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)"})

    # Step 1: Fetch main page and find JS URLs
    js_urls = set()
    try:
        resp = session.get(url, timeout=10, verify=False)
        js_in_page = re.findall(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', resp.text, re.IGNORECASE)
        for js in js_in_page:
            if js.startswith("http"):
                js_urls.add(js)
            elif js.startswith("//"):
                js_urls.add("https:" + js)
            else:
                from urllib.parse import urljoin
                js_urls.add(urljoin(url, js))
        result["raw"] += f"Found {len(js_urls)} JS files on main page\n"
    except Exception as e:
        result["raw"] += f"Error fetching main page: {e}\n"

    # Step 2: Common JS paths to check
    common_js = [
        "/app.js", "/main.js", "/bundle.js", "/vendor.js", "/index.js",
        "/static/js/main.js", "/js/app.js", "/assets/js/app.js",
        "/dist/bundle.js", "/build/app.js", "/assets/app.js",
        "/static/bundle.js", "/js/config.js", "/config.js",
        "/env.js", "/settings.js", "/constants.js",
    ]
    base = url.rstrip("/")
    for js_path in common_js:
        js_urls.add(base + js_path)

    # Step 3: Analyze each JS file
    secrets_found = []
    for js_url in list(js_urls)[:30]:  # Cap at 30 files
        try:
            r = session.get(js_url, timeout=8, verify=False)
            if r.status_code != 200 or "text" not in r.headers.get("content-type", ""):
                continue
            content = r.text

            file_secrets = []
            for secret_type, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    if len(match) > 6:
                        file_secrets.append((secret_type, match[:80]))

            if file_secrets:
                fname = sanitize_filename(js_url.split("/")[-1] or "unknown.js") + "_secrets.txt"
                loot_path = os.path.join(loot_dir, fname)
                with open(loot_path, "w") as f:
                    f.write(f"Source: {js_url}\n\n")
                    for stype, val in file_secrets:
                        f.write(f"[{stype}] {val}\n")
                result["loot"].append(loot_path)

                for stype, val in file_secrets:
                    result["findings"].append({
                        "type": f"JS Secret: {stype}",
                        "value": f"{val[:60]}... (in {js_url.split('/')[-1]})",
                        "severity": "CRITICAL"
                    })
                    print_error(f"CRITICAL: {stype} found in JS: {val[:50]}...")
                    secrets_found.append((stype, val, js_url))

        except Exception:
            continue

    if not secrets_found:
        result["findings"].append({
            "type": "JS Secrets",
            "value": f"No obvious secrets found in {len(js_urls)} JS files scanned",
            "severity": "INFO"
        })
        print_info("JS Harvesting: No secrets found")

    result["raw"] += f"Scanned {len(js_urls)} JS files, found {len(secrets_found)} secrets"
    return result


# ─── Config File Exposure ─────────────────────────────────────────────────────

CONFIG_PATHS = [
    ("/.env",                    "Environment file"),
    ("/.env.local",              "Local environment file"),
    ("/.env.production",         "Production environment file"),
    ("/.env.backup",             "Backup environment file"),
    ("/config.php",              "PHP config file"),
    ("/configuration.php",       "Joomla config file"),
    ("/wp-config.php",           "WordPress config"),
    ("/wp-config.php.bak",       "WordPress config backup"),
    ("/config/database.php",     "Laravel DB config"),
    ("/config/app.php",          "Laravel app config"),
    ("/application/config/database.php", "CodeIgniter DB config"),
    ("/web.config",              "ASP.NET config"),
    ("/web.config.bak",          "ASP.NET config backup"),
    ("/settings.py",             "Django settings"),
    ("/config.yml",              "YAML config"),
    ("/config.yaml",             "YAML config"),
    ("/database.yml",            "Database config"),
    ("/secrets.yml",             "Secrets config"),
    ("/application.properties",  "Spring Boot config"),
    ("/application.yml",         "Spring Boot YAML"),
    ("/docker-compose.yml",      "Docker Compose"),
    ("/Dockerfile",              "Dockerfile"),
    ("/phpinfo.php",             "PHP Info page"),
    ("/info.php",                "PHP Info"),
    ("/test.php",                "PHP test file"),
    ("/server-status",           "Apache status"),
    ("/server-info",             "Apache info"),
    ("/.htaccess",               "Apache htaccess"),
    ("/.htpasswd",               "Apache password file"),
    ("/crossdomain.xml",         "Flash crossdomain"),
    ("/clientaccesspolicy.xml",  "Silverlight policy"),
]

SENSITIVE_CONTENT_PATTERNS = [
    (r'(?i)DB_PASSWORD\s*=\s*\S+',         "Database Password"),
    (r'(?i)DB_USER\s*=\s*\S+',             "Database Username"),
    (r'(?i)DB_HOST\s*=\s*\S+',             "Database Host"),
    (r'(?i)SECRET_KEY\s*=\s*\S+',          "Secret Key"),
    (r'(?i)API_KEY\s*=\s*\S+',             "API Key"),
    (r'(?i)MAIL_PASSWORD\s*=\s*\S+',       "Mail Password"),
    (r'AKIA[0-9A-Z]{16}',                  "AWS Access Key"),
    (r"(?i)\$password\s*=\s*['\"][^'\"]+", "Hardcoded Password"),
    (r"define\('DB_PASSWORD',[^)]+\)",      "WP DB Password"),
    (r"phpinfo\(\)",                        "PHP Info Exposure"),
]


def harvest_config_files(url: str, output_dir: str) -> dict:
    """Check for exposed configuration and sensitive files."""
    result = {
        "module": "Config File Exposure Scan",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": [],
        "loot": []
    }

    if not HAS_REQUESTS:
        print_warning("requests not installed — skipping config scan")
        return result

    print_info(f"Scanning for exposed config files on {url}...")
    loot_dir = os.path.join(output_dir, "loot", "configs")
    os.makedirs(loot_dir, exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    base = url.rstrip("/")
    found_count = 0

    for path, description in CONFIG_PATHS:
        try:
            r = session.get(base + path, timeout=6, verify=False)
            if r.status_code == 200 and len(r.content) > 10:
                content = r.text

                # Check if it's a real file (not a redirect/error page)
                is_error = any(kw in content.lower() for kw in
                               ("404 not found", "page not found", "error 404",
                                "<html", "not found</title>"))
                if is_error and len(content) > 5000:
                    continue

                sev = "HIGH"
                sensitive_data = []

                for pattern, label in SENSITIVE_CONTENT_PATTERNS:
                    matches = re.findall(pattern, content)
                    for m in matches:
                        sensitive_data.append((label, m[:80]))
                        sev = "CRITICAL"

                result["findings"].append({
                    "type": f"Exposed: {description}",
                    "value": f"{base + path} — {len(content)} bytes" + (
                        f" | Contains: {', '.join(set(l for l, _ in sensitive_data[:3]))}" if sensitive_data else ""
                    ),
                    "severity": sev
                })
                print_error(f"{'CRITICAL' if sev == 'CRITICAL' else 'HIGH'}: {description} exposed: {path}")

                # Save the file
                fname = sanitize_filename(path.lstrip("/") or "root") + ".txt"
                loot_path = os.path.join(loot_dir, fname)
                with open(loot_path, "w", encoding="utf-8", errors="replace") as f:
                    f.write(f"URL: {base + path}\nDescription: {description}\n\n{content[:10000]}")
                result["loot"].append(loot_path)
                found_count += 1

        except Exception:
            continue

    if found_count == 0:
        result["findings"].append({
            "type": "Config Exposure",
            "value": f"No exposed config files found (checked {len(CONFIG_PATHS)} paths)",
            "severity": "INFO"
        })
        print_info("Config scan: No exposed files found")

    result["raw"] = f"Checked {len(CONFIG_PATHS)} paths, found {found_count} exposed files"
    return result


# ─── Git Repository Exposure ──────────────────────────────────────────────────

GIT_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/COMMIT_EDITMSG",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.svn/entries",
    "/.hg/hgrc",
]


def harvest_git_exposure(url: str, output_dir: str) -> dict:
    """Detect exposed .git repositories and attempt to extract data."""
    result = {
        "module": "Git Repository Exposure",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": [],
        "loot": []
    }

    if not HAS_REQUESTS:
        print_warning("requests not installed — skipping git exposure scan")
        return result

    print_info(f"Checking for exposed .git repositories on {url}...")
    loot_dir = os.path.join(output_dir, "loot", "git_exposure")
    os.makedirs(loot_dir, exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    base = url.rstrip("/")
    exposed = False

    for path in GIT_PATHS:
        try:
            r = session.get(base + path, timeout=6, verify=False)
            if r.status_code == 200 and len(r.content) > 5:
                content = r.text
                if "404" in content.lower() and len(content) > 3000:
                    continue

                exposed = True
                sev = "CRITICAL" if ".git" in path else "HIGH"
                result["findings"].append({
                    "type": "Exposed VCS File",
                    "value": f"{base + path} is publicly accessible!",
                    "severity": sev
                })
                print_error(f"{sev}: {path} exposed — source code may be downloadable!")

                # Save the file
                fname = sanitize_filename(path.replace("/", "_").lstrip("_")) + ".txt"
                loot_path = os.path.join(loot_dir, fname)
                with open(loot_path, "w", encoding="utf-8", errors="replace") as f:
                    f.write(f"URL: {base + path}\n\n{content[:5000]}")
                result["loot"].append(loot_path)

                # Try git-dumper if available
                if ".git/HEAD" in path and check_tool("git-dumper"):
                    dump_dir = os.path.join(loot_dir, "repo_dump")
                    os.makedirs(dump_dir, exist_ok=True)
                    print_info("Attempting full git repository dump with git-dumper...")
                    code, stdout, stderr = run_command(
                        ["git-dumper", base + "/.git", dump_dir], timeout=120
                    )
                    if code == 0:
                        result["findings"].append({
                            "type": "Git Repository Dumped",
                            "value": f"Full source code extracted to: {dump_dir}",
                            "severity": "CRITICAL"
                        })
                        result["loot"].append(dump_dir)
                        print_error(f"CRITICAL: Git repo dumped to {dump_dir}!")

        except Exception:
            continue

    if not exposed:
        result["findings"].append({
            "type": "Git Exposure",
            "value": "No exposed .git/.svn files found",
            "severity": "INFO"
        })
        print_info("Git exposure: No exposed repositories found")

    result["raw"] = f"Checked {len(GIT_PATHS)} VCS paths"
    return result


# ─── Backup File Detection ────────────────────────────────────────────────────

def harvest_backup_files(url: str, output_dir: str) -> dict:
    """Detect exposed backup files (.bak, .zip, .sql, .tar.gz)."""
    result = {
        "module": "Backup File Detection",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": [],
        "loot": []
    }

    if not HAS_REQUESTS:
        print_warning("requests not installed — skipping backup scan")
        return result

    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.netloc.replace("www.", "").split(".")[0]  # e.g. "example" from example.com

    print_info(f"Scanning for backup files on {url}...")
    loot_dir = os.path.join(output_dir, "loot", "backups")
    os.makedirs(loot_dir, exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    base = url.rstrip("/")

    backup_targets = []
    # Generic backups
    backup_targets += [
        "/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.tar",
        "/backup.rar", "/site.zip", "/site.tar.gz", "/www.zip",
        "/db.sql", "/database.sql", "/dump.sql", "/data.sql",
        "/backup/backup.zip", "/backups/backup.zip",
        f"/{hostname}.zip", f"/{hostname}.tar.gz", f"/{hostname}.sql",
        f"/{hostname}_backup.zip", f"/{hostname}_db.sql",
        "/old.zip", "/old.tar.gz", "/archive.zip",
        "/.DS_Store", "/Thumbs.db",
        "/error_log", "/access_log", "/debug.log", "/application.log",
        "/storage/logs/laravel.log", "/var/log/app.log",
        "/.bash_history", "/.bash_profile", "/.profile",
    ]

    found = 0
    for path in backup_targets:
        try:
            r = session.get(base + path, timeout=6, verify=False, stream=True)
            if r.status_code == 200:
                content_type = r.headers.get("content-type", "")
                content_length = int(r.headers.get("content-length", 0))

                # Skip if it's clearly an HTML error page
                if "text/html" in content_type and content_length > 5000:
                    first_chunk = next(r.iter_content(1024), b"")
                    if b"404" in first_chunk or b"Not Found" in first_chunk:
                        continue

                sev = "CRITICAL" if any(ext in path for ext in (".sql", ".zip", ".tar", "history", "passwd")) else "HIGH"
                result["findings"].append({
                    "type": "Backup File Exposed",
                    "value": f"{base + path} ({content_length} bytes, {content_type})",
                    "severity": sev
                })
                print_error(f"{sev}: Backup file found: {path} ({content_length} bytes)")
                found += 1

                # Save small files, note large ones
                if content_length < 5_000_000:  # < 5MB
                    fname = sanitize_filename(path.lstrip("/"))
                    loot_path = os.path.join(loot_dir, fname)
                    with open(loot_path, "wb") as f:
                        for chunk in r.iter_content(8192):
                            f.write(chunk)
                    result["loot"].append(loot_path)
                else:
                    result["findings"].append({
                        "type": "Large Backup (Not Downloaded)",
                        "value": f"{base + path} is too large to auto-download ({content_length // 1048576}MB)",
                        "severity": sev
                    })

        except Exception:
            continue

    if found == 0:
        result["findings"].append({
            "type": "Backup Files",
            "value": f"No backup files exposed (checked {len(backup_targets)} paths)",
            "severity": "INFO"
        })
        print_info("Backup scan: No backup files found")

    result["raw"] = f"Checked {len(backup_targets)} paths, found {found} backup files"
    return result


# ─── Sensitive Endpoint Discovery ─────────────────────────────────────────────

SENSITIVE_ENDPOINTS = [
    ("/api/v1/users",        "API Users Endpoint"),
    ("/api/v1/admin",        "API Admin Endpoint"),
    ("/api/v1/keys",         "API Keys Endpoint"),
    ("/api/users",           "API Users"),
    ("/api/admin",           "API Admin"),
    ("/api/config",          "API Config"),
    ("/api/settings",        "API Settings"),
    ("/api/debug",           "Debug Endpoint"),
    ("/api/health",          "Health Check"),
    ("/api/status",          "Status Endpoint"),
    ("/v1/users",            "Users API v1"),
    ("/v2/users",            "Users API v2"),
    ("/graphql",             "GraphQL Endpoint"),
    ("/graphiql",            "GraphiQL IDE"),
    ("/swagger",             "Swagger UI"),
    ("/swagger-ui",          "Swagger UI"),
    ("/swagger.json",        "Swagger JSON"),
    ("/openapi.json",        "OpenAPI Spec"),
    ("/api-docs",            "API Documentation"),
    ("/actuator",            "Spring Actuator"),
    ("/actuator/env",        "Spring Env Dump"),
    ("/actuator/dump",       "Spring Thread Dump"),
    ("/actuator/heapdump",   "Spring Heap Dump"),
    ("/metrics",             "Metrics Endpoint"),
    ("/debug/pprof",         "Go Profiler"),
    ("/console",             "Admin Console"),
    ("/jolokia",             "Jolokia JMX"),
    ("/.well-known/security.txt", "Security.txt"),
]


def harvest_sensitive_endpoints(url: str, output_dir: str) -> dict:
    """Discover and probe sensitive/debug API endpoints."""
    result = {
        "module": "Sensitive Endpoint Discovery",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": [],
        "loot": []
    }

    if not HAS_REQUESTS:
        print_warning("requests not installed — skipping endpoint discovery")
        return result

    print_info(f"Probing sensitive endpoints on {url}...")
    loot_dir = os.path.join(output_dir, "loot", "endpoints")
    os.makedirs(loot_dir, exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
    base = url.rstrip("/")
    found = 0

    for path, description in SENSITIVE_ENDPOINTS:
        try:
            r = session.get(base + path, timeout=6, verify=False)
            if r.status_code in (200, 201):
                content_type = r.headers.get("content-type", "")
                content = r.text[:2000]

                # Is it actually useful data?
                has_data = (
                    "application/json" in content_type or
                    content.lstrip().startswith(("{", "[")) or
                    any(kw in content.lower() for kw in
                        ("password", "token", "secret", "api_key", "email", "user", "admin"))
                )

                if not has_data and "text/html" in content_type:
                    continue

                sev = "CRITICAL" if any(kw in content.lower() for kw in
                      ("password", "secret", "token", "api_key", "private_key")) else "HIGH"

                result["findings"].append({
                    "type": f"Sensitive Endpoint: {description}",
                    "value": f"{base + path} returned HTTP {r.status_code} ({len(r.content)} bytes)",
                    "severity": sev
                })
                print_warning(f"{'CRITICAL' if sev == 'CRITICAL' else 'HIGH'}: {description} at {path}")
                found += 1

                fname = sanitize_filename(path.lstrip("/")) + ".json"
                loot_path = os.path.join(loot_dir, fname)
                with open(loot_path, "w", encoding="utf-8", errors="replace") as f:
                    f.write(f"URL: {base + path}\nStatus: {r.status_code}\nContent-Type: {content_type}\n\n{content}")
                result["loot"].append(loot_path)

        except Exception:
            continue

    if found == 0:
        result["findings"].append({
            "type": "Sensitive Endpoints",
            "value": f"No sensitive endpoints found (checked {len(SENSITIVE_ENDPOINTS)})",
            "severity": "INFO"
        })
        print_info("Endpoint scan: No sensitive endpoints found")

    result["raw"] = f"Checked {len(SENSITIVE_ENDPOINTS)} endpoints, found {found}"
    return result


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def run_data_harvest(session_obj, output_dir: str) -> list:
    """Run all data harvesting modules."""
    results = []

    console.print("\n[bold magenta]  ╔══════════════════════════════════╗[/bold magenta]")
    console.print("[bold magenta]  ║   DATA HARVESTING — GHOST RECON  ║[/bold magenta]")
    console.print("[bold magenta]  ╚══════════════════════════════════╝[/bold magenta]\n")

    url = session_obj.url

    r1 = harvest_js_secrets(url, output_dir)
    session_obj.add_result(r1)
    results.append(r1)

    r2 = harvest_config_files(url, output_dir)
    session_obj.add_result(r2)
    results.append(r2)

    r3 = harvest_git_exposure(url, output_dir)
    session_obj.add_result(r3)
    results.append(r3)

    r4 = harvest_backup_files(url, output_dir)
    session_obj.add_result(r4)
    results.append(r4)

    r5 = harvest_sensitive_endpoints(url, output_dir)
    session_obj.add_result(r5)
    results.append(r5)

    # Summary table
    total_loot = sum(len(r.get("loot", [])) for r in results)
    total_critical = sum(
        len([f for f in r.get("findings", []) if f.get("severity") == "CRITICAL"])
        for r in results
    )

    table = Table(title="Data Harvest Summary", box=box.DOUBLE_EDGE, header_style="bold magenta")
    table.add_column("Module", style="white")
    table.add_column("Findings", width=10)
    table.add_column("Loot Files", width=10)

    for r in results:
        crit = len([f for f in r.get("findings", []) if f.get("severity") == "CRITICAL"])
        finding_str = f"[bold red]{crit} CRITICAL[/bold red]" if crit else f"{len(r.get('findings', []))} info"
        table.add_row(r["module"], finding_str, str(len(r.get("loot", []))))

    console.print(table)
    console.print(f"\n[bold]  Critical: {total_critical} | Loot files: {total_loot}[/bold]")
    if total_loot:
        console.print(f"  [bold green]Saved to: {os.path.join(output_dir, 'loot')}[/bold green]")

    return results
