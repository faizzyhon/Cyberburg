"""
Directory & File Bruteforcing Module — Cyberburg
Handles: Gobuster, Dirb, FFuf, and manual directory enumeration
"""

import os
import re
from utils.helpers import run_command, get_timestamp
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console

console = Console()

# Default wordlists (common Linux locations)
WORDLISTS = {
    "common": [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    ],
    "small": [
        "/usr/share/wordlists/dirb/small.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    ],
    "big": [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
    ],
    "api": [
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
    ]
}

SENSITIVE_PATHS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    ".git", ".env", ".htaccess", "config", "backup", "db", "database",
    "phpmyadmin", "pma", "mysql", "myadmin", "sql", "shell", "cmd",
    "upload", "uploads", "files", "file", "includes", "include",
    "api", "v1", "v2", "graphql", "swagger", "api-docs",
    "test", "testing", "dev", "debug", "staging",
    "console", "dashboard", "panel", "cpanel", "plesk",
    "etc/passwd", "proc/self/environ", "windows/win.ini",
]


def get_wordlist(size: str = "common") -> str:
    """Get the best available wordlist."""
    for path in WORDLISTS.get(size, WORDLISTS["common"]):
        if os.path.isfile(path):
            return path
    # Fallback: embedded mini wordlist
    return _create_embedded_wordlist()


def _create_embedded_wordlist() -> str:
    """Create a minimal embedded wordlist if none found."""
    path = "/tmp/cyberburg_wordlist.txt"
    words = SENSITIVE_PATHS + [
        "index", "home", "main", "default", "images", "img", "css", "js",
        "fonts", "static", "assets", "media", "public", "private",
        "user", "users", "account", "accounts", "profile", "auth",
        "login", "logout", "register", "signup", "forgot", "reset",
        "search", "sitemap", "feed", "rss", "contact", "about",
        "cgi-bin", "server-status", "server-info", ".well-known",
        "robots.txt", "sitemap.xml", "favicon.ico", "crossdomain.xml",
        "phpinfo.php", "info.php", "wp-config.php.bak", "config.php",
        "readme.txt", "README.md", "CHANGELOG", "license.txt",
        ".DS_Store", "Thumbs.db", ".git/config", ".svn",
        "error_log", "access_log", "debug.log",
    ]
    with open(path, "w") as f:
        f.write('\n'.join(set(words)))
    return path


def gobuster_scan(target: str, wordlist: str = None, extensions: str = "php,html,js,txt,bak,xml,json,asp,aspx") -> dict:
    """Directory/file bruteforce using Gobuster."""
    result = {
        "module": "Directory Bruteforce (Gobuster)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "found_paths": [],
        "findings": []
    }

    if not check_tool("gobuster"):
        print_warning("gobuster not found — trying dirb")
        return dirb_scan(target, wordlist)

    if not wordlist:
        wordlist = get_wordlist("common")

    print_info(f"Running Gobuster on {target} with wordlist: {os.path.basename(wordlist)}...")

    code, stdout, stderr = run_command(
        [
            "gobuster", "dir",
            "-u", target,
            "-w", wordlist,
            "-x", extensions,
            "-t", "50",
            "-q",
            "--no-error",
            "-r",           # Follow redirects
            "--timeout", "10s",
            "--status-codes-blacklist", "404,403",
        ],
        timeout=600
    )

    result["raw"] = stdout + stderr
    result = _parse_gobuster_output(stdout, result)
    print_success(f"Gobuster complete — {len(result['found_paths'])} paths found")
    return result


def dirb_scan(target: str, wordlist: str = None) -> dict:
    """Directory brute force using Dirb."""
    result = {
        "module": "Directory Bruteforce (Dirb)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "found_paths": [],
        "findings": []
    }

    if not check_tool("dirb"):
        print_warning("dirb not found — using ffuf")
        return ffuf_scan(target, wordlist)

    if not wordlist:
        wordlist = get_wordlist("common")

    print_info(f"Running Dirb on {target}...")

    code, stdout, stderr = run_command(
        ["dirb", target, wordlist, "-S", "-r", "-w"],
        timeout=600
    )

    result["raw"] = stdout + stderr

    # Parse dirb output
    found = re.findall(r'==> DIRECTORY: (.+)', stdout)
    found += re.findall(r'\+ (.+) \(CODE:\d+', stdout)

    for path in found:
        path = path.strip()
        result["found_paths"].append(path)
        severity = _check_path_sensitivity(path)
        result["findings"].append({
            "type": "Directory/File Found",
            "value": path,
            "severity": severity
        })

    print_success(f"Dirb complete — {len(result['found_paths'])} paths found")
    return result


def ffuf_scan(target: str, wordlist: str = None) -> dict:
    """Directory/file fuzzing using FFuf."""
    result = {
        "module": "Directory Bruteforce (FFuf)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "found_paths": [],
        "findings": []
    }

    if not check_tool("ffuf"):
        print_warning("ffuf not found — using manual path check")
        return manual_path_check(target)

    if not wordlist:
        wordlist = get_wordlist("common")

    # Ensure target ends with FUZZ
    url = target.rstrip('/') + "/FUZZ"

    print_info(f"Running FFuf on {target}...")

    code, stdout, stderr = run_command(
        [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-t", "50",
            "-mc", "200,201,204,301,302,307,401,403",
            "-fc", "404",
            "-timeout", "10",
            "-r",
            "-s",       # Silent mode
            "-o", "/tmp/cyberburg_ffuf.json",
            "-of", "json",
        ],
        timeout=600
    )

    result["raw"] = stdout + stderr

    # Parse JSON output
    try:
        import json
        with open("/tmp/cyberburg_ffuf.json") as f:
            ffuf_data = json.load(f)
        for entry in ffuf_data.get("results", []):
            path = entry.get("url", "")
            status = entry.get("status", 0)
            result["found_paths"].append(path)
            severity = _check_path_sensitivity(path)
            result["findings"].append({
                "type": f"Path Found (HTTP {status})",
                "value": path,
                "severity": severity
            })
    except Exception:
        # Fallback: parse stdout
        for line in stdout.split('\n'):
            if '[Status:' in line or '200' in line:
                result["found_paths"].append(line.strip())

    print_success(f"FFuf complete — {len(result['found_paths'])} paths found")
    return result


def manual_path_check(target: str) -> dict:
    """Manually probe common sensitive paths using curl."""
    result = {
        "module": "Manual Sensitive Path Check",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "found_paths": [],
        "findings": []
    }

    if not check_tool("curl"):
        return result

    print_info(f"Probing common sensitive paths on {target}...")

    critical_paths = [
        "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
        "/config.php", "/wp-config.php", "/configuration.php",
        "/phpinfo.php", "/info.php", "/test.php",
        "/admin/", "/administrator/", "/wp-admin/",
        "/phpmyadmin/", "/pma/", "/mysql/",
        "/.htaccess", "/.htpasswd",
        "/backup/", "/backup.sql", "/backup.zip",
        "/database.sql", "/db.sql", "/dump.sql",
        "/api/v1/", "/api/v2/", "/graphql",
        "/swagger.json", "/api-docs/",
        "/server-status", "/server-info",
        "/console", "/shell.php", "/c99.php", "/r57.php",
        "/upload.php", "/filemanager/",
        "/.DS_Store", "/Thumbs.db",
        "/error_log", "/access_log",
        "/proc/self/environ",
        "/etc/passwd",
    ]

    for path in critical_paths:
        code, stdout, _ = run_command(
            ["curl", "-sI", "--max-time", "8", "-L",
             f"{target}{path}", "-o", "/dev/null",
             "-w", "%{http_code}"],
            timeout=15
        )

        status = stdout.strip()
        if status in ["200", "301", "302", "401", "403"]:
            result["found_paths"].append(f"{target}{path}")
            severity = _check_path_sensitivity(path)

            # Special escalation for accessible sensitive files
            if status == "200" and any(p in path for p in ['.env', '.git', 'config', 'phpinfo', 'admin', 'backup', 'sql', '.htpasswd']):
                severity = "CRITICAL"

            result["findings"].append({
                "type": f"Sensitive Path Accessible (HTTP {status})",
                "value": f"{target}{path} — HTTP {status}",
                "severity": severity
            })
            if severity in ["CRITICAL", "HIGH"]:
                print_error(f"[{severity}] Found: {target}{path} — HTTP {status}")
            else:
                print_info(f"[{severity}] Found: {target}{path} — HTTP {status}")

    result["raw"] = f"Checked {len(critical_paths)} sensitive paths\n" + \
                    "\n".join(result["found_paths"])

    print_success(f"Manual path check done — {len(result['found_paths'])} paths accessible")
    return result


def api_fuzzing(target: str) -> dict:
    """Fuzz for API endpoints."""
    result = {
        "module": "API Endpoint Discovery",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "found_paths": [],
        "findings": []
    }

    if not check_tool("ffuf") and not check_tool("gobuster"):
        print_warning("Neither ffuf nor gobuster available for API fuzzing")
        return result

    wordlist = get_wordlist("api")
    print_info(f"Fuzzing API endpoints on {target}...")

    api_bases = ["/api/", "/api/v1/", "/api/v2/", "/v1/", "/v2/", "/rest/"]

    for api_base in api_bases:
        code, stdout, _ = run_command(
            ["curl", "-sI", "--max-time", "8",
             f"{target}{api_base}", "-w", "%{http_code}", "-o", "/dev/null"],
            timeout=15
        )
        if stdout.strip() in ["200", "401", "403"]:
            result["findings"].append({
                "type": "API Base Found",
                "value": f"API endpoint: {target}{api_base} (HTTP {stdout.strip()})",
                "severity": "MEDIUM"
            })

    # Run ffuf on API-specific wordlist if available
    if os.path.isfile(wordlist) and check_tool("ffuf"):
        url = f"{target}/FUZZ"
        code, stdout, _ = run_command(
            [
                "ffuf", "-u", url,
                "-w", wordlist,
                "-t", "30",
                "-mc", "200,201,204,401,403",
                "-timeout", "10",
                "-s",
            ],
            timeout=300
        )

        for line in stdout.split('\n'):
            if line.strip():
                result["found_paths"].append(line.strip())
                result["findings"].append({
                    "type": "API Endpoint Found",
                    "value": line.strip(),
                    "severity": "MEDIUM"
                })

    return result


def _parse_gobuster_output(output: str, result: dict) -> dict:
    """Parse Gobuster output for found paths."""
    # Match lines like: /admin (Status: 200) [Size: 4096]
    pattern = re.compile(r'(/[^\s]+)\s+\(Status:\s*(\d+)\)')

    for match in pattern.finditer(output):
        path = match.group(1)
        status = match.group(2)
        result["found_paths"].append(path)
        severity = _check_path_sensitivity(path)

        if status in ["200", "201"] and any(
            sensitive in path.lower() for sensitive in
            ['.env', '.git', 'admin', 'config', 'backup', 'sql', '.htpasswd', 'phpinfo']
        ):
            severity = "CRITICAL"

        result["findings"].append({
            "type": f"Path Found (HTTP {status})",
            "value": f"{path} — HTTP {status}",
            "severity": severity
        })

    return result


def _check_path_sensitivity(path: str) -> str:
    """Determine severity based on path sensitivity."""
    path_lower = path.lower()

    critical_keywords = [
        '.env', '.git', 'config.php', 'wp-config', '.htpasswd',
        'shell.php', 'c99', 'r57', 'backup.sql', 'database.sql',
        'dump.sql', '/etc/passwd', 'phpinfo', 'proc/self',
    ]
    high_keywords = [
        'admin', 'phpmyadmin', 'pma', 'backup', 'upload',
        'shell', 'console', 'debug', '.svn', 'sql', 'db',
        'api-docs', 'swagger', 'graphql', 'server-status',
    ]
    medium_keywords = [
        'login', 'auth', 'user', 'account', 'test', 'api',
        'panel', 'dashboard', 'manage', 'manager',
    ]

    for kw in critical_keywords:
        if kw in path_lower:
            return "CRITICAL"
    for kw in high_keywords:
        if kw in path_lower:
            return "HIGH"
    for kw in medium_keywords:
        if kw in path_lower:
            return "MEDIUM"
    return "INFO"
