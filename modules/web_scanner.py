"""
Web Scanner Module — Cyberburg
Handles: Nikto, WhatWeb, WAF Detection, HTTP method testing, CMS detection
"""

import re
import json
import urllib.request
import urllib.error
from utils.helpers import run_command, get_timestamp
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console

console = Console()

# Security headers that MUST be present
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "desc": "HSTS missing — site vulnerable to protocol downgrade attacks"
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "desc": "Missing X-Content-Type-Options — MIME sniffing attacks possible"
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "desc": "Missing X-Frame-Options — clickjacking attacks possible"
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "desc": "Missing CSP — XSS and injection attacks easier"
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "desc": "Missing X-XSS-Protection header"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "desc": "Missing Referrer-Policy — referrer data leakage possible"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "desc": "Missing Permissions-Policy header"
    },
}

DANGEROUS_HEADERS = {
    "Server": "Server header reveals web server version",
    "X-Powered-By": "X-Powered-By reveals technology stack",
    "X-AspNet-Version": "Reveals ASP.NET version",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
}


def nikto_scan(target: str) -> dict:
    """Run Nikto web vulnerability scanner."""
    result = {
        "module": "Nikto Web Scanner",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("nikto"):
        print_warning("nikto not found — skipping web scan")
        return result

    print_info(f"Running Nikto on {target} (this takes a few minutes)...")

    code, stdout, stderr = run_command(
        ["nikto", "-h", target, "-output", "/tmp/cyberburg_nikto.txt",
         "-Format", "txt", "-nointeractive", "-Tuning", "1234567890abc"],
        timeout=600
    )

    result["raw"] = stdout + stderr

    # Parse Nikto findings
    severity_map = {
        "OSVDB": "HIGH",
        "CVE": "HIGH",
        "XSS": "HIGH",
        "injection": "HIGH",
        "SQL": "HIGH",
        "vulnerable": "HIGH",
        "default": "MEDIUM",
        "allowed": "MEDIUM",
        "outdated": "HIGH",
        "disclosure": "MEDIUM",
        "directory listing": "HIGH",
        "backup": "HIGH",
        "config": "HIGH",
        "password": "CRITICAL",
        "admin": "HIGH",
        "interesting": "INFO",
    }

    for line in (stdout + stderr).split('\n'):
        if line.startswith('+'):
            line_clean = line.lstrip('+ ').strip()
            if not line_clean or 'Target ' in line_clean or 'Start Time' in line_clean:
                continue

            severity = "INFO"
            for keyword, sev in severity_map.items():
                if keyword.lower() in line_clean.lower():
                    severity = sev
                    break

            result["findings"].append({
                "type": "Nikto Finding",
                "value": line_clean,
                "severity": severity
            })

    print_success(f"Nikto complete — {len(result['findings'])} findings")
    return result


def whatweb_scan(target: str) -> dict:
    """Fingerprint web technologies using WhatWeb."""
    result = {
        "module": "WhatWeb Technology Fingerprint",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "technologies": [],
        "findings": []
    }

    if not check_tool("whatweb"):
        print_warning("whatweb not found — using fallback fingerprinting")
        return _fallback_fingerprint(target, result)

    print_info(f"Fingerprinting {target} with WhatWeb...")

    code, stdout, stderr = run_command(
        ["whatweb", "--log-brief=-", "-a", "3", target],
        timeout=60
    )

    result["raw"] = stdout + stderr

    # Parse technology names
    tech_pattern = re.compile(r'(\w[\w\-\.]+)\[([^\]]+)\]')
    for match in tech_pattern.finditer(stdout):
        tech_name = match.group(1)
        tech_version = match.group(2)
        result["technologies"].append({"name": tech_name, "version": tech_version})

        # Flag dangerous version disclosures
        result["findings"].append({
            "type": "Technology Detected",
            "value": f"{tech_name} {tech_version}",
            "severity": "INFO"
        })

    # Flag CMS detections
    cms_list = ["WordPress", "Joomla", "Drupal", "Magento", "Django", "Laravel", "Ruby-on-Rails"]
    for cms in cms_list:
        if cms.lower() in stdout.lower():
            result["findings"].append({
                "type": f"CMS Detected: {cms}",
                "value": f"{cms} CMS detected — run specialized scanner for deeper analysis",
                "severity": "INFO"
            })

    print_success(f"WhatWeb complete — {len(result['technologies'])} technologies found")
    return result


def _fallback_fingerprint(target: str, result: dict) -> dict:
    """Basic fingerprinting using curl/requests when whatweb unavailable."""
    if not check_tool("curl"):
        return result

    code, stdout, stderr = run_command(
        ["curl", "-sI", "--max-time", "15", "-L", target], timeout=30
    )

    result["raw"] = stdout
    _parse_headers(stdout, target, result)
    return result


def waf_detection(target: str) -> dict:
    """Detect Web Application Firewalls."""
    result = {
        "module": "WAF Detection",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "waf": None,
        "findings": []
    }

    # Method 1: wafw00f
    if check_tool("wafw00f"):
        print_info(f"Running WAF detection on {target}...")
        code, stdout, stderr = run_command(
            ["wafw00f", "-a", target], timeout=60
        )
        result["raw"] = stdout + stderr

        # Parse result
        if "is behind" in stdout:
            waf_match = re.search(r'is behind (\w[\w\s]+)', stdout)
            if waf_match:
                result["waf"] = waf_match.group(1).strip()
                result["findings"].append({
                    "type": "WAF Detected",
                    "value": f"Web Application Firewall detected: {result['waf']}",
                    "severity": "INFO"
                })
                print_success(f"WAF detected: {result['waf']}")
        elif "No WAF" in stdout or "not behind" in stdout:
            result["waf"] = "None"
            result["findings"].append({
                "type": "No WAF Detected",
                "value": "No Web Application Firewall detected — attack surface is unprotected",
                "severity": "HIGH"
            })
            print_warning("No WAF detected!")

    # Method 2: Heuristic WAF detection via curl
    if not result["waf"] and check_tool("curl"):
        print_info("WAF heuristic detection via crafted requests...")
        xss_payload = '<script>alert(1)</script>'
        code, stdout, stderr = run_command(
            ["curl", "-sI", "--max-time", "10",
             f"{target}/?test={xss_payload}"],
            timeout=20
        )
        result["raw"] += stdout

        waf_signatures = {
            "cloudflare": "Cloudflare",
            "sucuri": "Sucuri",
            "akamai": "Akamai",
            "incapsula": "Imperva Incapsula",
            "mod_security": "ModSecurity",
            "f5": "F5 BIG-IP",
            "barracuda": "Barracuda",
        }

        for sig, name in waf_signatures.items():
            if sig.lower() in (stdout + stderr).lower():
                result["waf"] = name
                result["findings"].append({
                    "type": "WAF Detected (Heuristic)",
                    "value": f"WAF signatures found: {name}",
                    "severity": "INFO"
                })
                break

    return result


def http_methods_check(target: str) -> dict:
    """Check for dangerous HTTP methods enabled."""
    result = {
        "module": "HTTP Methods Check",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("curl"):
        print_warning("curl not found — skipping HTTP methods check")
        return result

    print_info(f"Checking HTTP methods on {target}...")

    # OPTIONS request to discover allowed methods
    code, stdout, stderr = run_command(
        ["curl", "-sI", "-X", "OPTIONS", "--max-time", "15", target],
        timeout=30
    )

    result["raw"] = stdout

    allow_header = ""
    for line in stdout.split('\n'):
        if line.lower().startswith("allow:"):
            allow_header = line.split(':', 1)[1].strip()
            break

    dangerous_methods = {
        "PUT": ("CRITICAL", "PUT method enabled — may allow arbitrary file upload"),
        "DELETE": ("HIGH", "DELETE method enabled — may allow file/resource deletion"),
        "TRACE": ("MEDIUM", "TRACE method enabled — enables XST (Cross-Site Tracing) attacks"),
        "CONNECT": ("HIGH", "CONNECT method enabled — can be used for tunneling"),
        "PATCH": ("LOW", "PATCH method enabled — partial resource modification possible"),
    }

    for method, (severity, desc) in dangerous_methods.items():
        if method in allow_header:
            result["findings"].append({
                "type": f"Dangerous HTTP Method: {method}",
                "value": desc,
                "severity": severity
            })
            print_warning(f"Dangerous method enabled: {method}")

    if allow_header:
        result["findings"].append({
            "type": "HTTP Methods Allowed",
            "value": f"Allowed: {allow_header}",
            "severity": "INFO"
        })

    # Test PUT directly
    code, stdout, stderr = run_command(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "-X", "PUT", "--max-time", "10",
         "-d", "cyberburg_test", f"{target}/cyberburg_test.txt"],
        timeout=20
    )

    if stdout.strip() in ["200", "201", "204"]:
        result["findings"].append({
            "type": "File Upload via PUT",
            "value": "PUT method allows file upload! Server returned success on test upload.",
            "severity": "CRITICAL"
        })
        print_error("CRITICAL: File upload via PUT is possible!")

    print_success("HTTP methods check complete")
    return result


def header_analysis(target: str) -> dict:
    """Deep HTTP security header analysis."""
    result = {
        "module": "HTTP Security Header Analysis",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "headers": {},
        "findings": [],
        "score": 100
    }

    if not check_tool("curl"):
        print_warning("curl not found — skipping header analysis")
        return result

    print_info(f"Analyzing HTTP security headers on {target}...")

    code, stdout, stderr = run_command(
        ["curl", "-sI", "-L", "--max-time", "20", "-A",
         "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
         target],
        timeout=40
    )

    result["raw"] = stdout

    # Parse headers
    headers = {}
    for line in stdout.split('\n'):
        if ':' in line:
            key, _, val = line.partition(':')
            headers[key.strip()] = val.strip()

    result["headers"] = headers
    _parse_headers(stdout, target, result)

    print_success(f"Header analysis complete — security score: {result['score']}/100")
    return result


def _parse_headers(raw_headers: str, target: str, result: dict):
    """Parse HTTP headers and generate findings."""
    headers = {}
    for line in raw_headers.split('\n'):
        if ':' in line:
            key, _, val = line.partition(':')
            headers[key.strip().lower()] = val.strip()

    # Check for required security headers
    deductions = {
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 5,
    }

    for header, info in REQUIRED_SECURITY_HEADERS.items():
        if header.lower() not in headers:
            result["findings"].append({
                "type": f"Missing Security Header: {header}",
                "value": info["desc"],
                "severity": info["severity"]
            })
            result["score"] = max(0, result.get("score", 100) - deductions.get(info["severity"], 5))

    # Check for dangerous information-revealing headers
    for header, desc in DANGEROUS_HEADERS.items():
        if header.lower() in headers:
            value = headers[header.lower()]
            result["findings"].append({
                "type": f"Information Disclosure: {header}",
                "value": f"{desc}: '{value}'",
                "severity": "LOW"
            })

    # Check HTTPS redirect
    if "location" in headers and target.startswith("http://"):
        location = headers["location"]
        if not location.startswith("https://"):
            result["findings"].append({
                "type": "No HTTPS Redirect",
                "value": "HTTP not redirecting to HTTPS — traffic can be intercepted",
                "severity": "HIGH"
            })

    # Check for cookies
    set_cookie_headers = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for cookie in set_cookie_headers:
        if "httponly" not in cookie.lower():
            result["findings"].append({
                "type": "Cookie Missing HttpOnly Flag",
                "value": f"Cookie without HttpOnly: {cookie[:80]}",
                "severity": "MEDIUM"
            })
        if "secure" not in cookie.lower():
            result["findings"].append({
                "type": "Cookie Missing Secure Flag",
                "value": f"Cookie without Secure flag: {cookie[:80]}",
                "severity": "MEDIUM"
            })
        if "samesite" not in cookie.lower():
            result["findings"].append({
                "type": "Cookie Missing SameSite Attribute",
                "value": f"Cookie without SameSite: {cookie[:80]}",
                "severity": "LOW"
            })


def cms_scan(target: str) -> dict:
    """Detect and scan CMS (WordPress, Joomla, Drupal)."""
    result = {
        "module": "CMS Detection & Scan",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "cms": None,
        "findings": []
    }

    if not check_tool("curl"):
        return result

    print_info(f"Detecting CMS on {target}...")

    # WordPress detection
    code, stdout, _ = run_command(
        ["curl", "-sL", "--max-time", "15", f"{target}/wp-login.php"], timeout=25
    )

    if "wp-login" in stdout or "WordPress" in stdout:
        result["cms"] = "WordPress"
        result["findings"].append({
            "type": "WordPress Detected",
            "value": "WordPress CMS identified",
            "severity": "INFO"
        })

        # Check readme/version disclosure
        code2, stdout2, _ = run_command(
            ["curl", "-sL", "--max-time", "10", f"{target}/readme.html"], timeout=20
        )
        if "WordPress" in stdout2:
            ver = re.search(r'Version\s+([\d.]+)', stdout2)
            if ver:
                result["findings"].append({
                    "type": "WordPress Version Disclosed",
                    "value": f"WordPress version {ver.group(1)} revealed in readme.html",
                    "severity": "MEDIUM"
                })

        # Run wpscan if available
        if check_tool("wpscan"):
            print_info("Running WPScan...")
            code3, stdout3, _ = run_command(
                ["wpscan", "--url", target, "--no-update",
                 "--enumerate", "u,p,vp,vt,tt,cb,dbe",
                 "--format", "cli-no-colour"],
                timeout=300
            )
            result["raw"] += stdout3

            # Parse WPScan findings
            for line in stdout3.split('\n'):
                if '[!' in line or '[+]' in line:
                    severity = "HIGH" if '[!]' in line else "INFO"
                    finding = re.sub(r'\[\+\]|\[!\]|\033\[[0-9;]*m', '', line).strip()
                    if finding:
                        result["findings"].append({
                            "type": "WPScan Finding",
                            "value": finding,
                            "severity": severity
                        })

    # Joomla detection
    code, stdout, _ = run_command(
        ["curl", "-sL", "--max-time", "15", f"{target}/administrator/"], timeout=25
    )

    if "joomla" in stdout.lower():
        result["cms"] = "Joomla"
        result["findings"].append({
            "type": "Joomla Detected",
            "value": "Joomla CMS identified — admin panel at /administrator/",
            "severity": "MEDIUM"
        })

    # Drupal detection
    code, stdout, _ = run_command(
        ["curl", "-sL", "--max-time", "15", f"{target}/CHANGELOG.txt"], timeout=25
    )

    if "Drupal" in stdout:
        result["cms"] = "Drupal"
        ver = re.search(r'Drupal ([\d.]+)', stdout)
        result["findings"].append({
            "type": "Drupal Detected + Version Disclosed",
            "value": f"Drupal CMS detected{f' version {ver.group(1)}' if ver else ''}. CHANGELOG.txt publicly accessible.",
            "severity": "HIGH"
        })

    if not result["cms"]:
        print_info("No common CMS detected")
    else:
        print_success(f"CMS detected: {result['cms']}")

    return result


def robots_sitemap_check(target: str) -> dict:
    """Check robots.txt and sitemap.xml for sensitive paths."""
    result = {
        "module": "Robots.txt & Sitemap Analysis",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("curl"):
        return result

    print_info(f"Checking robots.txt and sitemap.xml on {target}...")

    for path in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/.well-known/"]:
        code, stdout, _ = run_command(
            ["curl", "-sL", "--max-time", "10", "-w", "\n%{http_code}",
             f"{target}{path}"],
            timeout=20
        )

        lines = stdout.strip().split('\n')
        status = lines[-1] if lines else "0"
        content = '\n'.join(lines[:-1])

        if status == "200":
            result["raw"] += f"=== {path} ===\n{content}\n\n"

            if path == "/robots.txt":
                # Extract disallowed paths — these might be sensitive
                disallowed = re.findall(r'[Dd]isallow:\s*(.+)', content)
                for path_disallowed in disallowed:
                    path_disallowed = path_disallowed.strip()
                    if path_disallowed and path_disallowed != '/':
                        result["findings"].append({
                            "type": "Sensitive Path in robots.txt",
                            "value": f"Disallowed path reveals potentially sensitive location: {path_disallowed}",
                            "severity": "LOW"
                        })

                result["findings"].append({
                    "type": "robots.txt Found",
                    "value": f"robots.txt accessible — {len(disallowed)} disallowed paths found",
                    "severity": "INFO"
                })

            elif "sitemap" in path:
                urls = re.findall(r'<loc>(.+?)</loc>', content)
                result["findings"].append({
                    "type": "Sitemap Found",
                    "value": f"sitemap.xml found — {len(urls)} URLs mapped",
                    "severity": "INFO"
                })

    return result
