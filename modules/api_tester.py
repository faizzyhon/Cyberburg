#!/usr/bin/env python3
"""
API Security Tester — Cyberburg v5 PHANTOM PROTOCOL
REST/GraphQL security: BOLA/IDOR, mass assignment, rate limiting,
GraphQL introspection, JWT abuse, verb tampering, sensitive data leakage.

AUTHORIZED PENETRATION TESTING ONLY.
"""

import os
import re
import json
import time
import threading

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

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Cyberburg/5.0; +https://github.com/faizzyhon)",
    "Accept": "application/json, */*",
    "Content-Type": "application/json"
}

# ─── API Endpoint Discovery ───────────────────────────────────────────────────

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/v1", "/v2", "/v3",
    "/graphql", "/graphiql", "/playground",
    "/api/users", "/api/user", "/api/admin", "/api/me",
    "/api/profile", "/api/account", "/api/accounts",
    "/api/products", "/api/items", "/api/orders",
    "/api/config", "/api/settings", "/api/health",
    "/api/status", "/api/version", "/api/info",
    "/api/auth", "/api/login", "/api/token", "/api/refresh",
    "/api/password", "/api/reset", "/api/register",
    "/api/upload", "/api/download", "/api/files",
    "/api/search", "/api/query", "/api/export",
    "/api/debug", "/api/test", "/api/dev",
    "/swagger.json", "/swagger/v1/swagger.json",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json",
    "/docs", "/redoc",
    "/.well-known/openid-configuration",
]

SENSITIVE_PATTERNS = {
    "API Key":        re.compile(r'(?i)"?api[_-]?key"?\s*[:=]\s*"([^"]{8,})"'),
    "Secret":         re.compile(r'(?i)"?secret"?\s*[:=]\s*"([^"]{8,})"'),
    "Password":       re.compile(r'(?i)"?passw(?:or)?d"?\s*[:=]\s*"([^"]{4,})"'),
    "Token":          re.compile(r'(?i)"?token"?\s*[:=]\s*"([A-Za-z0-9\-_\.]{20,})"'),
    "AWS Key":        re.compile(r'AKIA[0-9A-Z]{16}'),
    "Private Key":    re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
    "Email":          re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}\b'),
    "SSN":            re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "Credit Card":    re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'),
}


def discover_api_endpoints(url: str, output_dir: str) -> dict:
    """Probe common API paths and collect live endpoints."""
    result = {
        "module": "API Tester — Endpoint Discovery",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "endpoints": [],
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests library not available"
        return result

    print_info(f"Discovering API endpoints on {url}...")
    base = url.rstrip("/")
    found = []

    for path in API_PATHS:
        try:
            r = requests.get(f"{base}{path}", headers=HEADERS, timeout=8,
                             verify=False, allow_redirects=False)
            if r.status_code not in (404, 410):
                entry = {
                    "path": path,
                    "status": r.status_code,
                    "size": len(r.content),
                    "ct": r.headers.get("Content-Type", "")
                }
                found.append(entry)
                sev = "HIGH" if path in ("/api/debug", "/api/test", "/api/dev") else (
                    "MEDIUM" if r.status_code == 200 else "LOW"
                )
                print_success(f"[{r.status_code}] {path}")
                result["findings"].append({
                    "type": "API Endpoint Found",
                    "severity": sev,
                    "url": f"{base}{path}",
                    "detail": f"HTTP {r.status_code} — {entry['ct'][:60]}"
                })
        except Exception:
            pass

    result["endpoints"] = found
    result["raw"] = f"Discovered {len(found)} API endpoints"

    # Save endpoints list
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)
    ep_file = os.path.join(loot_dir, "api_endpoints.txt")
    with open(ep_file, "w") as f:
        for e in found:
            f.write(f"[{e['status']}] {base}{e['path']}\n")

    return result


# ─── BOLA / IDOR ──────────────────────────────────────────────────────────────

def bola_idor_test(url: str, output_dir: str) -> dict:
    """Test for Broken Object Level Authorization / IDOR."""
    result = {
        "module": "API Tester — BOLA/IDOR",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests library not available"
        return result

    print_info("Testing BOLA/IDOR on API resource endpoints...")
    base = url.rstrip("/")

    resource_paths = [
        "/api/users/{id}", "/api/user/{id}", "/api/accounts/{id}",
        "/api/orders/{id}", "/api/products/{id}", "/api/items/{id}",
        "/api/profile/{id}", "/api/files/{id}", "/api/documents/{id}",
        "/api/v1/users/{id}", "/api/v2/users/{id}",
    ]

    vuln_count = 0
    for path_template in resource_paths:
        responses = {}
        for uid in [1, 2, 3, 100, 999]:
            path = path_template.replace("{id}", str(uid))
            try:
                r = requests.get(f"{base}{path}", headers=HEADERS, timeout=8,
                                 verify=False, allow_redirects=False)
                responses[uid] = (r.status_code, len(r.content))
            except Exception:
                pass

        # If IDs 1 and 2 both return 200 with different content sizes → possible IDOR
        if (responses.get(1, (0,))[0] == 200 and
                responses.get(2, (0,))[0] == 200 and
                responses.get(1, (0, 0))[1] != responses.get(2, (0, 0))[1]):
            vuln_count += 1
            result["findings"].append({
                "type": "BOLA/IDOR",
                "severity": "HIGH",
                "url": f"{base}{path_template}",
                "detail": f"IDs 1 and 2 return 200 with different body sizes — object-level auth may be missing"
            })
            print_success(f"Possible IDOR: {path_template}")

    result["raw"] = f"BOLA/IDOR test complete — {vuln_count} potential issues found"
    return result


# ─── Mass Assignment ──────────────────────────────────────────────────────────

def mass_assignment_test(url: str, output_dir: str) -> dict:
    """Test for mass assignment vulnerabilities on writable endpoints."""
    result = {
        "module": "API Tester — Mass Assignment",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests library not available"
        return result

    print_info("Testing mass assignment vulnerabilities...")
    base = url.rstrip("/")

    targets = [
        "/api/users/1", "/api/user/1", "/api/profile",
        "/api/account", "/api/me", "/api/v1/users/1",
    ]

    privileged_fields = ["isAdmin", "is_admin", "role", "admin", "superuser",
                         "privilege", "permissions", "verified", "email_verified",
                         "credits", "balance", "subscription"]

    for path in targets:
        full_url = f"{base}{path}"
        for field in privileged_fields:
            payload = json.dumps({field: True})
            try:
                r = requests.put(full_url, data=payload, headers=HEADERS,
                                 timeout=8, verify=False)
                if r.status_code in (200, 201, 204):
                    # Check if the field appears in the response
                    body = r.text
                    if field.lower() in body.lower() and "true" in body.lower():
                        result["findings"].append({
                            "type": "Mass Assignment",
                            "severity": "CRITICAL",
                            "url": full_url,
                            "detail": f"PUT with '{field}': true returned {r.status_code} and field reflected in response"
                        })
                        print_success(f"Mass assignment: {field} on {path}")
                    elif r.status_code in (200, 201):
                        result["findings"].append({
                            "type": "Mass Assignment (Potential)",
                            "severity": "MEDIUM",
                            "url": full_url,
                            "detail": f"PUT with '{field}': true returned HTTP {r.status_code} — manual verification needed"
                        })
            except Exception:
                pass

    result["raw"] = f"Mass assignment test complete — {len(result['findings'])} issues"
    return result


# ─── Rate Limiting ────────────────────────────────────────────────────────────

def rate_limit_test(url: str, output_dir: str) -> dict:
    """Test if API endpoints enforce rate limiting."""
    result = {
        "module": "API Tester — Rate Limiting",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests library not available"
        return result

    print_info("Testing rate limiting on authentication endpoints...")
    base = url.rstrip("/")

    auth_endpoints = [
        ("/api/login", {"username": "test@test.com", "password": "wrongpassword"}),
        ("/api/auth", {"email": "test@test.com", "password": "wrongpassword"}),
        ("/api/token", {"username": "admin", "password": "wrongpassword"}),
        ("/login", {"username": "admin", "password": "wrongpassword"}),
    ]

    for path, body in auth_endpoints:
        full_url = f"{base}{path}"
        statuses = []
        try:
            for _ in range(20):
                r = requests.post(full_url, json=body, headers=HEADERS,
                                  timeout=5, verify=False)
                statuses.append(r.status_code)
                if r.status_code == 429:
                    break
        except Exception:
            continue

        if not any(s == 429 for s in statuses):
            non_404 = [s for s in statuses if s != 404]
            if non_404:
                result["findings"].append({
                    "type": "Missing Rate Limiting",
                    "severity": "HIGH",
                    "url": full_url,
                    "detail": f"20 rapid requests with no 429 rate-limit response. Statuses: {list(set(statuses))}"
                })
                print_success(f"No rate limiting on: {path}")
        else:
            print_info(f"Rate limiting active on {path}")

    result["raw"] = f"Rate limit test complete — {len(result['findings'])} unprotected endpoints"
    return result


# ─── GraphQL ─────────────────────────────────────────────────────────────────

GRAPHQL_INTROSPECTION = {
    "query": "{ __schema { types { name kind fields { name type { name kind } } } } }"
}

GRAPHQL_INJECTION_PAYLOADS = [
    '{ __typename }',
    '{ users { id email password } }',
    '{ user(id: 1) { id email password isAdmin } }',
    '{ admin { id email role } }',
]


def graphql_test(url: str, output_dir: str) -> dict:
    """Test GraphQL endpoints for introspection and injection."""
    result = {
        "module": "API Tester — GraphQL",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests library not available"
        return result

    print_info("Testing GraphQL endpoints...")
    base = url.rstrip("/")

    gql_endpoints = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/playground"]

    for endpoint in gql_endpoints:
        full_url = f"{base}{endpoint}"
        # Introspection test
        try:
            r = requests.post(full_url, json=GRAPHQL_INTROSPECTION,
                              headers=HEADERS, timeout=10, verify=False)
            if r.status_code == 200 and "__schema" in r.text:
                result["findings"].append({
                    "type": "GraphQL Introspection Enabled",
                    "severity": "HIGH",
                    "url": full_url,
                    "detail": "GraphQL schema introspection is publicly accessible — exposes full API structure"
                })
                print_success(f"GraphQL introspection enabled: {full_url}")

                # Save schema
                loot_dir = os.path.join(output_dir, "loot")
                os.makedirs(loot_dir, exist_ok=True)
                with open(os.path.join(loot_dir, "graphql_schema.json"), "w") as f:
                    f.write(r.text)

            # Try injection payloads
            for payload in GRAPHQL_INJECTION_PAYLOADS:
                try:
                    rp = requests.post(full_url, json={"query": payload},
                                       headers=HEADERS, timeout=8, verify=False)
                    if rp.status_code == 200 and '"data"' in rp.text:
                        body = rp.text
                        if any(kw in body for kw in ('"password"', '"email"', '"isAdmin"', '"role"')):
                            result["findings"].append({
                                "type": "GraphQL Data Exposure",
                                "severity": "CRITICAL",
                                "url": full_url,
                                "detail": f"Query '{payload[:60]}' returned sensitive fields"
                            })
                            print_success(f"GraphQL data exposure: {payload[:50]}")
                except Exception:
                    pass
        except Exception:
            pass

    result["raw"] = f"GraphQL test complete — {len(result['findings'])} issues"
    return result


# ─── Sensitive Data in API Responses ─────────────────────────────────────────

def api_sensitive_data_check(url: str, output_dir: str, endpoints: list) -> dict:
    """Scan discovered API responses for sensitive data leakage."""
    result = {
        "module": "API Tester — Sensitive Data",
        "target": url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests library not available"
        return result

    print_info("Scanning API responses for sensitive data...")
    base = url.rstrip("/")

    for ep in endpoints[:20]:
        path = ep.get("path", ep) if isinstance(ep, dict) else ep
        try:
            r = requests.get(f"{base}{path}", headers=HEADERS, timeout=8,
                             verify=False)
            if r.status_code == 200:
                for name, pattern in SENSITIVE_PATTERNS.items():
                    matches = pattern.findall(r.text)
                    if matches:
                        result["findings"].append({
                            "type": f"Sensitive Data — {name}",
                            "severity": "CRITICAL" if name in ("AWS Key", "Private Key", "Password") else "HIGH",
                            "url": f"{base}{path}",
                            "detail": f"{name} found in response: {str(matches[:2])[:100]}"
                        })
                        print_success(f"Sensitive data '{name}' at {path}")
        except Exception:
            pass

    result["raw"] = f"Sensitive data scan complete — {len(result['findings'])} leaks found"
    return result


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def run_api_tester(session, output_dir: str):
    """Full API security test suite."""
    from utils.banner import print_section
    print_section("API SECURITY TESTER — PHANTOM PROTOCOL", "bold yellow")

    url = session.url

    # Endpoint discovery
    ep_result = discover_api_endpoints(url, output_dir)
    session.add_result(ep_result)
    found_endpoints = ep_result.get("endpoints", [])

    # BOLA / IDOR
    r = bola_idor_test(url, output_dir)
    session.add_result(r)

    # Mass assignment
    r = mass_assignment_test(url, output_dir)
    session.add_result(r)

    # Rate limiting
    r = rate_limit_test(url, output_dir)
    session.add_result(r)

    # GraphQL
    r = graphql_test(url, output_dir)
    session.add_result(r)

    # Sensitive data in responses
    r = api_sensitive_data_check(url, output_dir, found_endpoints)
    session.add_result(r)

    # Collect all findings
    all_findings = [f for m in session.modules[-6:] for f in m.get("findings", [])]
    crits = [f for f in all_findings if f.get("severity") in ("CRITICAL", "HIGH")]

    table = Table(title="API Security Test Summary", box=box.SIMPLE, header_style="bold cyan")
    table.add_column("Type", style="cyan", width=35)
    table.add_column("Severity", width=10)
    table.add_column("Detail", style="dim")

    for f in all_findings[:30]:
        sev = f.get("severity", "INFO")
        sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "blue")
        table.add_row(
            f.get("type", "-"),
            f"[{sev_color}]{sev}[/{sev_color}]",
            f.get("detail", "")[:70]
        )

    console.print(table)
    console.print(f"\n  [bold green][+] API test complete — {len(all_findings)} findings ({len(crits)} high/critical)[/bold green]")
