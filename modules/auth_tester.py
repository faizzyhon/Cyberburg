#!/usr/bin/env python3
"""
Authentication Testing Module — Cyberburg
Tests login forms, default credentials, brute-force protection.
Always used on authorized targets only (ethical hacking).
"""

import re
import time
import os
import tempfile
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from utils.helpers import run_command, normalize_target
from utils.banner import print_info, print_success, print_warning, print_error

# ─── Credential Lists ─────────────────────────────────────────────────────────

DEFAULT_CREDENTIALS = [
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         "123456"),
    ("admin",         "admin123"),
    ("admin",         ""),
    ("admin",         "1234"),
    ("admin",         "letmein"),
    ("admin",         "welcome"),
    ("admin",         "changeme"),
    ("root",          "root"),
    ("root",          "password"),
    ("root",          "toor"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("user",          "user"),
    ("test",          "test"),
    ("guest",         "guest"),
    ("demo",          "demo"),
    ("admin",         "admin@123"),
    ("admin",         "P@ssw0rd"),
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/login.php",
    "/administrator", "/administrator/index.php",
    "/wp-admin", "/wp-login.php",
    "/login", "/login.php", "/login.aspx", "/login.html",
    "/signin", "/sign-in", "/auth/login", "/user/login",
    "/account/login", "/member/login", "/members/login",
    "/panel", "/cpanel", "/dashboard", "/backend",
    "/manage", "/management", "/control", "/moderator",
    "/webmaster", "/phpmyadmin", "/pma", "/mysql",
    "/portal", "/secure", "/private",
]

SUCCESS_KEYWORDS = [
    "dashboard", "logout", "log out", "sign out", "signout",
    "welcome", "my account", "profile", "settings", "admin panel",
    "control panel", "manage", "overview", "authenticated",
    "your account", "edit profile",
]

FAILURE_KEYWORDS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "try again", "bad credentials", "unauthorized", "denied",
    "username or password", "login failed", "access denied",
    "invalid credentials", "no account",
]

SESSION_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


# ─── Auth Result Container ────────────────────────────────────────────────────

class AuthResult:
    def __init__(self):
        self.findings = []
        self.login_forms = []
        self.admin_panels = []
        self.successful_logins = []
        self.default_creds_found = []
        self.brute_force_protected = False
        self.rate_limited = False

    def add_finding(self, title, severity, description="", evidence="",
                    remediation="", module="auth_tester"):
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "module": module,
        })

    def to_module_dict(self):
        return {
            "module": "Authentication Tester",
            "findings": self.findings,
            "login_forms": self.login_forms,
            "admin_panels": self.admin_panels,
            "successful_logins": self.successful_logins,
            "default_creds_found": self.default_creds_found,
        }


# ─── Form Detection ───────────────────────────────────────────────────────────

def detect_login_forms(base_url: str, login_url: str = None) -> list:
    """
    Find login forms on the target by checking known admin paths.
    Returns list of form descriptors.
    """
    if not HAS_REQUESTS or not HAS_BS4:
        print_warning("[AUTH] requests/beautifulsoup4 not installed — skipping form detection")
        return []

    session = requests.Session()
    session.headers.update(SESSION_HEADERS)

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    urls_to_check = []
    if login_url:
        urls_to_check.append(login_url)
    urls_to_check.append(base_url)
    for path in ADMIN_PATHS:
        urls_to_check.append(origin + path)

    forms_found = []
    seen_actions = set()

    for url in urls_to_check[:25]:
        try:
            resp = session.get(url, timeout=5, verify=False, allow_redirects=True)
            if resp.status_code not in (200, 401, 403):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                inputs = form.find_all("input")
                has_pwd = any(i.get("type") == "password" for i in inputs)
                if not has_pwd:
                    continue

                username_field = None
                password_field = None
                hidden_fields = {}

                for inp in inputs:
                    name = inp.get("name", "")
                    itype = (inp.get("type") or "text").lower()
                    if itype == "password":
                        password_field = name
                    elif itype == "hidden":
                        hidden_fields[name] = inp.get("value", "")
                    elif itype in ("text", "email") and not username_field:
                        username_field = name
                    elif not username_field and any(
                        k in name.lower() for k in ("user", "email", "login", "name")
                    ):
                        username_field = name

                if not username_field or not password_field:
                    continue

                action = form.get("action") or url
                method = (form.get("method") or "post").lower()
                form_url = urljoin(url, action)

                if form_url in seen_actions:
                    continue
                seen_actions.add(form_url)

                forms_found.append({
                    "page_url": url,
                    "form_url": form_url,
                    "method": method,
                    "username_field": username_field,
                    "password_field": password_field,
                    "hidden_fields": hidden_fields,
                })
        except Exception:
            continue

    return forms_found


# ─── Credential Testing ───────────────────────────────────────────────────────

def _make_session():
    s = requests.Session()
    s.headers.update(SESSION_HEADERS)
    return s


def test_single_credential(form: dict, username: str, password: str,
                            session=None) -> dict:
    """
    Submit one credential pair against a detected form.
    Returns: {'success': bool, 'status_code': int, 'final_url': str}
    """
    if session is None:
        session = _make_session()

    data = dict(form.get("hidden_fields", {}))
    data[form["username_field"]] = username
    data[form["password_field"]] = password

    try:
        # Pre-fetch page to grab any dynamic CSRF tokens
        try:
            pre = session.get(form["page_url"], timeout=5, verify=False)
            if HAS_BS4:
                soup = BeautifulSoup(pre.text, "html.parser")
                for inp in soup.find_all("input", type="hidden"):
                    n, v = inp.get("name", ""), inp.get("value", "")
                    if n and n not in data:
                        data[n] = v
        except Exception:
            pass

        if form["method"] == "post":
            resp = session.post(
                form["form_url"], data=data, timeout=10, verify=False, allow_redirects=True
            )
        else:
            resp = session.get(
                form["form_url"], params=data, timeout=10, verify=False, allow_redirects=True
            )

        text_lower = resp.text.lower()
        success_score = sum(1 for k in SUCCESS_KEYWORDS if k in text_lower)
        failure_score = sum(1 for k in FAILURE_KEYWORDS if k in text_lower)

        final_url_lower = resp.url.lower()
        dashboard_redirect = any(
            d in final_url_lower for d in ["dashboard", "admin", "panel", "home", "welcome", "profile"]
        )

        # Login successful if: more success keywords than failure, or redirected to dashboard
        succeeded = dashboard_redirect or (success_score > 0 and success_score >= failure_score)

        return {
            "success": succeeded,
            "status_code": resp.status_code,
            "final_url": resp.url,
            "success_score": success_score,
            "failure_score": failure_score,
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def check_brute_force_protection(form: dict) -> bool:
    """
    Fire 6 rapid invalid login attempts to check for rate limiting / lockout.
    Returns True if protected.
    """
    if not HAS_REQUESTS:
        return False
    session = _make_session()
    for i in range(6):
        r = test_single_credential(form, f"__bf_test_{i}__", f"__pass_{i}__", session)
        if r.get("status_code") in (429, 503):
            return True
        time.sleep(0.15)
    return False


def check_admin_panels(base_url: str) -> list:
    """
    Probe common admin panel URLs and return accessible ones.
    """
    if not HAS_REQUESTS:
        return []

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    session = _make_session()
    found = []

    for path in ADMIN_PATHS:
        url = origin + path
        try:
            resp = session.get(url, timeout=4, verify=False, allow_redirects=True)
            if resp.status_code in (200, 401, 403):
                found.append({
                    "url": url,
                    "status": resp.status_code,
                    "title": _extract_title(resp.text),
                })
        except Exception:
            continue

    return found


def _extract_title(html: str) -> str:
    if HAS_BS4:
        try:
            soup = BeautifulSoup(html, "html.parser")
            t = soup.find("title")
            return t.get_text(strip=True)[:80] if t else ""
        except Exception:
            pass
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:80] if m else ""


# ─── Hydra Integration ────────────────────────────────────────────────────────

def _hydra_http_post(form: dict, result: AuthResult):
    """
    Run a limited Hydra credential test (max 25 combos) if Hydra is installed.
    Only used when brute-force protection is NOT active.
    """
    from utils.tool_checker import check_tool
    if not check_tool("hydra"):
        return

    u_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    p_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)

    users = ["admin", "administrator", "root", "user", "test", "guest"]
    passwords = ["admin", "password", "123456", "admin123", "welcome", "changeme", "P@ssword1"]

    u_file.write("\n".join(users))
    p_file.write("\n".join(passwords))
    u_file.close()
    p_file.close()

    try:
        parsed = urlparse(form["form_url"])
        host = parsed.netloc
        path = parsed.path or "/"
        proto = "https-post-form" if parsed.scheme == "https" else "http-post-form"

        post_str = f"{form['username_field']}=^USER^&{form['password_field']}=^PASS^"
        for k, v in form.get("hidden_fields", {}).items():
            post_str += f"&{k}={v}"
        failure_str = "invalid|incorrect|wrong|failed|denied|error"
        form_str = f"{path}:{post_str}:F={failure_str}"

        cmd = [
            "hydra",
            "-L", u_file.name,
            "-P", p_file.name,
            "-t", "4", "-w", "3", "-f",
            host, proto, form_str,
        ]
        _code, out, _err = run_command(cmd, timeout=90)

        for line in out.splitlines():
            if "login:" in line.lower() and "password:" in line.lower():
                result.add_finding(
                    "Hydra: Valid Credentials Discovered",
                    "CRITICAL",
                    "Hydra found valid login credentials against the application.",
                    line.strip(),
                    "Change credentials immediately. Implement account lockout and rate limiting.",
                )
                result.default_creds_found.append({"source": "hydra", "line": line.strip()})
    except Exception:
        pass
    finally:
        os.unlink(u_file.name)
        os.unlink(p_file.name)


# ─── Main Orchestrator ────────────────────────────────────────────────────────

def run_auth_tests(
    target: str,
    login_url: str = None,
    username: str = None,
    password: str = None,
) -> AuthResult:
    """
    Primary entry point for authentication testing.

    ⚖️  ETHICAL NOTICE: Only use on targets you own or have written
    authorization to test. Unauthorized access testing is illegal.

    Args:
        target:    Target URL or domain
        login_url: Specific login page URL (optional)
        username:  Username/email to test (provided by tester)
        password:  Password to test (provided by tester)
    """
    result = AuthResult()

    print_info("[AUTH] ⚖️  Ethical Notice: Only testing authorized targets")
    print_info(f"[AUTH] Starting authentication analysis on {target}")

    if not HAS_REQUESTS:
        result.add_finding(
            "Auth Module Unavailable",
            "INFO",
            "Install 'requests' and 'beautifulsoup4' to enable auth testing.",
            "",
            "pip install requests beautifulsoup4",
        )
        return result

    # Normalize target
    try:
        base_url, _, _ = normalize_target(target)
    except Exception:
        base_url = target if target.startswith("http") else f"http://{target}"

    # 1. Admin panel discovery
    print_info("[AUTH] Probing admin panels...")
    panels = check_admin_panels(base_url)
    result.admin_panels = panels

    if panels:
        panel_list = "\n".join(f"  [{p['status']}] {p['url']} — {p['title']}" for p in panels[:10])
        sev = "HIGH" if any(p["status"] == 200 for p in panels) else "MEDIUM"
        result.add_finding(
            f"Admin Panels Exposed ({len(panels)} found)",
            sev,
            "One or more administrative panels are publicly accessible.",
            panel_list,
            "Restrict admin URLs to trusted IPs via firewall or server config. "
            "Remove panels not in use. Implement MFA on all admin accounts.",
        )

    # 2. Login form detection
    print_info("[AUTH] Detecting login forms...")
    forms = detect_login_forms(base_url, login_url)
    result.login_forms = forms

    if not forms:
        result.add_finding(
            "No Login Forms Detected",
            "INFO",
            "No standard HTML login forms were found. The app may use API-based auth or JavaScript rendering.",
            "",
            "If login forms exist, try specifying --login-url explicitly.",
        )
        return result

    result.add_finding(
        f"Login Form Detected ({len(forms)} form(s))",
        "INFO",
        f"Found {len(forms)} login form(s). Testing for security issues.",
        "\n".join(f["page_url"] for f in forms[:5]),
        "Ensure CSRF protection, rate limiting, and account lockout are in place.",
    )

    primary = forms[0]

    # 3. Brute-force protection check
    print_info("[AUTH] Checking brute-force protection...")
    bf_protected = check_brute_force_protection(primary)
    result.brute_force_protected = bf_protected

    if not bf_protected:
        result.add_finding(
            "No Brute-Force / Rate-Limit Protection",
            "HIGH",
            "The login form allows rapid credential stuffing without triggering rate-limiting or lockout.",
            f"6 rapid invalid logins to {primary['page_url']} — no 429 / block response.",
            "Implement rate limiting (5 attempts/minute). Add CAPTCHA after 3 failures. "
            "Lock accounts after 10 failures with exponential backoff.",
        )
    else:
        result.add_finding(
            "Brute-Force Protection Active",
            "INFO",
            "Rate limiting or account lockout detected on the login form.",
            f"429 or lockout triggered on {primary['page_url']}",
            "",
        )

    # 4. Test user-supplied credentials first (tester-provided)
    if username and password:
        print_info(f"[AUTH] Testing supplied credentials: {username} / {'*' * len(password)}")
        r = test_single_credential(primary, username, password)
        if r.get("success"):
            entry = {
                "url": primary["page_url"],
                "username": username,
                "final_url": r.get("final_url", ""),
            }
            result.successful_logins.append(entry)
            result.add_finding(
                f"Authenticated Access Confirmed: {username}",
                "CRITICAL",
                f"Successfully logged in to {primary['page_url']} with the provided credentials. "
                "Verify the intended scope of this access.",
                f"User: {username} | Login: {primary['form_url']} | Redirected: {r.get('final_url','')}",
                "Ensure this account's privileges follow the principle of least privilege. "
                "Audit all actions performed with this credential. Enable MFA.",
            )
        else:
            result.add_finding(
                f"Credential Test: {username} — Access Denied",
                "INFO",
                "Provided credentials did not authenticate.",
                f"HTTP {r.get('status_code','N/A')} | Scores: success={r.get('success_score',0)}, failure={r.get('failure_score',0)}",
                "",
            )

    # 5. Default credential testing
    print_info("[AUTH] Testing default/common credentials...")
    creds_to_test = DEFAULT_CREDENTIALS[:10]  # Top 10 only — ethical limit
    session = _make_session()

    for def_user, def_pass in creds_to_test:
        r = test_single_credential(primary, def_user, def_pass, session)
        if r.get("success"):
            result.default_creds_found.append({
                "username": def_user,
                "password": def_pass,
                "url": primary["page_url"],
                "final_url": r.get("final_url", ""),
            })
            result.add_finding(
                f"Default Credentials Valid: {def_user} / {def_pass}",
                "CRITICAL",
                f"The application accepts default credentials '{def_user}:{def_pass}'. "
                "This allows any internet user to gain authenticated access.",
                f"Login URL: {primary['form_url']} | Final URL: {r.get('final_url','')}",
                "Change default credentials immediately. Force password reset on first login. "
                "Remove unused default accounts. Implement MFA for all admin accounts.",
            )
        time.sleep(0.3)  # Respect rate limits

    # 6. Hydra (only if not rate-limited and no creds found yet)
    if not bf_protected and not result.default_creds_found and not result.successful_logins:
        print_info("[AUTH] Running Hydra (limited) credential test...")
        _hydra_http_post(primary, result)

    # 7. Summary
    total_success = len(result.successful_logins) + len(result.default_creds_found)
    if total_success == 0:
        result.add_finding(
            "No Valid Credentials Found",
            "INFO",
            "Default credential testing did not yield valid access with the tested pairs.",
            "",
            "",
        )

    print_info(f"[AUTH] Complete — {len(result.findings)} findings, {total_success} valid logins")
    return result
