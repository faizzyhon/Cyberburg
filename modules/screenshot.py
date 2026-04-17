#!/usr/bin/env python3
"""
Screenshot Module — Cyberburg v4 DARK MATTER
Captures screenshots of discovered pages: admin panels, login forms,
exposed configs, found vulnerabilities.

Methods (in order of preference):
1. Chrome/Chromium headless
2. wkhtmltoimage
3. HTML snapshot fallback (always works)
"""

import os
import re
import time
from typing import Optional

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.helpers import run_command, get_timestamp, sanitize_filename, get_filename_timestamp
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console

console = Console()

SCREENSHOT_TARGETS = [
    "/", "/admin", "/admin/login", "/login", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/dashboard", "/cpanel", "/panel", "/phpinfo.php",
    "/.git/config", "/.env", "/api/v1/users", "/swagger-ui", "/actuator",
]


def _chromium_screenshot(url: str, output_path: str) -> bool:
    """Take screenshot using headless Chrome/Chromium."""
    chromium_bins = ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
                     "chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"]

    for chrome_bin in chromium_bins:
        if not (check_tool(chrome_bin.split("/")[-1]) or os.path.exists(chrome_bin)):
            continue
        code, stdout, stderr = run_command([
            chrome_bin,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--window-size=1280,800",
            f"--screenshot={output_path}",
            "--screenshot-format=png",
            "--hide-scrollbars",
            "--timeout=10000",
            url,
        ], timeout=20)
        if code == 0 and os.path.exists(output_path):
            return True

    return False


def _wkhtmltoimage_screenshot(url: str, output_path: str) -> bool:
    """Take screenshot using wkhtmltoimage."""
    if not check_tool("wkhtmltoimage"):
        return False
    code, stdout, stderr = run_command([
        "wkhtmltoimage",
        "--quiet", "--width", "1280",
        "--javascript-delay", "1000",
        url, output_path,
    ], timeout=20)
    return code == 0 and os.path.exists(output_path)


def _html_snapshot(url: str, output_path: str) -> bool:
    """Save HTML snapshot as fallback when headless browsers aren't available."""
    if not HAS_REQUESTS:
        return False
    try:
        resp = requests.get(url, timeout=8, verify=False,
                            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            html_path = output_path.replace(".png", ".html")
            with open(html_path, "w", encoding="utf-8", errors="replace") as f:
                f.write(f"<!-- Snapshot: {url} | Status: {resp.status_code} -->\n")
                f.write(resp.text)
            return True
    except Exception:
        pass
    return False


def screenshot_url(url: str, output_dir: str, label: str = "") -> Optional[str]:
    """Take a screenshot of a URL. Returns saved path or None."""
    ss_dir = os.path.join(output_dir, "screenshots")
    os.makedirs(ss_dir, exist_ok=True)

    safe_label = sanitize_filename(label or url.split("/")[-1] or "index")
    ts = get_filename_timestamp()
    png_path = os.path.join(ss_dir, f"{safe_label}_{ts}.png")

    if _chromium_screenshot(url, png_path):
        print_success(f"Screenshot saved: {png_path}")
        return png_path

    if _wkhtmltoimage_screenshot(url, png_path):
        print_success(f"Screenshot saved: {png_path}")
        return png_path

    # Fallback: HTML snapshot
    html_path = png_path.replace(".png", ".html")
    if _html_snapshot(url, html_path):
        print_info(f"HTML snapshot saved: {html_path} (no headless browser found)")
        return html_path

    return None


def run_screenshot_capture(session_obj, output_dir: str) -> dict:
    """Screenshot all interesting pages discovered during the scan."""
    result = {
        "module": "Screenshot Capture",
        "target": session_obj.url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": [],
        "screenshots": []
    }

    print_info("Starting screenshot capture of discovered pages...")
    ss_dir = os.path.join(output_dir, "screenshots")
    os.makedirs(ss_dir, exist_ok=True)

    base = session_obj.url.rstrip("/")
    urls_to_screenshot = []

    # Always screenshot the main target
    urls_to_screenshot.append((session_obj.url, "main_page"))

    # Extract interesting URLs from findings
    for module in session_obj.modules:
        for finding in module.get("findings", []):
            ftype = finding.get("type", "").lower()
            fval = finding.get("value", "")

            # Admin panels
            if "admin panel" in ftype or "login" in ftype:
                url_match = re.search(r'https?://\S+', fval)
                if url_match:
                    urls_to_screenshot.append((url_match.group(), "admin_panel"))

            # Config exposures
            if "exposed" in ftype or "config" in ftype:
                url_match = re.search(r'https?://\S+', fval)
                if url_match:
                    urls_to_screenshot.append((url_match.group()[:200], "exposed_file"))

    # Add standard interesting paths
    if HAS_REQUESTS:
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        for path in SCREENSHOT_TARGETS:
            test_url = base + path
            try:
                r = session.get(test_url, timeout=4, verify=False)
                if r.status_code == 200 and len(r.content) > 100:
                    label = sanitize_filename(path.lstrip("/") or "root")
                    urls_to_screenshot.append((test_url, label))
            except Exception:
                continue

    # Deduplicate
    seen = set()
    unique_urls = []
    for u, label in urls_to_screenshot:
        if u not in seen:
            seen.add(u)
            unique_urls.append((u, label))

    console.print(f"  [dim]Capturing {len(unique_urls)} pages...[/dim]")

    captured = 0
    for url, label in unique_urls[:20]:  # Cap at 20 screenshots
        path = screenshot_url(url, output_dir, label)
        if path:
            result["screenshots"].append(path)
            result["findings"].append({
                "type": "Screenshot Captured",
                "value": f"{url} → {os.path.basename(path)}",
                "severity": "INFO"
            })
            captured += 1
        time.sleep(0.5)

    result["raw"] = f"Attempted: {len(unique_urls)} | Captured: {captured}"

    if captured == 0:
        result["findings"].append({
            "type": "Screenshots",
            "value": "No screenshots captured (install chromium or wkhtmltoimage for PNG; HTML snapshots saved as fallback)",
            "severity": "INFO"
        })
    else:
        console.print(f"  [bold green]{captured} screenshots saved to: {ss_dir}[/bold green]")

    return result
