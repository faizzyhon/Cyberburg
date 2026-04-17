#!/usr/bin/env python3
"""
CVE Intelligence Module — Cyberburg v4 DARK MATTER
Queries NVD (National Vulnerability Database) API to map discovered
technology versions to known CVEs with CVSS scores and exploit availability.
"""

import os
import re
import json
import time

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.helpers import get_timestamp, sanitize_filename
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ─── Technology Version Extraction ────────────────────────────────────────────

TECH_PATTERNS = {
    "Apache":        r'Apache[/ ]([\d.]+)',
    "Nginx":         r'nginx[/ ]([\d.]+)',
    "PHP":           r'PHP[/ ]([\d.]+)',
    "WordPress":     r'WordPress ([\d.]+)',
    "Drupal":        r'Drupal[/ ]([\d.]+)',
    "Joomla":        r'Joomla[!/ ]?([\d.]+)',
    "OpenSSL":       r'OpenSSL[/ ]([\d.a-z]+)',
    "IIS":           r'Microsoft-IIS[/ ]([\d.]+)',
    "Tomcat":        r'Apache Tomcat[/ ]([\d.]+)',
    "jQuery":        r'jQuery[/ v]*([\d.]+)',
    "Bootstrap":     r'Bootstrap[/ v]*([\d.]+)',
    "Python":        r'Python[/ ]([\d.]+)',
    "Django":        r'Django[/ ]([\d.]+)',
    "Flask":         r'Werkzeug[/ ]([\d.]+)',
    "Express":       r'Express[/ ]([\d.]+)',
    "Spring":        r'Spring[/ Boot]*([\d.]+)',
    "Struts":        r'Struts[/ ]([\d.]+)',
    "Java":          r'Java[/ ]([\d._]+)',
    "Ruby":          r'Ruby[/ ]([\d.]+)',
    "Rails":         r'Rails[/ ]([\d.]+)',
    "Magento":       r'Magento[/ ]([\d.]+)',
    "WooCommerce":   r'WooCommerce[/ ]([\d.]+)',
}

# Known critical CVEs for quick offline check (augmented by live NVD query)
KNOWN_CRITICAL_CVES = {
    "Apache": [
        {"cve": "CVE-2021-41773", "description": "Path traversal and RCE in Apache 2.4.49", "cvss": 9.8, "version_range": "2.4.49"},
        {"cve": "CVE-2021-42013", "description": "Path traversal bypass in Apache 2.4.49-2.4.50", "cvss": 9.8, "version_range": "2.4.50"},
        {"cve": "CVE-2017-7679", "description": "Buffer overflow in Apache mod_mime", "cvss": 9.8, "version_range": "2.2.x"},
    ],
    "PHP": [
        {"cve": "CVE-2019-11043", "description": "RCE in PHP-FPM nginx misconfiguration", "cvss": 9.8, "version_range": "7.x"},
        {"cve": "CVE-2012-1823", "description": "PHP-CGI remote code execution", "cvss": 9.8, "version_range": "5.3.x"},
        {"cve": "CVE-2021-21705", "description": "PHP SSRF bypass via filter", "cvss": 5.3, "version_range": "7.4.x"},
    ],
    "WordPress": [
        {"cve": "CVE-2022-21661", "description": "SQL injection via WP_Query", "cvss": 9.8, "version_range": "<5.8.3"},
        {"cve": "CVE-2022-21662", "description": "Stored XSS via post slugs", "cvss": 8.0, "version_range": "<5.8.3"},
        {"cve": "CVE-2023-2745", "description": "Directory traversal in Core", "cvss": 6.5, "version_range": "<6.2.1"},
    ],
    "Joomla": [
        {"cve": "CVE-2023-23752", "description": "Unauthorized access via REST API", "cvss": 7.5, "version_range": "4.0.0-4.2.7"},
        {"cve": "CVE-2015-8562", "description": "RCE via PHP object injection", "cvss": 9.8, "version_range": "1.5-3.4.5"},
    ],
    "Drupal": [
        {"cve": "CVE-2018-7600", "description": "Drupalgeddon 2 — RCE", "cvss": 9.8, "version_range": "6-8.x"},
        {"cve": "CVE-2018-7602", "description": "Drupalgeddon 3 — RCE", "cvss": 9.8, "version_range": "7-8.x"},
        {"cve": "CVE-2019-6340", "description": "RCE via REST API", "cvss": 9.8, "version_range": "8.6.x"},
    ],
    "jQuery": [
        {"cve": "CVE-2019-11358", "description": "Prototype pollution via extend()", "cvss": 6.1, "version_range": "<3.4.0"},
        {"cve": "CVE-2020-11022", "description": "XSS via regex in HTML parsing", "cvss": 6.1, "version_range": "<3.5.0"},
        {"cve": "CVE-2015-9251", "description": "XSS via cross-domain AJAX", "cvss": 6.1, "version_range": "<3.0.0"},
    ],
    "OpenSSL": [
        {"cve": "CVE-2014-0160", "description": "Heartbleed — private key exposure", "cvss": 7.5, "version_range": "1.0.1-1.0.1f"},
        {"cve": "CVE-2022-0778", "description": "Infinite loop in BN_mod_sqrt()", "cvss": 7.5, "version_range": "<3.0.2"},
        {"cve": "CVE-2022-3786", "description": "Stack overflow in X.509 parsing", "cvss": 7.5, "version_range": "3.0.x"},
    ],
    "Nginx": [
        {"cve": "CVE-2021-23017", "description": "1-byte memory overwrite in resolver", "cvss": 9.4, "version_range": "<1.20.1"},
        {"cve": "CVE-2019-9511", "description": "HTTP/2 DoS via data dribble", "cvss": 7.5, "version_range": "<1.16.1"},
    ],
    "Struts": [
        {"cve": "CVE-2017-5638", "description": "Equifax breach RCE — OGNL injection", "cvss": 10.0, "version_range": "2.3.x-2.5.10"},
        {"cve": "CVE-2018-11776", "description": "RCE via namespace value", "cvss": 9.8, "version_range": "2.3-2.5.16"},
    ],
    "Spring": [
        {"cve": "CVE-2022-22965", "description": "Spring4Shell — RCE via data binding", "cvss": 9.8, "version_range": "5.3.x"},
        {"cve": "CVE-2022-22963", "description": "RCE in Spring Cloud Function", "cvss": 9.8, "version_range": "3.1.x-3.2.x"},
    ],
    "Tomcat": [
        {"cve": "CVE-2020-1938", "description": "Ghostcat — AJP connector file read/RCE", "cvss": 9.8, "version_range": "<9.0.31"},
        {"cve": "CVE-2019-0232", "description": "RCE via CGI on Windows", "cvss": 8.1, "version_range": "<9.0.18"},
    ],
}


def extract_technologies_from_session(session_modules: list) -> dict:
    """Parse scan session modules to extract identified technologies and versions."""
    techs = {}
    combined_text = ""

    for module in session_modules:
        combined_text += module.get("raw", "")
        for finding in module.get("findings", []):
            combined_text += " " + finding.get("value", "") + " " + finding.get("type", "")

    for tech, pattern in TECH_PATTERNS.items():
        m = re.search(pattern, combined_text, re.IGNORECASE)
        if m:
            techs[tech] = m.group(1).strip()

    return techs


def query_nvd_api(keyword: str, version: str = None) -> list:
    """Query NVD API for CVEs related to a technology."""
    if not HAS_REQUESTS:
        return []

    results = []
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 10,
        }
        if version:
            params["keywordSearch"] = f"{keyword} {version}"

        resp = requests.get(NVD_API_BASE, params=params, timeout=10)
        if resp.status_code != 200:
            return []

        data = resp.json()
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            desc = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            cvss_score = 0.0
            metrics = cve_data.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_score = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                    break

            results.append({
                "cve": cve_id,
                "description": desc[:150],
                "cvss": cvss_score,
                "severity": _cvss_to_severity(cvss_score),
            })

        time.sleep(0.6)  # NVD rate limit: 5 req/30s without API key

    except Exception:
        pass

    return sorted(results, key=lambda x: x["cvss"], reverse=True)[:5]


def run_cve_lookup(session_obj, output_dir: str) -> dict:
    """Extract detected technologies and map to CVEs."""
    result = {
        "module": "CVE Intelligence — Technology Mapping",
        "target": session_obj.url,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": [],
        "cve_report": {}
    }

    print_info("Running CVE intelligence lookup on detected technologies...")
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)

    # Extract technologies from all scan results
    techs = extract_technologies_from_session(session_obj.modules)

    if not techs:
        result["findings"].append({
            "type": "CVE Lookup",
            "value": "No specific technology versions detected in scan results",
            "severity": "INFO"
        })
        print_info("CVE Lookup: No technology versions identified")
        return result

    print_info(f"Detected {len(techs)} technologies: {', '.join(f'{k} {v}' for k,v in techs.items())}")
    result["raw"] = f"Technologies detected: {techs}\n\n"

    cve_report = {}

    for tech, version in techs.items():
        result["findings"].append({
            "type": "Technology Detected",
            "value": f"{tech} {version}",
            "severity": "INFO"
        })

        cves_found = []

        # Offline known critical CVE check first
        if tech in KNOWN_CRITICAL_CVES:
            for known in KNOWN_CRITICAL_CVES[tech]:
                cves_found.append(known)
                sev = _cvss_to_severity(known["cvss"])
                result["findings"].append({
                    "type": f"CVE — {tech}",
                    "value": f"{known['cve']} (CVSS {known['cvss']}) — {known['description']}",
                    "severity": sev
                })
                if known["cvss"] >= 9.0:
                    print_error(f"CRITICAL CVE: {known['cve']} ({tech} {version}) — CVSS {known['cvss']}")
                elif known["cvss"] >= 7.0:
                    print_warning(f"HIGH CVE: {known['cve']} ({tech} {version}) — CVSS {known['cvss']}")

        # Live NVD query
        live_cves = query_nvd_api(tech, version)
        for cve in live_cves:
            if not any(c["cve"] == cve["cve"] for c in cves_found):
                cves_found.append(cve)
                result["findings"].append({
                    "type": f"CVE (NVD) — {tech}",
                    "value": f"{cve['cve']} (CVSS {cve['cvss']}) — {cve['description'][:80]}",
                    "severity": cve["severity"]
                })

        cve_report[tech] = {"version": version, "cves": cves_found}

    result["cve_report"] = cve_report

    # Save CVE report
    loot_path = os.path.join(loot_dir, "cve_report.json")
    with open(loot_path, "w") as f:
        json.dump(cve_report, f, indent=2)

    # Display table
    total_cves = sum(len(v["cves"]) for v in cve_report.values())
    critical_cves = sum(
        len([c for c in v["cves"] if c.get("cvss", 0) >= 9.0])
        for v in cve_report.values()
    )

    table = Table(title="CVE Intelligence Report", box=box.DOUBLE_EDGE, header_style="bold yellow")
    table.add_column("Technology", style="cyan", min_width=15)
    table.add_column("Version", width=10)
    table.add_column("CVEs Found", width=10)
    table.add_column("Highest CVSS", width=13)

    for tech, data in cve_report.items():
        cvss_max = max((c.get("cvss", 0) for c in data["cves"]), default=0)
        cvss_color = "bold red" if cvss_max >= 9.0 else "red" if cvss_max >= 7.0 else "yellow" if cvss_max >= 4.0 else "green"
        table.add_row(
            tech, data["version"],
            str(len(data["cves"])),
            f"[{cvss_color}]{cvss_max:.1f}[/{cvss_color}]"
        )

    console.print(table)
    console.print(f"\n  Total CVEs: {total_cves} | Critical (CVSS≥9.0): [bold red]{critical_cves}[/bold red]")
    console.print(f"  [dim]Full report: {loot_path}[/dim]")

    return result


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "INFO"
