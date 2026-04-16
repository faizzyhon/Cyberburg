"""
Nuclei Scanner Module — Cyberburg
Handles: Nuclei template-based vulnerability scanning
"""

import re
from utils.helpers import run_command, get_timestamp
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console

console = Console()

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def nuclei_scan(target: str, severity: str = "critical,high,medium") -> dict:
    """Run Nuclei template scan on target."""
    result = {
        "module": "Nuclei Template Scan",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("nuclei"):
        print_warning("nuclei not installed — skipping template-based scan")
        result["findings"].append({
            "type": "Nuclei",
            "value": "nuclei not installed. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "severity": "INFO"
        })
        return result

    print_info(f"Running Nuclei scan on {target} (severity: {severity})...")
    print_info("Updating Nuclei templates first...")

    # Update templates
    run_command(["nuclei", "-update-templates", "-silent"], timeout=60)

    code, stdout, stderr = run_command(
        [
            "nuclei",
            "-u", target,
            "-severity", severity,
            "-c", "50",          # Concurrency
            "-timeout", "10",
            "-retries", "2",
            "-silent",
            "-nc",               # No color
            "-rate-limit", "50",
        ],
        timeout=600
    )

    result["raw"] = stdout + stderr

    # Parse Nuclei JSONL-style output
    for line in stdout.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Nuclei output format: [timestamp] [template-id] [type] [severity] [url] [extras]
        match = re.match(
            r'\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] (.+)',
            line
        )
        if match:
            template_id = match.group(2)
            finding_type = match.group(3)
            severity = match.group(4).upper()
            url_info = match.group(5)

            result["findings"].append({
                "type": f"Nuclei: {template_id}",
                "value": f"[{finding_type}] {url_info}",
                "severity": severity
            })

            if severity in ["CRITICAL", "HIGH"]:
                print_error(f"[{severity}] {template_id}: {url_info[:80]}")
        else:
            # Try simpler parsing
            for sev in SEVERITY_ORDER:
                if f"[{sev}]" in line.lower():
                    clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
                    result["findings"].append({
                        "type": "Nuclei Finding",
                        "value": clean,
                        "severity": sev.upper()
                    })
                    break

    if not result["findings"]:
        result["findings"].append({
            "type": "Nuclei Scan",
            "value": "No vulnerabilities found by Nuclei templates",
            "severity": "INFO"
        })

    print_success(f"Nuclei complete — {len(result['findings'])} findings")
    return result


def nuclei_technology_detect(target: str) -> dict:
    """Use Nuclei to detect technologies."""
    result = {
        "module": "Technology Detection (Nuclei)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("nuclei"):
        return result

    print_info(f"Detecting technologies on {target} with Nuclei...")

    code, stdout, stderr = run_command(
        [
            "nuclei", "-u", target,
            "-tags", "tech",
            "-silent", "-nc",
            "-c", "30",
            "-timeout", "10",
        ],
        timeout=180
    )

    result["raw"] = stdout + stderr

    for line in stdout.split('\n'):
        if line.strip():
            clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
            result["findings"].append({
                "type": "Technology Detected",
                "value": clean,
                "severity": "INFO"
            })

    return result


def nuclei_exposed_panels(target: str) -> dict:
    """Scan for exposed admin panels and login pages."""
    result = {
        "module": "Exposed Panels Scan (Nuclei)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("nuclei"):
        return result

    print_info(f"Scanning for exposed admin panels on {target}...")

    code, stdout, stderr = run_command(
        [
            "nuclei", "-u", target,
            "-tags", "panel,login,admin",
            "-severity", "critical,high,medium,low,info",
            "-silent", "-nc",
            "-c", "30",
        ],
        timeout=180
    )

    result["raw"] = stdout + stderr

    for line in stdout.split('\n'):
        if line.strip():
            clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
            result["findings"].append({
                "type": "Admin Panel Found",
                "value": clean,
                "severity": "HIGH"
            })

    return result


def nuclei_cves(target: str) -> dict:
    """Scan for known CVEs using Nuclei templates."""
    result = {
        "module": "CVE Scan (Nuclei)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("nuclei"):
        return result

    print_info(f"Scanning for known CVEs on {target}...")

    code, stdout, stderr = run_command(
        [
            "nuclei", "-u", target,
            "-tags", "cve",
            "-severity", "critical,high,medium",
            "-silent", "-nc",
            "-c", "30",
            "-timeout", "10",
        ],
        timeout=300
    )

    result["raw"] = stdout + stderr

    for line in stdout.split('\n'):
        if line.strip():
            cve_match = re.search(r'(CVE-\d{4}-\d+)', line)
            severity_match = re.search(r'\[(critical|high|medium|low|info)\]', line.lower())

            clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
            severity = severity_match.group(1).upper() if severity_match else "MEDIUM"
            cve_id = cve_match.group(1) if cve_match else "CVE"

            result["findings"].append({
                "type": f"CVE Found: {cve_id}",
                "value": clean,
                "severity": severity
            })

            if severity in ["CRITICAL", "HIGH"]:
                print_error(f"[{severity}] {clean[:100]}")

    if not result["findings"]:
        result["findings"].append({
            "type": "CVE Scan",
            "value": "No known CVEs detected by Nuclei",
            "severity": "INFO"
        })

    print_success(f"CVE scan complete — {len(result['findings'])} CVEs found")
    return result
