"""
SSL/TLS Analyzer Module — Cyberburg
Handles: SSLScan, testssl, OpenSSL certificate analysis
"""

import re
import socket
import ssl
from datetime import datetime, timezone
from utils.helpers import run_command, get_timestamp
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console

console = Console()

WEAK_CIPHERS = [
    "NULL", "EXPORT", "DES", "RC4", "MD5", "3DES", "ANON",
    "ADH", "AECDH", "PSK", "SRP", "CAMELLIA", "SEED",
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
STRONG_PROTOCOLS = ["TLSv1.2", "TLSv1.3"]


def sslscan_analysis(target: str) -> dict:
    """Run SSLScan on target."""
    result = {
        "module": "SSL/TLS Scan (SSLScan)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": [],
        "grade": "Unknown"
    }

    # Extract hostname
    host = re.sub(r'^https?://', '', target).split('/')[0]

    if not check_tool("sslscan"):
        print_warning("sslscan not installed — using openssl fallback")
        return openssl_check(target)

    print_info(f"Running SSLScan on {host}...")

    code, stdout, stderr = run_command(
        ["sslscan", "--no-colour", host],
        timeout=120
    )

    result["raw"] = stdout + stderr
    result = _parse_sslscan_output(stdout, result)

    print_success("SSLScan complete")
    return result


def testssl_analysis(target: str) -> dict:
    """Run testssl.sh on target."""
    result = {
        "module": "SSL/TLS Analysis (testssl.sh)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    host = re.sub(r'^https?://', '', target).split('/')[0]

    if not check_tool("testssl.sh") and not check_tool("testssl"):
        print_warning("testssl.sh not found — skipping")
        return openssl_check(target)

    testssl_cmd = "testssl.sh" if check_tool("testssl.sh") else "testssl"

    print_info(f"Running testssl.sh on {host} (comprehensive scan)...")

    code, stdout, stderr = run_command(
        [testssl_cmd, "--quiet", "--color", "0", host],
        timeout=300
    )

    result["raw"] = stdout + stderr

    # Parse severity markers from testssl output
    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "OK": "INFO",
        "INFO": "INFO",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
    }

    for line in stdout.split('\n'):
        for marker, severity in severity_map.items():
            if marker in line and severity in ["CRITICAL", "HIGH", "MEDIUM"]:
                clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
                if clean:
                    result["findings"].append({
                        "type": "SSL/TLS Vulnerability",
                        "value": clean,
                        "severity": severity
                    })
                break

    print_success("testssl.sh complete")
    return result


def openssl_check(target: str) -> dict:
    """Check SSL certificate details using Python ssl + openssl command."""
    result = {
        "module": "SSL Certificate Analysis",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "certificate": {},
        "findings": []
    }

    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    port = 443

    print_info(f"Analyzing SSL certificate for {host}:{port}...")

    # Method 1: Python SSL
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                result["certificate"] = cert

                # Check certificate expiry
                if cert:
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            expiry = expiry.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_left = (expiry - now).days

                            if days_left < 0:
                                result["findings"].append({
                                    "type": "SSL Certificate EXPIRED",
                                    "value": f"Certificate expired {abs(days_left)} days ago!",
                                    "severity": "CRITICAL"
                                })
                                print_error("CRITICAL: SSL certificate is EXPIRED!")
                            elif days_left < 14:
                                result["findings"].append({
                                    "type": "SSL Certificate Expiring Soon",
                                    "value": f"Certificate expires in {days_left} days!",
                                    "severity": "HIGH"
                                })
                                print_warning(f"Certificate expires in {days_left} days!")
                            elif days_left < 30:
                                result["findings"].append({
                                    "type": "SSL Certificate Expiring",
                                    "value": f"Certificate expires in {days_left} days",
                                    "severity": "MEDIUM"
                                })
                            else:
                                result["findings"].append({
                                    "type": "SSL Certificate Valid",
                                    "value": f"Certificate valid for {days_left} more days (expires {not_after})",
                                    "severity": "INFO"
                                })
                        except Exception:
                            pass

                    # Check CN / SANs
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    result["findings"].append({
                        "type": "Certificate CN",
                        "value": f"Common Name: {cn}",
                        "severity": "INFO"
                    })

                    # Check if self-signed
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    if subject == issuer:
                        result["findings"].append({
                            "type": "Self-Signed Certificate",
                            "value": "Certificate is self-signed — not trusted by browsers",
                            "severity": "HIGH"
                        })

                # Cipher suite
                if cipher:
                    cipher_name, proto, bits = cipher
                    result["findings"].append({
                        "type": "Active Cipher Suite",
                        "value": f"{cipher_name} ({bits}-bit) — Protocol: {proto}",
                        "severity": "INFO"
                    })

                    for weak in WEAK_CIPHERS:
                        if weak in cipher_name.upper():
                            result["findings"].append({
                                "type": "Weak Cipher Suite",
                                "value": f"Weak cipher in use: {cipher_name}",
                                "severity": "HIGH"
                            })

                # TLS version
                if version:
                    result["findings"].append({
                        "type": "TLS Protocol Version",
                        "value": f"Negotiated: {version}",
                        "severity": "INFO"
                    })

                    if version in WEAK_PROTOCOLS:
                        result["findings"].append({
                            "type": "Weak TLS Protocol",
                            "value": f"{version} is deprecated and insecure",
                            "severity": "CRITICAL"
                        })

    except ssl.SSLError as e:
        result["findings"].append({
            "type": "SSL Error",
            "value": str(e),
            "severity": "HIGH"
        })
    except ConnectionRefusedError:
        result["findings"].append({
            "type": "HTTPS Not Available",
            "value": f"Port 443 not open — site may not support HTTPS",
            "severity": "CRITICAL"
        })
    except Exception as e:
        result["findings"].append({
            "type": "SSL Check Error",
            "value": str(e),
            "severity": "INFO"
        })

    # Method 2: openssl command for protocol support
    if check_tool("openssl"):
        for proto in ["ssl2", "ssl3", "tls1", "tls1_1", "tls1_2", "tls1_3"]:
            code, stdout, stderr = run_command(
                ["openssl", "s_client", f"-{proto}", "-connect", f"{host}:{port}",
                 "-brief"],
                timeout=10
            )
            combined = (stdout + stderr).lower()
            if "handshake failure" not in combined and "error" not in combined and "unsupported" not in combined:
                proto_display = proto.replace("ssl", "SSLv").replace("tls", "TLSv").replace("_", ".")
                severity = "CRITICAL" if proto in ["ssl2", "ssl3", "tls1", "tls1_1"] else "INFO"
                result["findings"].append({
                    "type": f"Protocol Support: {proto_display}",
                    "value": f"Server supports {proto_display}",
                    "severity": severity
                })
                if severity == "CRITICAL":
                    print_warning(f"Server supports deprecated {proto_display}!")
        result["raw"] += "\nOpenSSL protocol checks complete"

    print_success("SSL analysis complete")
    return result


def heartbleed_check(target: str) -> dict:
    """Check for Heartbleed vulnerability using nmap."""
    result = {
        "module": "Heartbleed Check",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("nmap"):
        print_warning("nmap not found — skipping Heartbleed check")
        return result

    host = re.sub(r'^https?://', '', target).split('/')[0]
    print_info(f"Checking Heartbleed (CVE-2014-0160) on {host}...")

    code, stdout, stderr = run_command(
        ["nmap", "-p", "443", "--script", "ssl-heartbleed", host],
        timeout=60
    )

    result["raw"] = stdout + stderr

    if "VULNERABLE" in stdout:
        result["findings"].append({
            "type": "Heartbleed (CVE-2014-0160)",
            "value": "TARGET IS VULNERABLE TO HEARTBLEED! Private keys, passwords, and session tokens may be leaked.",
            "severity": "CRITICAL"
        })
        print_error("CRITICAL: Heartbleed vulnerability confirmed!")
    elif "NOT VULNERABLE" in stdout:
        result["findings"].append({
            "type": "Heartbleed Check",
            "value": "Not vulnerable to Heartbleed",
            "severity": "INFO"
        })
        print_success("Not vulnerable to Heartbleed")

    return result


def poodle_check(target: str) -> dict:
    """Check for POODLE vulnerability."""
    result = {
        "module": "POODLE Check",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("nmap"):
        return result

    host = re.sub(r'^https?://', '', target).split('/')[0]
    print_info(f"Checking POODLE vulnerability on {host}...")

    code, stdout, stderr = run_command(
        ["nmap", "-p", "443", "--script", "ssl-poodle", host],
        timeout=60
    )

    result["raw"] = stdout + stderr

    if "VULNERABLE" in stdout:
        result["findings"].append({
            "type": "POODLE (CVE-2014-3566)",
            "value": "Vulnerable to POODLE attack — SSLv3 padding oracle attack possible",
            "severity": "HIGH"
        })
        print_error("HIGH: POODLE vulnerability found!")
    else:
        result["findings"].append({
            "type": "POODLE Check",
            "value": "Not vulnerable to POODLE",
            "severity": "INFO"
        })

    return result


def _parse_sslscan_output(output: str, result: dict) -> dict:
    """Parse SSLScan output for vulnerabilities."""
    lines = output.split('\n')

    for line in lines:
        # Weak protocols
        for proto in WEAK_PROTOCOLS:
            if proto in line and "Enabled" in line:
                result["findings"].append({
                    "type": f"Weak Protocol: {proto}",
                    "value": f"{proto} is enabled and deprecated",
                    "severity": "CRITICAL" if "SSL" in proto else "HIGH"
                })
                print_warning(f"Weak protocol enabled: {proto}")

        # Weak ciphers
        for weak in WEAK_CIPHERS:
            if weak in line.upper() and "Enabled" in line:
                result["findings"].append({
                    "type": "Weak Cipher",
                    "value": line.strip(),
                    "severity": "HIGH"
                })

        # Certificate issues
        if "expired" in line.lower():
            result["findings"].append({
                "type": "Expired Certificate",
                "value": line.strip(),
                "severity": "CRITICAL"
            })
        if "self-signed" in line.lower():
            result["findings"].append({
                "type": "Self-Signed Certificate",
                "value": line.strip(),
                "severity": "HIGH"
            })

    # Grade calculation
    critical = sum(1 for f in result["findings"] if f["severity"] == "CRITICAL")
    high = sum(1 for f in result["findings"] if f["severity"] == "HIGH")

    if critical > 0:
        result["grade"] = "F"
    elif high >= 3:
        result["grade"] = "D"
    elif high >= 1:
        result["grade"] = "C"
    elif len(result["findings"]) > 2:
        result["grade"] = "B"
    else:
        result["grade"] = "A"

    return result
