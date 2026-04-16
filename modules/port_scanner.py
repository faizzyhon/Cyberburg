"""
Port Scanner Module — Cyberburg
Handles: Nmap scanning (quick, full, service, vuln, stealth, UDP)
"""

import re
from utils.helpers import run_command, run_command_stream, get_timestamp, parse_nmap_ports
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error, print_finding
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Ports that are commonly dangerous / interesting
DANGEROUS_PORTS = {
    21: ("FTP", "HIGH", "FTP allows unencrypted file transfer — credentials sent in plaintext"),
    22: ("SSH", "INFO", "SSH service exposed — ensure strong authentication"),
    23: ("Telnet", "CRITICAL", "Telnet transmits data including passwords in plaintext"),
    25: ("SMTP", "MEDIUM", "SMTP exposed — potential for open relay abuse"),
    53: ("DNS", "LOW", "DNS service exposed — check for zone transfer vulnerability"),
    80: ("HTTP", "LOW", "Unencrypted HTTP service"),
    110: ("POP3", "MEDIUM", "POP3 email service — likely transmits credentials in plaintext"),
    111: ("RPC", "HIGH", "RPC portmapper exposed — potential for various RPC attacks"),
    135: ("MSRPC", "HIGH", "Microsoft RPC exposed"),
    139: ("NetBIOS", "HIGH", "NetBIOS session service exposed — SMB attack surface"),
    143: ("IMAP", "MEDIUM", "IMAP email service exposed"),
    161: ("SNMP", "HIGH", "SNMP exposed — often uses default community strings"),
    443: ("HTTPS", "INFO", "HTTPS service exposed"),
    445: ("SMB", "CRITICAL", "SMB service exposed — EternalBlue/ransomware risk"),
    512: ("rexec", "CRITICAL", "Remote execution service exposed"),
    513: ("rlogin", "CRITICAL", "Remote login service exposed"),
    514: ("rsh", "CRITICAL", "Remote shell service exposed"),
    873: ("rsync", "HIGH", "rsync service exposed — potential unauthorized file access"),
    1433: ("MSSQL", "CRITICAL", "Microsoft SQL Server exposed"),
    1521: ("Oracle", "CRITICAL", "Oracle DB exposed"),
    2049: ("NFS", "HIGH", "NFS service exposed — potential unauthorized mount"),
    3306: ("MySQL", "CRITICAL", "MySQL database directly exposed to internet"),
    3389: ("RDP", "HIGH", "Remote Desktop exposed — BlueKeep/brute force risk"),
    4444: ("Metasploit", "CRITICAL", "Metasploit default port — possible backdoor"),
    5432: ("PostgreSQL", "CRITICAL", "PostgreSQL database exposed"),
    5900: ("VNC", "HIGH", "VNC remote desktop exposed"),
    6379: ("Redis", "CRITICAL", "Redis database exposed — often no auth by default"),
    8080: ("HTTP-Alt", "LOW", "Alternative HTTP port"),
    8443: ("HTTPS-Alt", "LOW", "Alternative HTTPS port"),
    9200: ("Elasticsearch", "CRITICAL", "Elasticsearch exposed — often no auth"),
    27017: ("MongoDB", "CRITICAL", "MongoDB exposed — often no auth by default"),
}


def quick_scan(target: str) -> dict:
    """Fast nmap scan of top 1000 ports."""
    result = {
        "module": "Quick Port Scan",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "ports": [],
        "findings": []
    }

    if not check_tool("nmap"):
        print_warning("nmap not found — skipping port scan")
        return result

    print_info(f"Quick scanning {target} (top 1000 ports)...")

    code, stdout, stderr = run_command(
        ["nmap", "-T4", "-F", "--open", "-sV", "--version-light", target],
        timeout=120
    )

    result["raw"] = stdout + stderr
    result["ports"] = parse_nmap_ports(stdout)
    _analyze_ports(result)
    print_success(f"Quick scan done — {len(result['ports'])} open ports found")
    return result


def full_scan(target: str) -> dict:
    """Full TCP port scan (all 65535 ports)."""
    result = {
        "module": "Full Port Scan",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "ports": [],
        "findings": []
    }

    if not check_tool("nmap"):
        print_warning("nmap not found — skipping full port scan")
        return result

    print_info(f"Full port scan on {target} (all 65535 ports — this takes a while)...")

    code, stdout, stderr = run_command(
        ["nmap", "-T4", "-p-", "--open", "-sV", target],
        timeout=600
    )

    result["raw"] = stdout + stderr
    result["ports"] = parse_nmap_ports(stdout)
    _analyze_ports(result)
    print_success(f"Full scan done — {len(result['ports'])} open ports found")
    return result


def service_version_scan(target: str) -> dict:
    """Service & version detection with OS fingerprinting."""
    result = {
        "module": "Service Version Detection",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "ports": [],
        "os_info": [],
        "findings": []
    }

    if not check_tool("nmap"):
        print_warning("nmap not found")
        return result

    print_info(f"Service/version detection on {target}...")

    code, stdout, stderr = run_command(
        ["nmap", "-sV", "-sC", "-O", "--version-intensity", "7", "-T4", target],
        timeout=300
    )

    result["raw"] = stdout + stderr
    result["ports"] = parse_nmap_ports(stdout)

    # Extract OS detection
    os_matches = re.findall(r'OS details?:\s*(.+)', stdout)
    if os_matches:
        result["os_info"] = os_matches
        result["findings"].append({
            "type": "OS Fingerprint",
            "value": os_matches[0],
            "severity": "INFO"
        })

    # Extract CVEs from nmap output
    cves = re.findall(r'(CVE-\d{4}-\d+)', stdout, re.IGNORECASE)
    for cve in set(cves):
        result["findings"].append({
            "type": "CVE Reference",
            "value": f"Potential vulnerability: {cve}",
            "severity": "HIGH"
        })

    _analyze_ports(result)
    print_success("Service detection complete")
    return result


def vuln_scan(target: str) -> dict:
    """Nmap vulnerability scripts scan."""
    result = {
        "module": "Nmap Vulnerability Scan",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "ports": [],
        "findings": []
    }

    if not check_tool("nmap"):
        print_warning("nmap not found")
        return result

    print_info(f"Running nmap vuln scripts on {target}...")

    # Run vulnerability detection scripts
    code, stdout, stderr = run_command(
        [
            "nmap", "-T4", "--script",
            "vuln,auth,default,exploit,brute,discovery",
            "-sV", "-p-", target
        ],
        timeout=600
    )

    result["raw"] = stdout + stderr
    result["ports"] = parse_nmap_ports(stdout)

    # Parse script output for vulnerabilities
    vuln_patterns = [
        (r'(VULNERABLE|EXPLOITABLE).*?(?=\n\n|\Z)', "CRITICAL"),
        (r'CVE-\d{4}-\d+', "HIGH"),
        (r'Anonymous FTP login allowed', "HIGH"),
        (r'Default credentials', "CRITICAL"),
        (r'Brute force', "HIGH"),
        (r'SSL.*?vulnerable', "HIGH"),
        (r'Heartbleed', "CRITICAL"),
        (r'EternalBlue', "CRITICAL"),
        (r'ShellShock', "CRITICAL"),
    ]

    for pattern, severity in vuln_patterns:
        matches = re.findall(pattern, stdout, re.IGNORECASE | re.DOTALL)
        for match in matches:
            match_str = match.strip()[:200]
            if match_str:
                result["findings"].append({
                    "type": "Nmap Script Finding",
                    "value": match_str,
                    "severity": severity
                })

    _analyze_ports(result)
    print_success("Nmap vuln scan complete")
    return result


def stealth_scan(target: str) -> dict:
    """SYN stealth scan (requires root)."""
    result = {
        "module": "Stealth SYN Scan",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "ports": [],
        "findings": []
    }

    if not check_tool("nmap"):
        print_warning("nmap not found")
        return result

    print_info(f"Running stealth SYN scan on {target} (requires root)...")

    code, stdout, stderr = run_command(
        ["nmap", "-sS", "-T3", "-p-", "--open", "-D", "RND:10", target],
        timeout=600
    )

    if "requires root" in (stdout + stderr).lower() or "Operation not permitted" in stderr:
        print_warning("Stealth scan requires root — falling back to TCP scan")
        code, stdout, stderr = run_command(
            ["nmap", "-sT", "-T4", "-p-", "--open", target], timeout=600
        )

    result["raw"] = stdout + stderr
    result["ports"] = parse_nmap_ports(stdout)
    _analyze_ports(result)
    print_success("Stealth scan complete")
    return result


def udp_scan(target: str) -> dict:
    """UDP port scan (requires root)."""
    result = {
        "module": "UDP Port Scan",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "ports": [],
        "findings": []
    }

    if not check_tool("nmap"):
        print_warning("nmap not found")
        return result

    print_info(f"Running UDP scan on {target} top 100 ports (requires root)...")

    code, stdout, stderr = run_command(
        ["nmap", "-sU", "--top-ports", "100", "-T4", target],
        timeout=300
    )

    result["raw"] = stdout + stderr
    result["ports"] = parse_nmap_ports(stdout)
    _analyze_ports(result)
    print_success("UDP scan complete")
    return result


def firewall_detection(target: str) -> dict:
    """Detect firewall/IDS using nmap techniques."""
    result = {
        "module": "Firewall/IDS Detection",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("nmap"):
        print_warning("nmap not found")
        return result

    print_info(f"Detecting firewall/IDS on {target}...")

    # ACK scan for firewall detection
    code, stdout, stderr = run_command(
        ["nmap", "-sA", "-T4", "--top-ports", "100", target],
        timeout=120
    )

    result["raw"] = stdout + stderr

    if "filtered" in stdout:
        filtered_count = stdout.count("filtered")
        result["findings"].append({
            "type": "Firewall Detected",
            "value": f"{filtered_count} ports filtered — firewall/IDS likely present",
            "severity": "INFO"
        })
        print_success("Firewall detected")
    else:
        result["findings"].append({
            "type": "No Firewall Detected",
            "value": "No firewall filtering detected — all probed ports appear unfiltered",
            "severity": "HIGH"
        })
        print_warning("No firewall detected!")

    return result


def _analyze_ports(result: dict):
    """Analyze open ports and generate security findings."""
    for port_info in result.get("ports", []):
        port = port_info["port"]
        service = port_info.get("service", "unknown")
        version = port_info.get("version", "")

        if port in DANGEROUS_PORTS:
            svc_name, severity, desc = DANGEROUS_PORTS[port]
            result["findings"].append({
                "type": f"Dangerous Port Open: {port}/{service}",
                "value": f"Port {port} ({svc_name}): {desc}. Version: {version or 'unknown'}",
                "severity": severity
            })
        else:
            result["findings"].append({
                "type": f"Open Port: {port}/{service}",
                "value": f"Port {port} open — Service: {service}, Version: {version or 'unknown'}",
                "severity": "INFO"
            })

        # Check for outdated versions
        outdated_checks = [
            ("vsftpd 2.3.4", "CRITICAL", "vsftpd 2.3.4 contains a backdoor (CVE-2011-2523)"),
            ("OpenSSH 7.2", "HIGH", "OpenSSH 7.2 may be vulnerable to username enumeration"),
            ("Apache/2.2", "HIGH", "Apache 2.2 is EOL — multiple known vulnerabilities"),
            ("Apache/2.4.49", "CRITICAL", "Apache 2.4.49 is vulnerable to path traversal (CVE-2021-41773)"),
            ("nginx/1.14", "MEDIUM", "nginx 1.14 has known security issues"),
            ("PHP/5.", "CRITICAL", "PHP 5.x is EOL and contains many unpatched vulnerabilities"),
            ("PHP/7.0", "HIGH", "PHP 7.0 is EOL"),
            ("PHP/7.1", "HIGH", "PHP 7.1 is EOL"),
            ("IIS/6.0", "CRITICAL", "IIS 6.0 is EOL with multiple RCE vulnerabilities"),
            ("IIS/7.5", "HIGH", "IIS 7.5 has known vulnerabilities"),
            ("OpenSSL/1.0.1", "CRITICAL", "OpenSSL 1.0.1 vulnerable to Heartbleed (CVE-2014-0160)"),
            ("MySQL 5.0", "HIGH", "MySQL 5.0 is EOL"),
            ("ProFTPD 1.3.5", "HIGH", "ProFTPD 1.3.5 has known vulnerabilities"),
        ]

        for pattern, severity, description in outdated_checks:
            if pattern.lower() in version.lower():
                result["findings"].append({
                    "type": "Outdated/Vulnerable Software",
                    "value": f"Port {port}: {description} (detected: {version})",
                    "severity": severity
                })


def display_ports_table(ports: list):
    """Display port scan results in a rich table."""
    if not ports:
        console.print("[dim]No open ports found.[/dim]")
        return

    table = Table(title="Open Ports", box=None, show_header=True, header_style="bold cyan")
    table.add_column("Port", style="bold yellow", width=8)
    table.add_column("Protocol", width=10)
    table.add_column("State", width=10)
    table.add_column("Service", style="bold white", width=15)
    table.add_column("Version", style="dim")
    table.add_column("Risk", width=10)

    for p in ports:
        port = p["port"]
        risk = ""
        if port in DANGEROUS_PORTS:
            _, sev, _ = DANGEROUS_PORTS[port]
            color_map = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "INFO": "green", "LOW": "cyan"}
            c = color_map.get(sev, "white")
            risk = f"[{c}]{sev}[/{c}]"
        else:
            risk = "[dim]INFO[/dim]"

        table.add_row(
            str(p["port"]),
            p.get("protocol", "tcp"),
            p.get("state", "open"),
            p.get("service", "unknown"),
            p.get("version", "")[:50],
            risk
        )

    console.print(table)
