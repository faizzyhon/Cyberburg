#!/usr/bin/env python3
"""
Network Mapper — Cyberburg v5 PHANTOM PROTOCOL
CIDR range discovery, ARP sweep, OS fingerprinting, host enumeration.

AUTHORIZED PENETRATION TESTING ONLY.
"""

import os
import re
import json
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.helpers import run_command, get_timestamp, sanitize_filename, parse_nmap_ports
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import box

console = Console()


# ─── ICMP Ping Sweep ──────────────────────────────────────────────────────────

def _ping_host(ip: str) -> tuple[str, bool]:
    """Check if a single host responds to ping."""
    import subprocess, platform
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    ret = subprocess.run(
        ["ping", flag, "1", "-W", "1", str(ip)],
        capture_output=True, timeout=5
    )
    return str(ip), ret.returncode == 0


def ping_sweep(cidr: str, output_dir: str) -> dict:
    """Discover live hosts in a CIDR range using parallel ping."""
    result = {
        "module": "Network Mapper — Ping Sweep",
        "target": cidr,
        "timestamp": get_timestamp(),
        "raw": "",
        "live_hosts": [],
        "findings": []
    }

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        result["raw"] = f"Invalid CIDR: {cidr}"
        return result

    # Cap at /16 to avoid absurd ranges
    if network.num_addresses > 65536:
        result["raw"] = "Range too large (max /16). Narrow your CIDR."
        return result

    console.print(f"  [dim]Pinging {network.num_addresses} hosts in {cidr}...[/dim]")
    live = []

    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_ping_host, ip): ip for ip in network.hosts()}
        for future in as_completed(futures):
            ip, is_up = future.result()
            if is_up:
                live.append(ip)
                print_success(f"Host UP: {ip}")

    result["live_hosts"] = sorted(live, key=lambda x: ipaddress.ip_address(x))
    result["raw"] = f"Ping sweep complete. {len(live)}/{network.num_addresses - 2} hosts up."

    for ip in result["live_hosts"]:
        result["findings"].append({
            "type": "Live Host",
            "severity": "INFO",
            "host": ip,
            "detail": "Host responded to ICMP ping"
        })

    # Save host list
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)
    host_file = os.path.join(loot_dir, f"live_hosts_{sanitize_filename(cidr)}.txt")
    with open(host_file, "w") as f:
        f.write("\n".join(result["live_hosts"]))
    console.print(f"  [dim]Live hosts saved: {host_file}[/dim]")

    return result


# ─── Nmap Network Scan ────────────────────────────────────────────────────────

def nmap_network_scan(cidr: str, output_dir: str) -> dict:
    """Run nmap host discovery + service scan on a CIDR range."""
    result = {
        "module": "Network Mapper — Nmap Range Scan",
        "target": cidr,
        "timestamp": get_timestamp(),
        "raw": "",
        "hosts": [],
        "findings": []
    }

    if not check_tool("nmap"):
        result["raw"] = "nmap not available"
        print_warning("nmap not found — skipping range scan")
        return result

    print_info(f"Running nmap discovery on {cidr}...")
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)
    out_file = os.path.join(loot_dir, f"nmap_network_{sanitize_filename(cidr)}.txt")

    code, stdout, stderr = run_command(
        ["nmap", "-sn", "--open", "-T4", cidr, "-oN", out_file],
        timeout=300
    )
    result["raw"] = stdout or stderr

    # Parse nmap's "Nmap scan report for" lines
    host_pattern = re.compile(r'Nmap scan report for (.+)')
    mac_pattern  = re.compile(r'MAC Address: ([0-9A-F:]+)\s+\((.+)\)')

    current_host = None
    for line in (stdout + stderr).splitlines():
        m = host_pattern.search(line)
        if m:
            current_host = m.group(1).strip()
            result["hosts"].append({"host": current_host, "mac": "", "vendor": ""})
        if current_host and (m2 := mac_pattern.search(line)):
            result["hosts"][-1]["mac"] = m2.group(1)
            result["hosts"][-1]["vendor"] = m2.group(2)

    for h in result["hosts"]:
        result["findings"].append({
            "type": "Live Host",
            "severity": "INFO",
            "host": h["host"],
            "detail": f"MAC: {h['mac']} Vendor: {h['vendor']}"
        })

    return result


def os_fingerprint(ip: str, output_dir: str) -> dict:
    """Run nmap OS detection on a single host."""
    result = {
        "module": "Network Mapper — OS Fingerprint",
        "target": ip,
        "timestamp": get_timestamp(),
        "raw": "",
        "os_matches": [],
        "findings": []
    }

    if not check_tool("nmap"):
        result["raw"] = "nmap not available"
        return result

    print_info(f"OS fingerprinting {ip}...")
    code, stdout, stderr = run_command(
        ["nmap", "-O", "--osscan-guess", "-T4", ip],
        timeout=120
    )
    result["raw"] = stdout or stderr

    os_pattern = re.compile(r'OS details?:\s*(.+)')
    for line in (stdout + stderr).splitlines():
        m = os_pattern.search(line)
        if m:
            os_info = m.group(1).strip()
            result["os_matches"].append(os_info)
            result["findings"].append({
                "type": "OS Detection",
                "severity": "INFO",
                "host": ip,
                "detail": os_info
            })

    return result


def service_sweep(live_hosts: list, output_dir: str) -> dict:
    """Quick service scan on discovered live hosts."""
    result = {
        "module": "Network Mapper — Service Sweep",
        "target": f"{len(live_hosts)} hosts",
        "timestamp": get_timestamp(),
        "raw": "",
        "services": [],
        "findings": []
    }

    if not live_hosts:
        result["raw"] = "No live hosts to scan"
        return result

    if not check_tool("nmap"):
        result["raw"] = "nmap not available"
        return result

    # Scan top 100 ports across all live hosts
    targets = " ".join(live_hosts[:50])  # Cap at 50 hosts
    print_info(f"Service sweep on {len(live_hosts[:50])} hosts (top 100 ports)...")
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)
    out_file = os.path.join(loot_dir, "service_sweep.txt")

    code, stdout, stderr = run_command(
        ["nmap", "--top-ports", "100", "-sV", "-T4", "--open"] + live_hosts[:50],
        timeout=600
    )
    result["raw"] = stdout or stderr

    # Parse open ports
    current_host = None
    host_pattern = re.compile(r'Nmap scan report for (.+)')
    port_pattern  = re.compile(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?')

    for line in (stdout + stderr).splitlines():
        hm = host_pattern.search(line)
        if hm:
            current_host = hm.group(1).strip()
        pm = port_pattern.search(line)
        if pm and current_host:
            entry = {
                "host": current_host,
                "port": int(pm.group(1)),
                "proto": pm.group(2),
                "service": pm.group(3),
                "version": pm.group(4) or ""
            }
            result["services"].append(entry)
            sev = "HIGH" if pm.group(3) in ("telnet", "ftp", "rsh", "rlogin") else "INFO"
            result["findings"].append({
                "type": "Open Service",
                "severity": sev,
                "host": current_host,
                "detail": f"{pm.group(1)}/{pm.group(2)} {pm.group(3)} {pm.group(4) or ''}"
            })

    with open(out_file, "w") as f:
        f.write(stdout)

    return result


# ─── ARP Scan ─────────────────────────────────────────────────────────────────

def arp_scan(cidr: str, output_dir: str) -> dict:
    """Run arp-scan for LAN discovery (requires root)."""
    result = {
        "module": "Network Mapper — ARP Scan",
        "target": cidr,
        "timestamp": get_timestamp(),
        "raw": "",
        "hosts": [],
        "findings": []
    }

    if not check_tool("arp-scan"):
        # Fallback: nmap ARP ping
        if check_tool("nmap"):
            print_info("arp-scan not found, using nmap ARP ping...")
            code, stdout, stderr = run_command(
                ["nmap", "-PR", "-sn", cidr], timeout=120
            )
            result["raw"] = stdout or stderr
            for line in (stdout + stderr).splitlines():
                m = re.search(r'Nmap scan report for (.+)', line)
                if m:
                    result["hosts"].append(m.group(1).strip())
                    result["findings"].append({
                        "type": "ARP Host",
                        "severity": "INFO",
                        "host": m.group(1).strip(),
                        "detail": "Discovered via ARP ping"
                    })
        else:
            result["raw"] = "arp-scan and nmap not available"
        return result

    print_info(f"ARP scanning {cidr}...")
    code, stdout, stderr = run_command(["arp-scan", cidr], timeout=120)
    result["raw"] = stdout or stderr

    arp_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.+)')
    for line in (stdout + stderr).splitlines():
        m = arp_pattern.search(line)
        if m:
            result["hosts"].append(m.group(1))
            result["findings"].append({
                "type": "ARP Host",
                "severity": "INFO",
                "host": m.group(1),
                "detail": f"MAC: {m.group(2)} | Vendor: {m.group(3)}"
            })

    return result


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def run_network_mapper(session, output_dir: str):
    """Full network mapping: ARP, ping sweep, nmap discovery, service sweep."""
    from utils.banner import print_section
    print_section("NETWORK MAPPER — PHANTOM PROTOCOL", "bold blue")

    # Ask for CIDR if not derivable from target
    cidr = Prompt.ask(
        "  [bold cyan]Enter CIDR range[/bold cyan] [dim](e.g. 192.168.1.0/24)[/dim]",
        default=f"{session.ip}/24"
    ).strip()

    results = []

    # ARP scan
    r = arp_scan(cidr, output_dir)
    session.add_result(r)
    results.append(r)

    # Nmap discovery
    r = nmap_network_scan(cidr, output_dir)
    session.add_result(r)
    results.append(r)

    # Collect live hosts
    live_hosts = list(set(
        [h["host"] for h in r.get("hosts", [])] +
        [f["host"] for rr in results for f in rr.get("findings", []) if f.get("type") in ("ARP Host", "Live Host")]
    ))

    if live_hosts:
        # Service sweep
        r = service_sweep(live_hosts, output_dir)
        session.add_result(r)
        results.append(r)

        # OS fingerprint on first 5 live hosts
        for ip in live_hosts[:5]:
            r = os_fingerprint(ip, output_dir)
            session.add_result(r)
            results.append(r)

    # Summary table
    all_findings = [f for r in results for f in r.get("findings", [])]
    table = Table(title="Network Mapper Summary", box=box.SIMPLE, header_style="bold cyan")
    table.add_column("Host", style="cyan")
    table.add_column("Type")
    table.add_column("Detail", style="dim")

    for f in all_findings[:40]:
        sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "blue"}.get(f.get("severity", "INFO"), "white")
        table.add_row(
            f.get("host", "-"),
            f"[{sev_color}]{f.get('type', '-')}[/{sev_color}]",
            f.get("detail", "")[:70]
        )

    console.print(table)
    console.print(f"\n  [bold green][+] Network map complete — {len(live_hosts)} live hosts, {len(all_findings)} findings[/bold green]")
