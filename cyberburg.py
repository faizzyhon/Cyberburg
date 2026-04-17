#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CYBERBURG v4.0.0 — DARK MATTER                          ║
║          Advanced Web Penetration Testing & Vulnerability Scanner           ║
║                                                                              ║
║   Developer : Faiz Zyhon                                                    ║
║   GitHub    : github.com/faizzyhon                                          ║
║   Instagram : instagram.com/faizzyhon                                       ║
║   Website   : faizzyhon.online                                              ║
║                                                                              ║
║   For authorized penetration testing and security research ONLY             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import time
import json
import signal
import argparse
from datetime import datetime

# Fix import path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn,
        BarColumn, TimeElapsedColumn
    )
    from rich.text import Text
    from rich.rule import Rule
    from rich import box
except ImportError:
    print("ERROR: 'rich' library not found. Run: pip3 install rich")
    sys.exit(1)

# Import Cyberburg modules
from utils.banner import print_banner, print_section, print_info, print_success, print_warning, print_error
from utils.tool_checker import display_tool_status, get_available_tools, check_tool
from utils.helpers import (
    normalize_target, is_valid_target, get_timestamp,
    get_filename_timestamp, severity_score, risk_rating,
    setup_output_dir, save_session_snapshot
)

console = Console()

# ─── Scan result container ────────────────────────────────────────────────────

class ScanSession:
    """Holds all scan results for a target."""

    def __init__(self, target: str, output_dir: str = None):
        self.target = target
        url, hostname, ip = normalize_target(target)
        self.url = url
        self.hostname = hostname
        self.ip = ip
        self.start_time = get_timestamp()
        self.end_time = None
        self.modules = []
        self.output_dir = output_dir or setup_output_dir(hostname)

    def add_result(self, result: dict):
        self.modules.append(result)
        # Auto-save snapshot after every module
        save_session_snapshot(self.to_dict(), self.output_dir)

    def all_findings(self):
        findings = []
        for m in self.modules:
            for f in m.get("findings", []):
                f["module"] = m.get("module", "Unknown")
                findings.append(f)
        return findings

    def to_dict(self):
        return {
            "target": self.target,
            "hostname": self.hostname,
            "ip": self.ip,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "modules": self.modules,
        }

    def print_summary(self):
        findings = self.all_findings()
        counts = severity_score(findings)
        rating, _ = risk_rating(counts)

        color_map = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "blue"
        }
        rating_color = color_map.get(rating, "white")

        table = Table(title=f"Scan Summary — {self.hostname}", box=box.DOUBLE_EDGE,
                      show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="bold white", width=25)
        table.add_column("Value", width=30)

        table.add_row("Target", self.target)
        table.add_row("IP Address", self.ip)
        table.add_row("Scan Start", self.start_time)
        table.add_row("Scan End", self.end_time or get_timestamp())
        table.add_row("Risk Rating", f"[{rating_color}]{rating}[/{rating_color}]")
        table.add_row("Total Findings", str(len(findings)))
        table.add_row("Critical", f"[bold red]{counts.get('CRITICAL', 0)}[/bold red]")
        table.add_row("High", f"[red]{counts.get('HIGH', 0)}[/red]")
        table.add_row("Medium", f"[yellow]{counts.get('MEDIUM', 0)}[/yellow]")
        table.add_row("Low", f"[cyan]{counts.get('LOW', 0)}[/cyan]")
        table.add_row("Info", f"[blue]{counts.get('INFO', 0)}[/blue]")

        console.print(table)


# ─── Scan functions ───────────────────────────────────────────────────────────

def run_recon(session: ScanSession):
    """Run full reconnaissance."""
    from modules.recon import (
        whois_lookup, dns_lookup, subdomain_enumeration,
        ip_geolocation, harvest_emails
    )

    print_section("RECONNAISSANCE")

    session.add_result(whois_lookup(session.hostname))
    session.add_result(dns_lookup(session.hostname))
    session.add_result(ip_geolocation(session.ip))
    session.add_result(subdomain_enumeration(session.hostname))
    session.add_result(harvest_emails(session.hostname))


def run_port_scan(session: ScanSession, mode: str = "quick"):
    """Run port scanning."""
    from modules.port_scanner import (
        quick_scan, full_scan, service_version_scan,
        vuln_scan, stealth_scan, udp_scan, firewall_detection
    )
    from modules.port_scanner import display_ports_table

    print_section("PORT SCANNING")

    if mode == "quick":
        result = quick_scan(session.ip)
    elif mode == "full":
        result = full_scan(session.ip)
    elif mode == "stealth":
        result = stealth_scan(session.ip)
    else:
        result = service_version_scan(session.ip)

    session.add_result(result)
    display_ports_table(result.get("ports", []))

    session.add_result(firewall_detection(session.ip))

    if mode in ["full", "service"]:
        session.add_result(vuln_scan(session.ip))
        session.add_result(udp_scan(session.ip))


def run_web_scan(session: ScanSession):
    """Run web application scanning."""
    from modules.web_scanner import (
        nikto_scan, whatweb_scan, waf_detection,
        http_methods_check, header_analysis, cms_scan,
        robots_sitemap_check
    )

    print_section("WEB APPLICATION SCANNING")

    session.add_result(whatweb_scan(session.url))
    session.add_result(waf_detection(session.url))
    session.add_result(header_analysis(session.url))
    session.add_result(http_methods_check(session.url))
    session.add_result(robots_sitemap_check(session.url))
    session.add_result(cms_scan(session.url))
    session.add_result(nikto_scan(session.url))


def run_ssl_scan(session: ScanSession):
    """Run SSL/TLS analysis."""
    from modules.ssl_analyzer import (
        openssl_check, sslscan_analysis, heartbleed_check, poodle_check
    )

    print_section("SSL/TLS ANALYSIS")

    session.add_result(openssl_check(session.url))
    session.add_result(sslscan_analysis(session.url))
    session.add_result(heartbleed_check(session.url))
    session.add_result(poodle_check(session.url))


def run_vuln_scan(session: ScanSession):
    """Run vulnerability scanning (XSS, SQLi, directories)."""
    from modules.sql_injection import sqlmap_quick, manual_sqli_test
    from modules.xss_scanner import dalfox_scan, dom_xss_check
    from modules.dir_bruteforce import gobuster_scan, manual_path_check, api_fuzzing
    from modules.nuclei_scan import nuclei_scan, nuclei_cves, nuclei_exposed_panels

    print_section("VULNERABILITY SCANNING")

    # Directory bruting
    session.add_result(gobuster_scan(session.url))
    session.add_result(manual_path_check(session.url))
    session.add_result(api_fuzzing(session.url))

    # Injection
    session.add_result(sqlmap_quick(session.url))
    session.add_result(manual_sqli_test(session.url))

    # XSS
    session.add_result(dalfox_scan(session.url))
    session.add_result(dom_xss_check(session.url))

    # Nuclei
    session.add_result(nuclei_scan(session.url))
    session.add_result(nuclei_cves(session.url))
    session.add_result(nuclei_exposed_panels(session.url))


def generate_reports(session: ScanSession) -> dict:
    """Generate all report formats."""
    from modules.report_gen import (
        generate_html_report, generate_json_report, generate_txt_report
    )

    print_section("GENERATING REPORTS")

    session.end_time = get_timestamp()
    scan_dict = session.to_dict()

    reports = {}
    reports["html"] = generate_html_report(scan_dict)
    reports["json"] = generate_json_report(scan_dict)
    reports["txt"] = generate_txt_report(scan_dict)

    return reports


# ─── Interactive Menu ─────────────────────────────────────────────────────────

def interactive_menu():
    """Main interactive menu."""
    print_banner()

    while True:
        console.print("\n[bold cyan]╔═════════════════════════════════════════════╗[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]        [bold white]CYBERBURG v4 — DARK MATTER[/bold white]          [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]╠═════════════════════════════════════════════╣[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold green]1.[/bold green]   Full Scan (All Modules)               [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold green]2.[/bold green]   Quick Scan (Recon + Web + Ports)      [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold green]3.[/bold green]   Stealth Scan                          [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold green]4.[/bold green]   Custom Scan (Select Modules)          [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold green]5.[/bold green]   Web Vulnerability Only                [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold green]6.[/bold green]   SSL/TLS Analysis Only                 [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold green]7.[/bold green]   Reconnaissance Only                   [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold green]8.[/bold green]   Authentication Testing                [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]╠═════════════════════════════════════════════╣[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold red]11.[/bold red]  Exploit Mode (v3 Auto Attacks)        [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold magenta]12.[/bold magenta]  Data Harvesting (v3 Secrets & Loot)  [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold red]13.[/bold red]  GOD MODE — Elite Attack Chain (v4)   [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold yellow]14.[/bold yellow]  CVE Intelligence Lookup (v4)         [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold cyan]15.[/bold cyan]  AI Analysis — Claude Expert (v4)     [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold green]16.[/bold green]  Screenshot Capture (v4)              [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold red]17.[/bold red]  Metasploit Integration (v4)          [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]╠═════════════════════════════════════════════╣[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold green]9.[/bold green]   Check Tool Availability               [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold green]10.[/bold green]  View Previous Reports                 [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold yellow]O.[/bold yellow]   Open Output Folder                   [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold yellow]K.[/bold yellow]   Configure AI API Key                 [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold magenta]D.[/bold magenta]   Launch Web Dashboard (localhost)      [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]║[/bold cyan]  [bold red]0.[/bold red]   Exit                                  [bold cyan]║[/bold cyan]")
        console.print("[bold cyan]╚═════════════════════════════════════════════╝[/bold cyan]")

        choice = Prompt.ask("\n[bold yellow]  ◆ Select option[/bold yellow]", default="1")

        if choice == "0":
            console.print("\n[bold red]Exiting Cyberburg. Stay ethical![/bold red]")
            sys.exit(0)

        elif choice == "D" or choice == "d":
            console.print("\n[bold magenta]  Launching Cyberburg Dashboard...[/bold magenta]")
            console.print("  [dim]Open http://localhost:5000 in your browser[/dim]")
            try:
                import subprocess, sys
                dashboard_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "start_dashboard.py")
                subprocess.Popen([sys.executable, dashboard_script], cwd=os.path.dirname(os.path.abspath(__file__)))
                time.sleep(1.5)
                import webbrowser
                webbrowser.open("http://localhost:5000")
            except Exception as e:
                print_error(f"Dashboard error: {e}")
            continue

        elif choice == "9":
            display_tool_status()
            continue

        elif choice == "10":
            _view_reports()
            continue

        elif choice == "O" or choice == "o":
            _open_output_folder()
            continue

        elif choice == "K" or choice == "k":
            from modules.ai_analyst import configure_api_key
            configure_api_key()
            continue

        # Get target for scan options
        target = Prompt.ask("\n[bold cyan]  ◆ Enter target[/bold cyan] [dim](URL, domain, or IP)[/dim]")

        if not target.strip():
            print_error("No target provided")
            continue

        if not is_valid_target(target):
            print_error(f"Invalid target: {target}")
            continue

        # Confirmation
        console.print(f"\n[bold yellow]  ⚠  Scanning: [white]{target}[/white][/bold yellow]")
        console.print("[dim]  Ensure you have written authorization to test this target.[/dim]")

        if not Confirm.ask("  Proceed?", default=True):
            continue

        session = ScanSession(target)
        console.print(f"\n[bold green]  [+] Session started — {session.hostname} ({session.ip})[/bold green]")
        console.print(f"  [dim]Start time: {session.start_time}[/dim]\n")

        try:
            if choice == "1":
                _full_scan(session)
            elif choice == "2":
                _quick_scan(session)
            elif choice == "3":
                _stealth_scan(session)
            elif choice == "4":
                _custom_scan(session)
            elif choice == "5":
                run_web_scan(session)
                run_vuln_scan(session)
            elif choice == "6":
                run_ssl_scan(session)
            elif choice == "7":
                run_recon(session)
            elif choice == "8":
                _run_auth(session)
            elif choice == "11":
                _run_exploit_mode(session)
            elif choice == "12":
                _run_data_harvest(session)
            elif choice == "13":
                _run_god_mode(session)
            elif choice == "14":
                _run_cve_lookup(session)
            elif choice == "15":
                _run_ai_analysis(session)
            elif choice == "16":
                _run_screenshot(session)
            elif choice == "17":
                _run_metasploit(session)

            # Print summary
            console.print()
            session.print_summary()

            # Generate reports
            if Confirm.ask("\n  [bold cyan]Generate reports?[/bold cyan]", default=True):
                reports = generate_reports(session)
                console.print(f"\n[bold green]  Reports generated:[/bold green]")
                for fmt, path in reports.items():
                    console.print(f"  [{fmt.upper()}] {path}")

        except KeyboardInterrupt:
            print_warning("\nScan interrupted by user")
            session.end_time = get_timestamp()

            if Confirm.ask("\n  Generate partial report?", default=True):
                generate_reports(session)

        console.print(f"\n[dim]  Session complete. {len(session.all_findings())} total findings.[/dim]")
        console.print(f"[bold green]  Output saved to: {session.output_dir}[/bold green]")


def _full_scan(session: ScanSession):
    """Run all scan modules."""
    print_section("FULL SCAN — ALL MODULES", "bold red")
    run_recon(session)
    run_port_scan(session, mode="full")
    run_ssl_scan(session)
    run_web_scan(session)
    run_vuln_scan(session)


def _quick_scan(session: ScanSession):
    """Run quick scan."""
    print_section("QUICK SCAN")
    run_recon(session)
    run_port_scan(session, mode="quick")
    run_ssl_scan(session)
    run_web_scan(session)


def _stealth_scan(session: ScanSession):
    """Run stealth scan."""
    from modules.port_scanner import stealth_scan, firewall_detection

    print_section("STEALTH SCAN")

    # Lighter recon
    from modules.recon import whois_lookup, dns_lookup, ip_geolocation
    session.add_result(whois_lookup(session.hostname))
    session.add_result(dns_lookup(session.hostname))
    session.add_result(ip_geolocation(session.ip))

    # Stealth port scan
    result = stealth_scan(session.ip)
    session.add_result(result)
    session.add_result(firewall_detection(session.ip))

    # Silent web checks
    from modules.web_scanner import header_analysis, waf_detection
    session.add_result(header_analysis(session.url))
    session.add_result(waf_detection(session.url))

    # SSL
    from modules.ssl_analyzer import openssl_check
    session.add_result(openssl_check(session.url))


def _custom_scan(session: ScanSession):
    """Allow user to select individual modules."""
    console.print("\n[bold cyan]Select modules to run:[/bold cyan]")

    modules = {
        "1":  ("Reconnaissance (WHOIS, DNS, Subdomains)", lambda: run_recon(session)),
        "2":  ("Port Scan — Quick", lambda: run_port_scan(session, "quick")),
        "3":  ("Port Scan — Full (all 65535 ports)", lambda: run_port_scan(session, "full")),
        "4":  ("SSL/TLS Analysis", lambda: run_ssl_scan(session)),
        "5":  ("Web Vulnerability Scan (Nikto, WhatWeb, Headers)", lambda: run_web_scan(session)),
        "6":  ("SQL Injection Testing", lambda: _run_sqli(session)),
        "7":  ("XSS Testing", lambda: _run_xss(session)),
        "8":  ("Directory Bruteforce", lambda: _run_dirbust(session)),
        "9":  ("Nuclei Template Scan", lambda: _run_nuclei(session)),
        "10": ("Authentication Testing (Login/Default Creds)", lambda: _run_auth(session)),
        "11": ("[v3] Exploit Mode — Automated Attacks", lambda: _run_exploit_mode(session)),
        "12": ("[v3] Data Harvesting — Secrets & Loot", lambda: _run_data_harvest(session)),
    }

    for key, (name, _) in modules.items():
        console.print(f"  [bold green]{key}.[/bold green] {name}")

    selected = Prompt.ask(
        "\n  [bold yellow]Select modules[/bold yellow] [dim](e.g. 1,2,4,5)[/dim]",
        default="1,2,4,5"
    )

    selected_keys = [s.strip() for s in selected.split(',')]
    for key in selected_keys:
        if key in modules:
            try:
                modules[key][1]()
            except Exception as e:
                print_error(f"Module error: {e}")


def _run_sqli(session):
    from modules.sql_injection import sqlmap_quick, manual_sqli_test
    session.add_result(sqlmap_quick(session.url))
    session.add_result(manual_sqli_test(session.url))


def _run_xss(session):
    from modules.xss_scanner import dalfox_scan, dom_xss_check
    session.add_result(dalfox_scan(session.url))
    session.add_result(dom_xss_check(session.url))


def _run_dirbust(session):
    from modules.dir_bruteforce import gobuster_scan, manual_path_check, api_fuzzing
    session.add_result(gobuster_scan(session.url))
    session.add_result(manual_path_check(session.url))
    session.add_result(api_fuzzing(session.url))


def _run_nuclei(session):
    from modules.nuclei_scan import nuclei_scan, nuclei_cves
    session.add_result(nuclei_scan(session.url))
    session.add_result(nuclei_cves(session.url))


def _run_god_mode(session: ScanSession):
    """Run the elite 12-vector attack chain."""
    from modules.god_mode import run_god_mode
    run_god_mode(session, session.output_dir)
    crits = [f for f in session.all_findings() if f.get("severity") == "CRITICAL"]
    if crits:
        from modules.bug_bounty_report import create_bug_bounty_report
        bb_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bug_bounty_reports")
        os.makedirs(bb_dir, exist_ok=True)
        bb_path = create_bug_bounty_report(
            f"godmode_{session.hostname}", session.target, crits, bb_dir
        )
        console.print(f"\n[bold red]  Bug Bounty report: {bb_path}[/bold red]")


def _run_cve_lookup(session: ScanSession):
    """Run CVE intelligence lookup against detected technologies."""
    from modules.cve_lookup import run_cve_lookup
    result = run_cve_lookup(session, session.output_dir)
    session.add_result(result)


def _run_ai_analysis(session: ScanSession):
    """Run Claude AI expert analysis on all findings."""
    from modules.ai_analyst import run_ai_analysis
    result = run_ai_analysis(session, session.output_dir)
    session.add_result(result)


def _run_screenshot(session: ScanSession):
    """Capture screenshots of discovered pages."""
    from modules.screenshot import run_screenshot_capture
    result = run_screenshot_capture(session, session.output_dir)
    session.add_result(result)


def _run_metasploit(session: ScanSession):
    """Generate Metasploit resource script and display run instructions."""
    from modules.metasploit_integration import run_metasploit_integration
    result = run_metasploit_integration(session, session.output_dir)
    session.add_result(result)


def _run_exploit_mode(session: ScanSession):
    """Run automated exploitation engine."""
    from modules.exploit_engine import run_exploit_mode
    run_exploit_mode(session, session.output_dir)

    crits = [f for f in session.all_findings() if f.get("severity") == "CRITICAL"]
    if crits:
        from modules.bug_bounty_report import create_bug_bounty_report
        bb_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bug_bounty_reports")
        os.makedirs(bb_dir, exist_ok=True)
        bb_path = create_bug_bounty_report(
            f"exploit_{session.hostname}", session.target, crits, bb_dir
        )
        console.print(f"\n[bold red]  🚨 Bug Bounty report generated: {bb_path}[/bold red]")


def _run_data_harvest(session: ScanSession):
    """Run data harvesting module."""
    from modules.data_harvester import run_data_harvest
    run_data_harvest(session, session.output_dir)


def _open_output_folder():
    """Open the output folder in the file manager."""
    import subprocess
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(output_dir, exist_ok=True)
    console.print(f"\n[bold yellow]  Output folder: {output_dir}[/bold yellow]")
    try:
        if os.name == "nt":
            subprocess.Popen(["explorer", output_dir])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", output_dir])
        else:
            subprocess.Popen(["xdg-open", output_dir])
    except Exception as e:
        print_warning(f"Could not open folder automatically: {e}")


def _run_auth(session, login_url: str = None, username: str = None, password: str = None):
    """Run authentication testing module."""
    from modules.auth_tester import run_auth_tests
    if not login_url:
        login_url = Prompt.ask(
            "\n  [bold cyan]  Login URL[/bold cyan] [dim](leave blank for auto-detect)[/dim]",
            default=""
        ).strip() or None
    if not username:
        username = Prompt.ask(
            "  [bold cyan]  Username / Email[/bold cyan] [dim](optional — leave blank to skip)[/dim]",
            default=""
        ).strip() or None
    if username and not password:
        from rich.prompt import Prompt as P
        import getpass
        password = getpass.getpass("  Password: ").strip() or None

    result = run_auth_tests(session.url, login_url, username, password)
    session.add_result(result.to_module_dict())

    # Auto-generate bug bounty report if critical findings found
    crits = [f for f in result.findings if f.get("severity") == "CRITICAL"]
    if crits:
        from modules.bug_bounty_report import create_bug_bounty_report
        bb_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bug_bounty_reports")
        os.makedirs(bb_dir, exist_ok=True)
        bb_path = create_bug_bounty_report(
            f"cli_{session.hostname}", session.target, result.findings, bb_dir
        )
        console.print(f"\n[bold red]  🚨 CRITICAL ALERT: Bug Bounty report generated:[/bold red]")
        console.print(f"  [bold white]{bb_path}[/bold white]")


def _view_reports():
    """List and open previous reports."""
    reports_dir = "reports"
    if not os.path.isdir(reports_dir):
        print_warning("No reports directory found")
        return

    files = sorted(
        [f for f in os.listdir(reports_dir) if f.endswith(('.html', '.json', '.txt'))],
        reverse=True
    )

    if not files:
        print_warning("No reports found in ./reports/")
        return

    table = Table(title="Previous Reports", box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("#", width=4)
    table.add_column("Filename", style="cyan")
    table.add_column("Size", width=10)
    table.add_column("Modified", width=20)

    for i, fname in enumerate(files[:20], 1):
        fpath = os.path.join(reports_dir, fname)
        size = os.path.getsize(fpath)
        mtime = datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M")
        size_str = f"{size//1024} KB" if size > 1024 else f"{size} B"
        table.add_row(str(i), fname, size_str, mtime)

    console.print(table)


# ─── CLI Entry ────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="cyberburg",
        description="Cyberburg — Advanced Web Penetration Testing Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cyberburg.py                           # Interactive menu
  python3 cyberburg.py -t example.com            # Full scan
  python3 cyberburg.py -t example.com --quick    # Quick scan
  python3 cyberburg.py -t example.com --recon    # Recon only
  python3 cyberburg.py -t example.com --web      # Web scan only
  python3 cyberburg.py -t example.com --ssl      # SSL only
  python3 cyberburg.py -t example.com --vuln     # Vuln scan only
  python3 cyberburg.py -t example.com --stealth  # Stealth scan
  python3 cyberburg.py -t example.com --exploit    # [v3] Automated attacks
  python3 cyberburg.py -t example.com --harvest    # [v3] Data harvesting
  python3 cyberburg.py -t example.com --god-mode   # [v4] Elite attack chain
  python3 cyberburg.py -t example.com --cve        # [v4] CVE intelligence
  python3 cyberburg.py -t example.com --ai         # [v4] Claude AI analysis
  python3 cyberburg.py -t example.com --screenshot # [v4] Screenshots
  python3 cyberburg.py -t example.com --msf        # [v4] Metasploit .rc script
  python3 cyberburg.py --tools                     # Check tools

Developer: Faiz Zyhon | github.com/faizzyhon | faizzyhon.online
        """
    )

    parser.add_argument("-t", "--target", help="Target URL, domain, or IP address")
    parser.add_argument("--full", action="store_true", help="Run full scan (all modules)")
    parser.add_argument("--quick", action="store_true", help="Quick scan (recon + ports + web)")
    parser.add_argument("--stealth", action="store_true", help="Stealth mode scan")
    parser.add_argument("--recon", action="store_true", help="Reconnaissance only")
    parser.add_argument("--web", action="store_true", help="Web vulnerability scan only")
    parser.add_argument("--ssl", action="store_true", help="SSL/TLS analysis only")
    parser.add_argument("--vuln", action="store_true", help="Vulnerability scan only")
    parser.add_argument("--ports", action="store_true", help="Port scan only")
    parser.add_argument("--auth", action="store_true", help="Authentication testing only")
    parser.add_argument("--login-url", help="Login page URL for auth testing")
    parser.add_argument("--username", help="Username/email for auth testing")
    parser.add_argument("--password", help="Password for auth testing")
    parser.add_argument("--exploit", action="store_true", help="[v3] Automated exploitation mode")
    parser.add_argument("--harvest", action="store_true", help="[v3] Data harvesting mode (JS secrets, configs, git)")
    parser.add_argument("--god-mode", action="store_true", help="[v4] Elite 12-vector attack chain")
    parser.add_argument("--cve", action="store_true", help="[v4] CVE intelligence lookup")
    parser.add_argument("--ai", action="store_true", help="[v4] Claude AI expert analysis")
    parser.add_argument("--screenshot", action="store_true", help="[v4] Screenshot capture")
    parser.add_argument("--msf", action="store_true", help="[v4] Metasploit resource script generation")
    parser.add_argument("--tools", action="store_true", help="Check available tools")
    parser.add_argument("--dashboard", action="store_true", help="Launch web dashboard on localhost:5000")
    parser.add_argument("--no-report", action="store_true", help="Skip report generation")
    parser.add_argument("-o", "--output", help="Custom output directory")
    parser.add_argument("--version", action="version", version="Cyberburg v4.0.0 — DARK MATTER")

    return parser.parse_args()


def main():
    """Main entry point."""
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        console.print("\n\n[bold red]  ✘  Interrupted. Exiting Cyberburg...[/bold red]")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    args = parse_args()

    # Check tools only
    if args.tools:
        print_banner()
        display_tool_status()
        return

    # Launch dashboard
    if args.dashboard:
        try:
            from start_dashboard import main as dashboard_main
            dashboard_main()
        except ImportError:
            print_error("Dashboard not available. Run: pip install flask")
        return

    # No arguments = interactive mode
    if not args.target:
        interactive_menu()
        return

    # CLI mode
    print_banner()

    target = args.target
    if not is_valid_target(target):
        print_error(f"Invalid target: {target}")
        sys.exit(1)

    output_dir = setup_output_dir(normalize_target(target)[1], args.output) if args.output else None
    session = ScanSession(target, output_dir)
    console.print(f"\n[bold green]  [+] Target: {session.url}[/bold green]")
    console.print(f"  [dim]IP: {session.ip} | Start: {session.start_time}[/dim]")
    console.print(f"  [dim]Output: {session.output_dir}[/dim]\n")

    try:
        has_mode = any([args.quick, args.stealth, args.recon, args.web,
                        args.ssl, args.vuln, args.ports, args.auth,
                        args.exploit, args.harvest,
                        args.god_mode, args.cve, args.ai, args.screenshot, args.msf])
        if args.full or not has_mode:
            _full_scan(session)
            if args.login_url or args.username:
                _run_auth(session, args.login_url, args.username, args.password)
        elif args.quick:
            _quick_scan(session)
        elif args.stealth:
            _stealth_scan(session)
        elif args.recon:
            run_recon(session)
        elif args.web:
            run_web_scan(session)
            run_vuln_scan(session)
        elif args.ssl:
            run_ssl_scan(session)
        elif args.vuln:
            run_vuln_scan(session)
        elif args.ports:
            run_port_scan(session, mode="full")
        elif args.auth:
            _run_auth(session, args.login_url, args.username, args.password)
        elif args.exploit:
            _run_exploit_mode(session)
        elif args.harvest:
            _run_data_harvest(session)
        elif args.god_mode:
            _run_god_mode(session)
        elif args.cve:
            _run_cve_lookup(session)
        elif args.ai:
            _run_ai_analysis(session)
        elif args.screenshot:
            _run_screenshot(session)
        elif args.msf:
            _run_metasploit(session)

        # Summary
        console.print()
        session.print_summary()

        # Generate reports
        if not args.no_report:
            reports = generate_reports(session)
            console.print(f"\n[bold green]  Reports generated:[/bold green]")
            for fmt, path in reports.items():
                console.print(f"  [{fmt.upper()}] {path}")

        console.print(f"\n[bold green]  All output saved to: {session.output_dir}[/bold green]")

    except KeyboardInterrupt:
        print_warning("\nScan interrupted")
        session.end_time = get_timestamp()
        if not args.no_report and session.modules:
            generate_reports(session)
    except Exception as e:
        print_error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
