"""
Tool availability checker for Cyberburg
Verifies which Linux security tools are installed and ready.
"""

import subprocess
import shutil
from rich.table import Table
from rich.console import Console
from typing import Dict, Tuple

console = Console()

REQUIRED_TOOLS = {
    "nmap": {
        "desc": "Network port scanner & vuln detection",
        "install": "sudo apt install nmap",
        "critical": True
    },
    "nikto": {
        "desc": "Web server vulnerability scanner",
        "install": "sudo apt install nikto",
        "critical": True
    },
    "sqlmap": {
        "desc": "Automatic SQL injection tool",
        "install": "sudo apt install sqlmap",
        "critical": True
    },
    "gobuster": {
        "desc": "Directory/file brute-forcer",
        "install": "sudo apt install gobuster",
        "critical": False
    },
    "dirb": {
        "desc": "Web content scanner",
        "install": "sudo apt install dirb",
        "critical": False
    },
    "ffuf": {
        "desc": "Fast web fuzzer",
        "install": "sudo apt install ffuf",
        "critical": False
    },
    "wpscan": {
        "desc": "WordPress vulnerability scanner",
        "install": "sudo apt install wpscan",
        "critical": False
    },
    "sslscan": {
        "desc": "SSL/TLS configuration scanner",
        "install": "sudo apt install sslscan",
        "critical": False
    },
    "whatweb": {
        "desc": "Web technology fingerprinter",
        "install": "sudo apt install whatweb",
        "critical": False
    },
    "wafw00f": {
        "desc": "Web Application Firewall detector",
        "install": "pip3 install wafw00f",
        "critical": False
    },
    "sublist3r": {
        "desc": "Subdomain enumeration tool",
        "install": "pip3 install sublist3r",
        "critical": False
    },
    "whois": {
        "desc": "Domain registration info lookup",
        "install": "sudo apt install whois",
        "critical": True
    },
    "dig": {
        "desc": "DNS lookup utility",
        "install": "sudo apt install dnsutils",
        "critical": True
    },
    "curl": {
        "desc": "HTTP request tool",
        "install": "sudo apt install curl",
        "critical": True
    },
    "nuclei": {
        "desc": "Template-based vulnerability scanner",
        "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "critical": False
    },
    "hydra": {
        "desc": "Password brute-force tool",
        "install": "sudo apt install hydra",
        "critical": False
    },
    "amass": {
        "desc": "Attack surface mapping",
        "install": "sudo apt install amass",
        "critical": False
    },
    "wfuzz": {
        "desc": "Web application fuzzer",
        "install": "pip3 install wfuzz",
        "critical": False
    },
    "openssl": {
        "desc": "SSL certificate analysis",
        "install": "sudo apt install openssl",
        "critical": True
    },
    "theHarvester": {
        "desc": "Email/subdomain harvesting",
        "install": "sudo apt install theharvester",
        "critical": False
    },
    "dnsenum": {
        "desc": "DNS enumeration tool",
        "install": "sudo apt install dnsenum",
        "critical": False
    },
    "fierce": {
        "desc": "DNS reconnaissance tool",
        "install": "pip3 install fierce",
        "critical": False
    },
    "dalfox": {
        "desc": "XSS vulnerability scanner",
        "install": "go install github.com/hahwul/dalfox/v2@latest",
        "critical": False
    },
    "httprobe": {
        "desc": "HTTP/HTTPS probe tool",
        "install": "go install github.com/tomnomnom/httprobe@latest",
        "critical": False
    },
    "gau": {
        "desc": "Get All URLs tool",
        "install": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "critical": False
    },
    "waybackurls": {
        "desc": "Fetch Wayback Machine URLs",
        "install": "go install github.com/tomnomnom/waybackurls@latest",
        "critical": False
    },
    "subfinder": {
        "desc": "Subdomain discovery tool",
        "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "critical": False
    },
    "httpx": {
        "desc": "HTTP toolkit",
        "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "critical": False
    },
}


def check_tool(tool_name: str) -> bool:
    """Check if a tool is available in PATH."""
    return shutil.which(tool_name) is not None


def check_all_tools() -> Dict[str, bool]:
    """Check availability of all tools."""
    results = {}
    for tool in REQUIRED_TOOLS:
        results[tool] = check_tool(tool)
    return results


def display_tool_status():
    """Display tool availability in a rich table."""
    results = check_all_tools()

    table = Table(title="[bold red]Cyberburg — Tool Availability Status[/bold red]",
                  box=None, show_header=True, header_style="bold cyan")
    table.add_column("Tool", style="bold white", width=18)
    table.add_column("Status", width=12)
    table.add_column("Critical", width=10)
    table.add_column("Description", style="dim")
    table.add_column("Install Command", style="dim cyan")

    available = 0
    for tool, info in REQUIRED_TOOLS.items():
        installed = results[tool]
        if installed:
            status = "[bold green]✔ READY[/bold green]"
            available += 1
        else:
            status = "[bold red]✘ MISSING[/bold red]"

        critical = "[red]YES[/red]" if info["critical"] else "[dim]no[/dim]"
        table.add_row(tool, status, critical, info["desc"], info["install"] if not installed else "")

    console.print(table)
    console.print(f"\n[bold]Tools Available: [green]{available}[/green] / {len(REQUIRED_TOOLS)}[/bold]")

    missing_critical = [t for t, info in REQUIRED_TOOLS.items()
                        if info["critical"] and not results[t]]
    if missing_critical:
        console.print(f"[bold red]⚠ Missing critical tools: {', '.join(missing_critical)}[/bold red]")

    return results


def get_available_tools() -> list:
    """Return list of available tool names."""
    return [t for t in REQUIRED_TOOLS if check_tool(t)]


def get_missing_tools() -> list:
    """Return list of missing tool names."""
    return [t for t in REQUIRED_TOOLS if not check_tool(t)]
