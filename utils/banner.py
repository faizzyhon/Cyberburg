"""
Cyberburg Banner and Branding Module
Developer: Faiz Zyhon
GitHub: github.com/faizzyhon
Instagram: instagram.com/faizzyhon
Website: faizzyhon.online
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

BANNER = r"""
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗██████╗  ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║██████╔╝██║  ███╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██║   ██║██╔══██╗██║   ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝╚██████╔╝██║  ██║╚██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝
"""

VERSION = "2.0.0"
CODENAME = "PHANTOM BLADE"

DEVELOPER_INFO = {
    "name": "Faiz Zyhon",
    "github": "github.com/faizzyhon",
    "instagram": "instagram.com/faizzyhon",
    "website": "faizzyhon.online",
    "tool": "Cyberburg",
    "version": VERSION,
    "codename": CODENAME
}


def print_banner():
    """Print the Cyberburg ASCII banner with developer info."""
    console.print(f"[bold red]{BANNER}[/bold red]")

    info_text = Text()
    info_text.append("  ╔══════════════════════════════════════════════════════════════════════════╗\n", style="bold red")
    info_text.append("  ║", style="bold red")
    info_text.append(f"   Cyberburg v{VERSION} [{CODENAME}]  —  Advanced Web Penetration Testing Suite   ", style="bold white")
    info_text.append("║\n", style="bold red")
    info_text.append("  ║", style="bold red")
    info_text.append("   Developer : Faiz Zyhon                                                  ", style="cyan")
    info_text.append("║\n", style="bold red")
    info_text.append("  ║", style="bold red")
    info_text.append("   GitHub    : github.com/faizzyhon                                        ", style="green")
    info_text.append("║\n", style="bold red")
    info_text.append("  ║", style="bold red")
    info_text.append("   Instagram : instagram.com/faizzyhon                                     ", style="magenta")
    info_text.append("║\n", style="bold red")
    info_text.append("  ║", style="bold red")
    info_text.append("   Website   : faizzyhon.online                                            ", style="yellow")
    info_text.append("║\n", style="bold red")
    info_text.append("  ║", style="bold red")
    info_text.append("   For authorized penetration testing and security research only            ", style="bold red")
    info_text.append("║\n", style="bold red")
    info_text.append("  ╚══════════════════════════════════════════════════════════════════════════╝", style="bold red")

    console.print(info_text)
    console.print()


def print_section(title: str, color: str = "bold cyan"):
    """Print a section divider."""
    console.print(f"\n[{color}]{'═' * 70}[/{color}]")
    console.print(f"[{color}]  ◆  {title}[/{color}]")
    console.print(f"[{color}]{'═' * 70}[/{color}]\n")


def print_info(msg: str):
    console.print(f"[bold blue][*][/bold blue] {msg}")


def print_success(msg: str):
    console.print(f"[bold green][+][/bold green] {msg}")


def print_warning(msg: str):
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def print_error(msg: str):
    console.print(f"[bold red][-][/bold red] {msg}")


def print_finding(severity: str, msg: str):
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "blue"
    }
    color = colors.get(severity.upper(), "white")
    console.print(f"  [{color}][{severity.upper()}][/{color}] {msg}")
