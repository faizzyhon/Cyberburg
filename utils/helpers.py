"""
Helper utilities for Cyberburg
"""

import re
import subprocess
import socket
import urllib.parse
import ipaddress
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import urlparse


def normalize_target(target: str) -> Tuple[str, str, str]:
    """
    Normalize a target URL/domain/IP.
    Returns: (url_with_scheme, hostname, ip_or_hostname)
    """
    target = target.strip().rstrip('/')

    # Add scheme if missing
    if not target.startswith(('http://', 'https://')):
        url = f"https://{target}"
    else:
        url = target

    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    hostname = hostname.split(':')[0]  # Remove port if present

    # Try to resolve IP
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        ip = hostname

    return url, hostname, ip


def is_valid_target(target: str) -> bool:
    """Validate if target is a valid domain, IP, or URL."""
    target = target.strip()

    # Check for obvious invalid inputs
    if not target or len(target) < 4:
        return False

    # Strip scheme
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path

    # Check if IP
    try:
        ipaddress.ip_address(target.split(':')[0])
        return True
    except ValueError:
        pass

    # Check if valid domain
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(target.split(':')[0]))


def run_command(cmd: list, timeout: int = 300, capture_output: bool = True) -> Tuple[int, str, str]:
    """
    Run a shell command and return (returncode, stdout, stderr).
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Tool not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def run_command_stream(cmd: list, timeout: int = 300):
    """
    Run a shell command and yield output lines in real-time.
    """
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for line in iter(process.stdout.readline, ''):
            yield line.rstrip()
        process.wait()
    except FileNotFoundError:
        yield f"Error: Tool not found: {cmd[0]}"
    except Exception as e:
        yield f"Error: {str(e)}"


def get_timestamp() -> str:
    """Get current timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_filename_timestamp() -> str:
    """Get timestamp suitable for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def severity_score(findings: list) -> dict:
    """Calculate vulnerability severity counts."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def risk_rating(counts: dict) -> Tuple[str, str]:
    """
    Calculate overall risk rating based on finding counts.
    Returns: (rating, color)
    """
    if counts.get("CRITICAL", 0) > 0:
        return "CRITICAL", "#FF0000"
    elif counts.get("HIGH", 0) >= 2:
        return "CRITICAL", "#FF0000"
    elif counts.get("HIGH", 0) == 1:
        return "HIGH", "#FF4500"
    elif counts.get("MEDIUM", 0) >= 3:
        return "HIGH", "#FF4500"
    elif counts.get("MEDIUM", 0) > 0:
        return "MEDIUM", "#FFA500"
    elif counts.get("LOW", 0) > 0:
        return "LOW", "#FFD700"
    else:
        return "INFO", "#00BFFF"


def parse_nmap_ports(output: str) -> list:
    """Parse nmap output to extract open ports."""
    ports = []
    pattern = re.compile(
        r'(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)(?:\s+(.+))?'
    )
    for match in pattern.finditer(output):
        ports.append({
            "port": int(match.group(1)),
            "protocol": match.group(2),
            "state": match.group(3),
            "service": match.group(4),
            "version": match.group(5) or ""
        })
    return ports


def extract_emails(text: str) -> list:
    """Extract email addresses from text."""
    pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    return list(set(pattern.findall(text)))


def extract_urls(text: str) -> list:
    """Extract URLs from text."""
    pattern = re.compile(r'https?://[^\s<>"\']+')
    return list(set(pattern.findall(text)))


def sanitize_filename(name: str) -> str:
    """Make a string safe for use as a filename."""
    return re.sub(r'[^\w\-_.]', '_', name)


def format_size(bytes_size: int) -> str:
    """Format bytes to human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.1f} TB"
