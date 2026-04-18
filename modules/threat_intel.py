#!/usr/bin/env python3
"""
Threat Intelligence — Cyberburg v5 PHANTOM PROTOCOL
IP reputation (AbuseIPDB), certificate transparency (crt.sh),
passive DNS (HackerTarget), blacklist checks, Shodan lookup.

AUTHORIZED PENETRATION TESTING ONLY.
"""

import os
import re
import json
import socket

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.helpers import run_command, get_timestamp, sanitize_filename
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import box

console = Console()

# ─── IP Reputation (AbuseIPDB) ────────────────────────────────────────────────

def check_abuseipdb(ip: str, api_key: str = None, output_dir: str = "") -> dict:
    """Check IP reputation against AbuseIPDB."""
    result = {
        "module": "Threat Intel — AbuseIPDB",
        "target": ip,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests not available"
        return result

    if not api_key:
        # Try free lookup via plain web scrape (no key needed for basic info)
        print_info(f"Checking IP reputation for {ip} (no API key — limited data)...")
        try:
            r = requests.get(
                f"https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": "demo", "Accept": "application/json"},
                timeout=10
            )
            # Without valid key this will 401, that's ok — try fallback
        except Exception:
            pass

        # Fallback: ipinfo.io (free, no key)
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if r.status_code == 200:
                data = r.json()
                result["raw"] = json.dumps(data, indent=2)
                org = data.get("org", "Unknown")
                country = data.get("country", "Unknown")
                hostname = data.get("hostname", "")
                bogon = data.get("bogon", False)

                result["findings"].append({
                    "type": "IP Info",
                    "severity": "INFO",
                    "ip": ip,
                    "detail": f"Org: {org} | Country: {country} | Hostname: {hostname}"
                })

                if bogon:
                    result["findings"].append({
                        "type": "Bogon IP",
                        "severity": "MEDIUM",
                        "ip": ip,
                        "detail": "IP is in a reserved/bogon range"
                    })
        except Exception as e:
            result["raw"] = str(e)
        return result

    # Full AbuseIPDB check with API key
    print_info(f"Checking AbuseIPDB reputation for {ip}...")
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=15
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            result["raw"] = json.dumps(data, indent=2)
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            country = data.get("countryCode", "?")
            isp = data.get("isp", "Unknown")
            usage = data.get("usageType", "Unknown")

            sev = "CRITICAL" if score >= 75 else ("HIGH" if score >= 40 else ("MEDIUM" if score >= 10 else "LOW"))
            result["findings"].append({
                "type": "IP Reputation",
                "severity": sev,
                "ip": ip,
                "detail": f"Abuse score: {score}/100 | Reports: {reports} | ISP: {isp} | Country: {country} | Usage: {usage}"
            })

            if score >= 40:
                print_success(f"Malicious IP: score {score}/100, {reports} reports")
        else:
            result["raw"] = f"AbuseIPDB returned {r.status_code}"
    except Exception as e:
        result["raw"] = str(e)

    return result


# ─── Certificate Transparency (crt.sh) ───────────────────────────────────────

def crt_sh_lookup(domain: str, output_dir: str) -> dict:
    """Query crt.sh for certificate transparency records."""
    result = {
        "module": "Threat Intel — Certificate Transparency",
        "target": domain,
        "timestamp": get_timestamp(),
        "raw": "",
        "subdomains": [],
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests not available"
        return result

    print_info(f"Querying crt.sh for {domain}...")
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20, headers={"User-Agent": "Cyberburg/5.0"}
        )
        if r.status_code == 200:
            certs = r.json()
            result["raw"] = f"Found {len(certs)} certificate records"

            subdomains = set()
            for cert in certs:
                names = cert.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lstrip("*.")
                    if domain in name and name not in subdomains:
                        subdomains.add(name)

            result["subdomains"] = sorted(subdomains)
            for sub in result["subdomains"]:
                result["findings"].append({
                    "type": "Subdomain (crt.sh)",
                    "severity": "INFO",
                    "domain": sub,
                    "detail": f"Found in certificate transparency logs"
                })

            print_success(f"Found {len(subdomains)} unique subdomains via crt.sh")

            # Save to loot
            loot_dir = os.path.join(output_dir, "loot")
            os.makedirs(loot_dir, exist_ok=True)
            with open(os.path.join(loot_dir, "crtsh_subdomains.txt"), "w") as f:
                f.write("\n".join(result["subdomains"]))
        else:
            result["raw"] = f"crt.sh returned HTTP {r.status_code}"
    except Exception as e:
        result["raw"] = str(e)
        print_warning(f"crt.sh lookup failed: {e}")

    return result


# ─── Passive DNS (HackerTarget) ───────────────────────────────────────────────

def passive_dns(domain: str, output_dir: str) -> dict:
    """Query HackerTarget passive DNS for historical records."""
    result = {
        "module": "Threat Intel — Passive DNS",
        "target": domain,
        "timestamp": get_timestamp(),
        "raw": "",
        "records": [],
        "findings": []
    }

    if not HAS_REQUESTS:
        result["raw"] = "requests not available"
        return result

    print_info(f"Querying passive DNS for {domain}...")
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15, headers={"User-Agent": "Cyberburg/5.0"}
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:50]:
            lines = [l.strip() for l in r.text.strip().splitlines() if l.strip()]
            result["raw"] = r.text[:2000]
            for line in lines:
                parts = line.split(",")
                if len(parts) == 2:
                    hostname, ip = parts[0].strip(), parts[1].strip()
                    result["records"].append({"hostname": hostname, "ip": ip})
                    result["findings"].append({
                        "type": "Passive DNS Record",
                        "severity": "INFO",
                        "domain": hostname,
                        "detail": f"Resolves to: {ip}"
                    })

            print_success(f"Passive DNS: {len(result['records'])} records found")
        else:
            result["raw"] = f"HackerTarget: {r.text[:200]}"
    except Exception as e:
        result["raw"] = str(e)

    return result


# ─── Shodan Lookup ────────────────────────────────────────────────────────────

def shodan_lookup(ip: str, api_key: str = None, output_dir: str = "") -> dict:
    """Lookup IP in Shodan (requires API key)."""
    result = {
        "module": "Threat Intel — Shodan",
        "target": ip,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not api_key:
        # Free lookup via Shodan InternetDB (no key needed)
        print_info(f"Querying Shodan InternetDB for {ip} (no key)...")
        try:
            r = requests.get(
                f"https://internetdb.shodan.io/{ip}",
                timeout=10, headers={"User-Agent": "Cyberburg/5.0"}
            )
            if r.status_code == 200:
                data = r.json()
                result["raw"] = json.dumps(data, indent=2)
                ports = data.get("ports", [])
                vulns = data.get("vulns", [])
                tags  = data.get("tags", [])
                hostnames = data.get("hostnames", [])

                if ports:
                    result["findings"].append({
                        "type": "Shodan — Open Ports",
                        "severity": "INFO",
                        "ip": ip,
                        "detail": f"Ports: {ports}"
                    })

                for vuln in vulns:
                    result["findings"].append({
                        "type": "Shodan — CVE",
                        "severity": "HIGH",
                        "ip": ip,
                        "detail": f"Known vulnerability: {vuln}"
                    })
                    print_success(f"Shodan CVE: {vuln} on {ip}")

                if hostnames:
                    result["findings"].append({
                        "type": "Shodan — Hostnames",
                        "severity": "INFO",
                        "ip": ip,
                        "detail": f"Hostnames: {', '.join(hostnames)}"
                    })
            elif r.status_code == 404:
                result["raw"] = f"No Shodan data for {ip}"
        except Exception as e:
            result["raw"] = str(e)
        return result

    # Full Shodan API with key
    print_info(f"Querying Shodan API for {ip}...")
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=15
        )
        if r.status_code == 200:
            data = r.json()
            result["raw"] = json.dumps(data, indent=2)
            ports = data.get("ports", [])
            vulns = data.get("vulns", {})
            os_info = data.get("os", "Unknown")
            org = data.get("org", "Unknown")

            result["findings"].append({
                "type": "Shodan Host Info",
                "severity": "INFO",
                "ip": ip,
                "detail": f"OS: {os_info} | Org: {org} | Ports: {ports}"
            })

            for cve, cve_data in vulns.items():
                cvss = cve_data.get("cvss", 0) if isinstance(cve_data, dict) else 0
                sev = "CRITICAL" if cvss >= 9 else ("HIGH" if cvss >= 7 else "MEDIUM")
                result["findings"].append({
                    "type": "Shodan CVE",
                    "severity": sev,
                    "ip": ip,
                    "detail": f"{cve} — CVSS: {cvss}"
                })
                print_success(f"CVE: {cve} (CVSS {cvss})")

            # Save full Shodan data
            loot_dir = os.path.join(output_dir, "loot")
            os.makedirs(loot_dir, exist_ok=True)
            with open(os.path.join(loot_dir, f"shodan_{sanitize_filename(ip)}.json"), "w") as f:
                json.dump(data, f, indent=2)
        else:
            result["raw"] = f"Shodan returned {r.status_code}: {r.text[:200]}"
    except Exception as e:
        result["raw"] = str(e)

    return result


# ─── DNS Blacklist Check ──────────────────────────────────────────────────────

DNSBL_LISTS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net",
    "spam.dnsbl.sorbs.net",
    "dul.dnsbl.sorbs.net",
]


def dnsbl_check(ip: str) -> dict:
    """Check IP against DNS blacklists."""
    result = {
        "module": "Threat Intel — DNSBL Check",
        "target": ip,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    print_info(f"Checking {ip} against {len(DNSBL_LISTS)} DNS blacklists...")

    # Reverse IP for DNSBL lookup
    try:
        parts = ip.split(".")
        reversed_ip = ".".join(reversed(parts))
    except Exception:
        result["raw"] = "Invalid IP for DNSBL"
        return result

    listed_on = []
    for bl in DNSBL_LISTS:
        lookup = f"{reversed_ip}.{bl}"
        try:
            socket.gethostbyname(lookup)
            listed_on.append(bl)
            result["findings"].append({
                "type": "DNSBL Listed",
                "severity": "HIGH",
                "ip": ip,
                "detail": f"Listed on blacklist: {bl}"
            })
            print_success(f"Blacklisted on: {bl}")
        except socket.gaierror:
            pass

    result["raw"] = f"DNSBL check complete. Listed on {len(listed_on)}/{len(DNSBL_LISTS)} lists."
    return result


# ─── VirusTotal (optional) ────────────────────────────────────────────────────

def virustotal_lookup(target: str, api_key: str, output_dir: str) -> dict:
    """VirusTotal domain/IP lookup (requires free API key)."""
    result = {
        "module": "Threat Intel — VirusTotal",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not api_key or not HAS_REQUESTS:
        result["raw"] = "VirusTotal API key not configured"
        return result

    print_info(f"Querying VirusTotal for {target}...")

    # Determine endpoint type
    try:
        socket.inet_aton(target)
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    except socket.error:
        endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"

    try:
        r = requests.get(
            endpoint,
            headers={"x-apikey": api_key},
            timeout=15
        )
        if r.status_code == 200:
            data = r.json()
            result["raw"] = json.dumps(data, indent=2)[:3000]
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            sev = "CRITICAL" if malicious >= 5 else ("HIGH" if malicious >= 2 else ("MEDIUM" if malicious >= 1 else "LOW"))
            result["findings"].append({
                "type": "VirusTotal Reputation",
                "severity": sev,
                "target": target,
                "detail": f"Malicious: {malicious}/{total} | Suspicious: {suspicious}/{total}"
            })
            if malicious > 0:
                print_success(f"VirusTotal: {malicious} vendors flagged {target} as malicious")

            loot_dir = os.path.join(output_dir, "loot")
            os.makedirs(loot_dir, exist_ok=True)
            with open(os.path.join(loot_dir, f"virustotal_{sanitize_filename(target)}.json"), "w") as f:
                json.dump(data, f, indent=2)
        else:
            result["raw"] = f"VirusTotal returned {r.status_code}"
    except Exception as e:
        result["raw"] = str(e)

    return result


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def run_threat_intel(session, output_dir: str):
    """Full threat intelligence sweep."""
    from utils.banner import print_section
    print_section("THREAT INTELLIGENCE — PHANTOM PROTOCOL", "bold red")

    ip       = session.ip
    hostname = session.hostname

    # Load optional API keys
    abuseipdb_key  = os.environ.get("ABUSEIPDB_API_KEY", "")
    shodan_key     = os.environ.get("SHODAN_API_KEY", "")
    virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY", "")

    # IP Reputation
    r = check_abuseipdb(ip, abuseipdb_key, output_dir)
    session.add_result(r)

    # Certificate Transparency
    r = crt_sh_lookup(hostname, output_dir)
    session.add_result(r)

    # Passive DNS
    r = passive_dns(hostname, output_dir)
    session.add_result(r)

    # Shodan
    r = shodan_lookup(ip, shodan_key, output_dir)
    session.add_result(r)

    # DNSBL
    r = dnsbl_check(ip)
    session.add_result(r)

    # VirusTotal (only if key available)
    if virustotal_key:
        r = virustotal_lookup(hostname, virustotal_key, output_dir)
        session.add_result(r)

    # Summary
    all_findings = [f for m in session.modules[-6:] for f in m.get("findings", [])]
    high_crits = [f for f in all_findings if f.get("severity") in ("CRITICAL", "HIGH")]

    table = Table(title="Threat Intelligence Summary", box=box.SIMPLE, header_style="bold cyan")
    table.add_column("Type", style="cyan", width=35)
    table.add_column("Severity", width=10)
    table.add_column("Detail", style="dim")

    for f in all_findings[:30]:
        sev = f.get("severity", "INFO")
        sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "blue")
        table.add_row(
            f.get("type", "-"),
            f"[{sev_color}]{sev}[/{sev_color}]",
            f.get("detail", "")[:70]
        )

    console.print(table)
    console.print(f"\n  [bold green][+] Threat intel complete — {len(all_findings)} findings ({len(high_crits)} high/critical)[/bold green]")
    if not any([abuseipdb_key, shodan_key, virustotal_key]):
        console.print("  [dim]Tip: Set ABUSEIPDB_API_KEY, SHODAN_API_KEY, VIRUSTOTAL_API_KEY env vars for enhanced intelligence[/dim]")
