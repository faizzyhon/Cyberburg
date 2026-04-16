"""
Reconnaissance Module — Cyberburg
Handles: WHOIS, DNS, subdomain enumeration, IP geolocation, theHarvester, amass
"""

import json
import re
import urllib.request
from utils.helpers import run_command, run_command_stream, get_timestamp
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console
from rich.table import Table

console = Console()


def whois_lookup(target: str) -> dict:
    """Perform WHOIS lookup on target."""
    result = {
        "module": "WHOIS Lookup",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("whois"):
        print_warning("whois not found — skipping")
        return result

    print_info(f"Running WHOIS on {target}...")
    code, stdout, stderr = run_command(["whois", target], timeout=30)

    if stdout:
        result["raw"] = stdout
        # Extract key fields
        fields = {
            "Registrar": r'[Rr]egistrar:\s*(.+)',
            "Creation Date": r'[Cc]reation [Dd]ate:\s*(.+)',
            "Expiry Date": r'[Rr]egistry [Ee]xpiry [Dd]ate:\s*(.+)',
            "Updated Date": r'[Uu]pdated [Dd]ate:\s*(.+)',
            "Name Servers": r'[Nn]ame [Ss]erver:\s*(.+)',
            "Registrant": r'[Rr]egistrant [Oo]rg.*?:\s*(.+)',
            "Registrant Email": r'[Rr]egistrant [Ee]mail:\s*(.+)',
            "Country": r'[Rr]egistrant [Cc]ountry:\s*(.+)',
        }
        for label, pattern in fields.items():
            matches = re.findall(pattern, stdout)
            if matches:
                result["findings"].append({
                    "type": label,
                    "value": matches[0].strip(),
                    "severity": "INFO"
                })

        print_success("WHOIS completed")
    else:
        print_warning(f"WHOIS returned no data: {stderr}")

    return result


def dns_lookup(target: str) -> dict:
    """Perform comprehensive DNS enumeration."""
    result = {
        "module": "DNS Enumeration",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": [],
        "records": {}
    }

    if not check_tool("dig"):
        print_warning("dig not found — skipping DNS enumeration")
        return result

    print_info(f"Running DNS enumeration on {target}...")

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]
    raw_output = []

    for rtype in record_types:
        code, stdout, stderr = run_command(
            ["dig", "+short", rtype, target], timeout=15
        )
        if stdout.strip():
            result["records"][rtype] = [r.strip() for r in stdout.strip().split('\n')]
            raw_output.append(f"=== {rtype} Records ===\n{stdout}")
            result["findings"].append({
                "type": f"DNS {rtype} Record",
                "value": stdout.strip(),
                "severity": "INFO"
            })

    # Zone transfer attempt
    if "NS" in result["records"]:
        for ns in result["records"]["NS"][:3]:
            ns = ns.rstrip('.')
            print_info(f"Attempting zone transfer via {ns}...")
            code, stdout, stderr = run_command(
                ["dig", "axfr", target, f"@{ns}"], timeout=20
            )
            if stdout and "Transfer failed" not in stdout and "REFUSED" not in stdout:
                result["findings"].append({
                    "type": "DNS Zone Transfer",
                    "value": f"Zone transfer SUCCESSFUL via {ns}! This is a critical misconfiguration.",
                    "severity": "CRITICAL"
                })
                raw_output.append(f"=== ZONE TRANSFER via {ns} ===\n{stdout}")
                print_warning("CRITICAL: Zone transfer is ALLOWED!")
            else:
                raw_output.append(f"=== Zone Transfer {ns} — REFUSED (good) ===")

    result["raw"] = "\n".join(raw_output)

    # Security checks on DNS
    if "TXT" in result["records"]:
        txt_records = " ".join(result["records"]["TXT"])
        if "v=spf1" not in txt_records:
            result["findings"].append({
                "type": "Missing SPF Record",
                "value": "No SPF TXT record found — email spoofing possible",
                "severity": "MEDIUM"
            })
        if "_dmarc" not in txt_records.lower():
            result["findings"].append({
                "type": "Missing DMARC Record",
                "value": "No DMARC TXT record found — email spoofing protection missing",
                "severity": "MEDIUM"
            })

    print_success(f"DNS enumeration complete — {len(result['findings'])} records found")
    return result


def subdomain_enumeration(target: str, method: str = "auto") -> dict:
    """Enumerate subdomains using available tools."""
    result = {
        "module": "Subdomain Enumeration",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "subdomains": [],
        "findings": []
    }

    print_info(f"Starting subdomain enumeration for {target}...")

    # Strip www/http
    domain = re.sub(r'^(https?://)?(www\.)?', '', target).rstrip('/')

    all_subdomains = set()

    # Method 1: subfinder
    if check_tool("subfinder"):
        print_info("Running subfinder...")
        code, stdout, stderr = run_command(
            ["subfinder", "-d", domain, "-silent"], timeout=120
        )
        if stdout:
            subs = [s.strip() for s in stdout.strip().split('\n') if s.strip()]
            all_subdomains.update(subs)
            result["raw"] += f"=== subfinder ===\n{stdout}\n"
            print_success(f"subfinder found {len(subs)} subdomains")

    # Method 2: amass
    if check_tool("amass"):
        print_info("Running amass (passive mode)...")
        code, stdout, stderr = run_command(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "2"], timeout=180
        )
        if stdout:
            subs = [s.strip() for s in stdout.strip().split('\n') if s.strip()]
            all_subdomains.update(subs)
            result["raw"] += f"=== amass ===\n{stdout}\n"
            print_success(f"amass found {len(subs)} subdomains")

    # Method 3: sublist3r
    if check_tool("sublist3r"):
        print_info("Running sublist3r...")
        code, stdout, stderr = run_command(
            ["sublist3r", "-d", domain, "-o", "/tmp/cyberburg_subs.txt", "-n"],
            timeout=120
        )
        try:
            with open("/tmp/cyberburg_subs.txt") as f:
                subs = [s.strip() for s in f.readlines() if s.strip()]
                all_subdomains.update(subs)
                print_success(f"sublist3r found {len(subs)} subdomains")
        except FileNotFoundError:
            pass

    # Method 4: theHarvester
    if check_tool("theHarvester"):
        print_info("Running theHarvester...")
        code, stdout, stderr = run_command(
            ["theHarvester", "-d", domain, "-b", "all", "-l", "500"],
            timeout=120
        )
        if stdout:
            # Parse subdomains
            sub_section = re.search(r'\[Subdomains\](.*?)(?=\[|$)', stdout, re.DOTALL)
            if sub_section:
                subs = [s.strip() for s in sub_section.group(1).strip().split('\n') if s.strip()]
                all_subdomains.update(subs)
            result["raw"] += f"=== theHarvester ===\n{stdout}\n"
            print_success("theHarvester completed")

    # Method 5: DNS brute force with dig
    if check_tool("dig"):
        print_info("Running DNS brute force on common subdomains...")
        common_subs = [
            "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
            "vpn", "admin", "portal", "api", "dev", "staging", "test", "beta",
            "m", "mobile", "shop", "store", "blog", "news", "cdn", "static",
            "media", "images", "img", "assets", "login", "secure", "payment",
            "pay", "checkout", "dashboard", "panel", "cpanel", "whm", "webdisk",
            "ns1", "ns2", "mx", "autodiscover", "autoconfig", "intranet"
        ]
        found_dns = []
        for sub in common_subs:
            code, stdout, _ = run_command(
                ["dig", "+short", f"{sub}.{domain}"], timeout=5
            )
            if stdout.strip():
                found_dns.append(f"{sub}.{domain}")
                all_subdomains.add(f"{sub}.{domain}")

        if found_dns:
            result["raw"] += f"=== DNS Brute Force ===\n" + "\n".join(found_dns) + "\n"
            print_success(f"DNS brute found {len(found_dns)} subdomains")

    result["subdomains"] = sorted(list(all_subdomains))

    for sub in result["subdomains"]:
        result["findings"].append({
            "type": "Subdomain Discovered",
            "value": sub,
            "severity": "INFO"
        })

    print_success(f"Total subdomains found: {len(result['subdomains'])}")
    return result


def ip_geolocation(ip: str) -> dict:
    """Get geolocation info for an IP address."""
    result = {
        "module": "IP Geolocation",
        "target": ip,
        "timestamp": get_timestamp(),
        "geo": {},
        "findings": []
    }

    print_info(f"Getting geolocation for {ip}...")

    try:
        url = f"http://ip-api.com/json/{ip}"
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        if data.get("status") == "success":
            geo = {
                "IP": data.get("query", ip),
                "Country": data.get("country", "Unknown"),
                "Region": data.get("regionName", "Unknown"),
                "City": data.get("city", "Unknown"),
                "ZIP": data.get("zip", "Unknown"),
                "ISP": data.get("isp", "Unknown"),
                "Organization": data.get("org", "Unknown"),
                "ASN": data.get("as", "Unknown"),
                "Timezone": data.get("timezone", "Unknown"),
            }
            result["geo"] = geo

            for k, v in geo.items():
                result["findings"].append({
                    "type": f"IP Info: {k}",
                    "value": v,
                    "severity": "INFO"
                })

            print_success(f"Geolocation: {geo.get('City')}, {geo.get('Country')} — {geo.get('ISP')}")
    except Exception as e:
        print_warning(f"Geolocation lookup failed: {e}")

    return result


def harvest_emails(target: str) -> dict:
    """Harvest emails and other intel using theHarvester."""
    result = {
        "module": "Email & Intel Harvesting",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "emails": [],
        "findings": []
    }

    if not check_tool("theHarvester"):
        print_warning("theHarvester not found — skipping email harvesting")
        return result

    domain = re.sub(r'^(https?://)?(www\.)?', '', target).rstrip('/')
    print_info(f"Harvesting emails/intel for {domain}...")

    sources = ["google", "bing", "yahoo", "duckduckgo", "hackertarget", "urlscan", "crtsh"]
    code, stdout, stderr = run_command(
        ["theHarvester", "-d", domain, "-b", ",".join(sources), "-l", "500"],
        timeout=180
    )

    if stdout:
        result["raw"] = stdout
        # Extract emails
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        emails = list(set(email_pattern.findall(stdout)))
        result["emails"] = emails

        for email in emails:
            result["findings"].append({
                "type": "Email Address Found",
                "value": email,
                "severity": "LOW"
            })

        print_success(f"Found {len(emails)} email addresses")
    else:
        print_warning("theHarvester returned no results")

    return result
