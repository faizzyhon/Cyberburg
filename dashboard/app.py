#!/usr/bin/env python3
"""
Cyberburg Dashboard — Localhost Web Interface
Real-time scan management, live findings, critical alerts, and bug bounty reports.
Access at: http://localhost:5000

⚖️ ETHICAL USE ONLY — authorized targets only.
"""

import os
import sys
import json
import time
import uuid
import sqlite3
import threading
from datetime import datetime, timezone

# Add parent project root to path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

try:
    from flask import Flask, render_template, request, jsonify, Response, send_from_directory
except ImportError:
    print("ERROR: Flask not installed. Run: pip install flask")
    sys.exit(1)

app = Flask(__name__)

DB_PATH        = os.path.join(os.path.dirname(__file__), "cyberburg_dashboard.db")
REPORTS_DIR    = os.path.join(ROOT, "reports")
BB_REPORTS_DIR = os.path.join(ROOT, "bug_bounty_reports")

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(BB_REPORTS_DIR, exist_ok=True)

# Per-scan SSE event queues: scan_id -> list of event dicts
_sse_queues: dict = {}
_sse_lock = threading.Lock()

# Running subprocess handles
_processes: dict = {}


# ─── Database ─────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id              TEXT PRIMARY KEY,
                target          TEXT NOT NULL,
                scan_mode       TEXT NOT NULL DEFAULT 'quick',
                login_url       TEXT DEFAULT '',
                username        TEXT DEFAULT '',
                has_password    INTEGER DEFAULT 0,
                status          TEXT DEFAULT 'running',
                started_at      TEXT,
                completed_at    TEXT,
                risk_rating     TEXT DEFAULT '',
                report_html     TEXT DEFAULT '',
                report_json     TEXT DEFAULT '',
                bug_bounty_path TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS findings (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id      TEXT NOT NULL,
                module       TEXT DEFAULT '',
                title        TEXT,
                severity     TEXT DEFAULT 'INFO',
                description  TEXT DEFAULT '',
                evidence     TEXT DEFAULT '',
                remediation  TEXT DEFAULT '',
                found_at     TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
        """)


# ─── SSE Event Helpers ────────────────────────────────────────────────────────

def _push(scan_id: str, etype: str, data: dict):
    """Append an event to the scan's SSE queue."""
    with _sse_lock:
        if scan_id not in _sse_queues:
            _sse_queues[scan_id] = []
        _sse_queues[scan_id].append({"type": etype, "data": data, "ts": time.time()})
        _sse_queues[scan_id] = _sse_queues[scan_id][-1000:]  # keep last 1000


def _log(scan_id: str, msg: str, level: str = "info"):
    _push(scan_id, "log", {"msg": msg, "level": level, "ts": datetime.now().strftime("%H:%M:%S")})


def _store_finding(scan_id: str, module: str, title: str, severity: str,
                   description: str = "", evidence: str = "", remediation: str = ""):
    found_at = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO findings (scan_id,module,title,severity,description,evidence,remediation,found_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, module, title, severity, description, evidence, remediation, found_at),
        )
    _push(scan_id, "finding", {
        "module": module, "title": title, "severity": severity,
        "description": description, "evidence": evidence,
        "remediation": remediation, "found_at": found_at,
    })
    if severity in ("CRITICAL", "HIGH"):
        icon = "🔴" if severity == "CRITICAL" else "🟠"
        _push(scan_id, "alert", {
            "title": f"{icon} {severity}: {title}",
            "severity": severity,
            "module": module,
            "ts": datetime.now().strftime("%H:%M:%S"),
        })


# ─── REST API ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    with get_db() as conn:
        total   = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        active  = conn.execute("SELECT COUNT(*) FROM scans WHERE status='running'").fetchone()[0]
        crits   = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'").fetchone()[0]
        highs   = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='HIGH'").fetchone()[0]
    return jsonify({"total": total, "active": active, "critical": crits, "high": highs})


@app.route("/api/scans", methods=["GET"])
def api_list_scans():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id,target,scan_mode,status,started_at,completed_at,risk_rating,"
            "login_url,username,bug_bounty_path,report_html"
            " FROM scans ORDER BY started_at DESC LIMIT 100"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/scans", methods=["POST"])
def api_start_scan():
    body        = request.json or {}
    target      = (body.get("target") or "").strip()
    scan_mode   = (body.get("scan_mode") or "quick").strip()
    login_url   = (body.get("login_url") or "").strip()
    username    = (body.get("username") or "").strip()
    password    = (body.get("password") or "").strip()

    if not target:
        return jsonify({"error": "target is required"}), 400

    scan_id    = str(uuid.uuid4())[:8].upper()
    started_at = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        conn.execute(
            "INSERT INTO scans (id,target,scan_mode,login_url,username,has_password,status,started_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, target, scan_mode, login_url, username, 1 if password else 0, "running", started_at),
        )

    t = threading.Thread(
        target=_run_scan,
        args=(scan_id, target, scan_mode, login_url, username, password),
        daemon=True,
    )
    t.start()
    return jsonify({"scan_id": scan_id, "status": "started"})


@app.route("/api/scans/<sid>", methods=["GET"])
def api_get_scan(sid):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY id", (sid,)
        ).fetchall()
    result = dict(row)
    result["findings"] = [dict(f) for f in findings]
    return jsonify(result)


@app.route("/api/scans/<sid>/stop", methods=["POST"])
def api_stop_scan(sid):
    proc = _processes.pop(sid, None)
    if proc:
        try:
            proc.terminate()
        except Exception:
            pass
    with get_db() as conn:
        conn.execute(
            "UPDATE scans SET status='stopped',completed_at=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), sid),
        )
    _push(sid, "status", {"status": "stopped"})
    return jsonify({"status": "stopped"})


@app.route("/api/scans/<sid>/events")
def api_events(sid):
    """Server-Sent Events stream for a scan."""
    def generate():
        # Send all buffered events first
        with _sse_lock:
            existing = list(_sse_queues.get(sid, []))
        for ev in existing:
            yield f"data: {json.dumps(ev)}\n\n"
        cursor = len(existing)

        deadline = time.time() + 7200  # max 2 h
        while time.time() < deadline:
            with _sse_lock:
                queue = _sse_queues.get(sid, [])
            chunk = queue[cursor:]
            for ev in chunk:
                yield f"data: {json.dumps(ev)}\n\n"
            cursor += len(chunk)
            # End stream when scan finishes
            if chunk:
                terminal = {"complete", "error", "stopped"}
                if any(
                    e["type"] == "status" and e["data"].get("status") in terminal
                    for e in chunk
                ):
                    break
            time.sleep(0.4)

        yield "data: {\"type\": \"end\"}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/scans/<sid>/findings")
def api_findings(sid):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY id", (sid,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/reports/<path:filename>")
def download_report(filename):
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)


@app.route("/api/bug_bounty/<path:filename>")
def download_bb(filename):
    return send_from_directory(BB_REPORTS_DIR, filename, as_attachment=True)


# ─── Background Scan Runner ───────────────────────────────────────────────────

def _run_scan(scan_id, target, scan_mode, login_url, username, password):
    """
    Execute a Cyberburg scan in a background thread.
    Calls modules directly and streams findings via SSE.
    """
    _log(scan_id, f"Starting {scan_mode.upper()} scan on {target}", "info")
    _log(scan_id, "⚖️  Ethical Notice: Only scanning authorized targets", "warn")

    try:
        from utils.helpers import normalize_target, is_valid_target

        if not is_valid_target(target):
            _log(scan_id, f"Invalid target: {target}", "error")
            _finish_scan(scan_id, "error")
            return

        url, hostname, ip = normalize_target(target)
        _log(scan_id, f"Resolved — URL: {url} | IP: {ip}", "info")

        # ── Recon ─────────────────────────────────────────────────────────────
        if scan_mode in ("full", "quick", "stealth", "recon"):
            _log(scan_id, "Running Reconnaissance...", "section")
            _run_module_recon(scan_id, hostname, ip)

        # ── Port Scanning ─────────────────────────────────────────────────────
        if scan_mode in ("full", "quick", "stealth", "ports"):
            port_mode = "stealth" if scan_mode == "stealth" else (
                "full" if scan_mode == "full" else "quick"
            )
            _log(scan_id, f"Running Port Scanning ({port_mode})...", "section")
            _run_module_ports(scan_id, ip, port_mode)

        # ── SSL/TLS ───────────────────────────────────────────────────────────
        if scan_mode in ("full", "quick", "ssl"):
            _log(scan_id, "Running SSL/TLS Analysis...", "section")
            _run_module_ssl(scan_id, url)

        # ── Web Scanning ──────────────────────────────────────────────────────
        if scan_mode in ("full", "quick", "web"):
            _log(scan_id, "Running Web Application Scanning...", "section")
            _run_module_web(scan_id, url)

        # ── Vulnerability Scanning ────────────────────────────────────────────
        if scan_mode in ("full", "vuln", "web"):
            _log(scan_id, "Running Vulnerability Scanning...", "section")
            _run_module_vuln(scan_id, url)

        # ── Authentication Testing ────────────────────────────────────────────
        if login_url or username or password or scan_mode in ("full", "auth"):
            _log(scan_id, "Running Authentication Testing...", "section")
            _run_module_auth(scan_id, target, login_url, username, password)

        # ── Generate Standard Reports ─────────────────────────────────────────
        _log(scan_id, "Generating reports...", "info")
        _generate_standard_reports(scan_id, target, url, hostname, ip)

        # ── Bug Bounty Report (auto on critical findings) ─────────────────────
        _auto_bug_bounty(scan_id, target)

        _finish_scan(scan_id, "complete")

    except Exception as exc:
        import traceback
        _log(scan_id, f"Scan error: {exc}", "error")
        _log(scan_id, traceback.format_exc(), "error")
        _finish_scan(scan_id, "error")


def _emit_findings(scan_id: str, module_result: dict):
    """Push all findings from a module result dict."""
    if not module_result:
        return
    for f in module_result.get("findings", []):
        _store_finding(
            scan_id,
            module_result.get("module", "scanner"),
            f.get("title", ""),
            f.get("severity", "INFO"),
            f.get("description", ""),
            f.get("evidence", ""),
            f.get("remediation", ""),
        )


def _run_module_recon(scan_id, hostname, ip):
    try:
        from modules.recon import whois_lookup, dns_lookup, ip_geolocation, subdomain_enumeration
        _log(scan_id, "WHOIS lookup...", "info")
        _emit_findings(scan_id, whois_lookup(hostname))
        _log(scan_id, "DNS lookup...", "info")
        _emit_findings(scan_id, dns_lookup(hostname))
        _log(scan_id, "IP geolocation...", "info")
        _emit_findings(scan_id, ip_geolocation(ip))
        _log(scan_id, "Subdomain enumeration...", "info")
        _emit_findings(scan_id, subdomain_enumeration(hostname))
    except Exception as e:
        _log(scan_id, f"Recon error: {e}", "error")


def _run_module_ports(scan_id, ip, mode):
    try:
        from modules.port_scanner import quick_scan, full_scan, stealth_scan, firewall_detection
        fn = {"quick": quick_scan, "full": full_scan, "stealth": stealth_scan}.get(mode, quick_scan)
        _emit_findings(scan_id, fn(ip))
        _emit_findings(scan_id, firewall_detection(ip))
    except Exception as e:
        _log(scan_id, f"Port scan error: {e}", "error")


def _run_module_ssl(scan_id, url):
    try:
        from modules.ssl_analyzer import openssl_check, heartbleed_check, poodle_check
        _log(scan_id, "OpenSSL certificate check...", "info")
        _emit_findings(scan_id, openssl_check(url))
        _log(scan_id, "Heartbleed check...", "info")
        _emit_findings(scan_id, heartbleed_check(url))
        _log(scan_id, "POODLE check...", "info")
        _emit_findings(scan_id, poodle_check(url))
    except Exception as e:
        _log(scan_id, f"SSL error: {e}", "error")


def _run_module_web(scan_id, url):
    try:
        from modules.web_scanner import (
            whatweb_scan, waf_detection, header_analysis,
            http_methods_check, robots_sitemap_check, cms_scan
        )
        for fn_name, fn in [
            ("Technology fingerprint", whatweb_scan),
            ("WAF detection", waf_detection),
            ("Security headers", header_analysis),
            ("HTTP methods", http_methods_check),
            ("Robots/Sitemap", robots_sitemap_check),
            ("CMS detection", cms_scan),
        ]:
            _log(scan_id, f"{fn_name}...", "info")
            _emit_findings(scan_id, fn(url))
    except Exception as e:
        _log(scan_id, f"Web scan error: {e}", "error")


def _run_module_vuln(scan_id, url):
    try:
        from modules.dir_bruteforce import manual_path_check, api_fuzzing
        from modules.xss_scanner import dom_xss_check
        from modules.sql_injection import manual_sqli_test
        from modules.nuclei_scan import nuclei_exposed_panels, nuclei_cves

        for fn_name, fn in [
            ("Directory/file probe", manual_path_check),
            ("API endpoint discovery", api_fuzzing),
            ("Manual SQLi test", manual_sqli_test),
            ("DOM XSS analysis", dom_xss_check),
            ("Nuclei exposed panels", nuclei_exposed_panels),
            ("Nuclei CVE scan", nuclei_cves),
        ]:
            _log(scan_id, f"{fn_name}...", "info")
            _emit_findings(scan_id, fn(url))
    except Exception as e:
        _log(scan_id, f"Vuln scan error: {e}", "error")


def _run_module_auth(scan_id, target, login_url, username, password):
    try:
        from modules.auth_tester import run_auth_tests
        result = run_auth_tests(target, login_url or None, username or None, password or None)
        for f in result.findings:
            _store_finding(
                scan_id, "auth_tester",
                f.get("title", ""), f.get("severity", "INFO"),
                f.get("description", ""), f.get("evidence", ""),
                f.get("remediation", ""),
            )
        if result.successful_logins:
            logins_str = "\n".join(
                f"  • {l['username']} → {l.get('final_url','')}"
                for l in result.successful_logins
            )
            _log(scan_id, f"✅ VALID LOGINS FOUND:\n{logins_str}", "critical")
    except Exception as e:
        _log(scan_id, f"Auth test error: {e}", "error")


def _generate_standard_reports(scan_id, target, url, hostname, ip):
    try:
        from modules.report_gen import generate_html_report, generate_json_report
        from utils.helpers import get_timestamp, severity_score, risk_rating

        with get_db() as conn:
            findings_rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id=?", (scan_id,)
            ).fetchall()

        findings = [dict(r) for r in findings_rows]
        counts = severity_score(findings)
        rating, _ = risk_rating(counts)

        scan_dict = {
            "target": target, "hostname": hostname, "ip": ip,
            "start_time": "", "end_time": get_timestamp(),
            "modules": [{"module": "Dashboard Scan", "findings": findings}],
        }

        html_path = generate_html_report(scan_dict)
        json_path = generate_json_report(scan_dict)

        with get_db() as conn:
            conn.execute(
                "UPDATE scans SET report_html=?,report_json=? WHERE id=?",
                (os.path.basename(html_path), os.path.basename(json_path), scan_id),
            )

        _push(scan_id, "report", {
            "html": os.path.basename(html_path),
            "json": os.path.basename(json_path),
        })
        _log(scan_id, f"Reports: {os.path.basename(html_path)}", "success")
        return rating
    except Exception as e:
        _log(scan_id, f"Report generation error: {e}", "error")
        return "UNKNOWN"


def _auto_bug_bounty(scan_id, target):
    """Auto-generate bug bounty report if CRITICAL or HIGH findings exist."""
    try:
        with get_db() as conn:
            findings_rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id=? AND severity IN ('CRITICAL','HIGH')"
                " ORDER BY severity",
                (scan_id,),
            ).fetchall()

        if not findings_rows:
            return

        findings = [dict(r) for r in findings_rows]
        crits = sum(1 for f in findings if f["severity"] == "CRITICAL")
        highs = sum(1 for f in findings if f["severity"] == "HIGH")

        _log(scan_id,
             f"🚨 {crits} CRITICAL + {highs} HIGH findings — generating Bug Bounty report!",
             "critical")

        from modules.bug_bounty_report import create_bug_bounty_report
        bb_path = create_bug_bounty_report(scan_id, target, findings, BB_REPORTS_DIR)

        with get_db() as conn:
            conn.execute(
                "UPDATE scans SET bug_bounty_path=? WHERE id=?",
                (os.path.basename(bb_path), scan_id),
            )

        _push(scan_id, "bug_bounty", {
            "file": os.path.basename(bb_path),
            "critical": crits,
            "high": highs,
            "msg": f"Bug Bounty report ready! {crits} critical, {highs} high findings.",
        })
        _log(scan_id, f"Bug Bounty report: {os.path.basename(bb_path)}", "success")

    except Exception as e:
        _log(scan_id, f"Bug bounty report error: {e}", "error")


def _finish_scan(scan_id, status):
    """Compute final risk rating and mark scan complete."""
    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT severity FROM findings WHERE scan_id=?", (scan_id,)
            ).fetchall()

        crits = sum(1 for r in rows if r[0] == "CRITICAL")
        highs = sum(1 for r in rows if r[0] == "HIGH")
        meds  = sum(1 for r in rows if r[0] == "MEDIUM")

        if crits > 0:
            risk = "CRITICAL"
        elif highs >= 3:
            risk = "HIGH"
        elif highs >= 1:
            risk = "MEDIUM"
        elif meds >= 1:
            risk = "LOW"
        else:
            risk = "INFO"

        with get_db() as conn:
            conn.execute(
                "UPDATE scans SET status=?,completed_at=?,risk_rating=? WHERE id=?",
                (status, datetime.now(timezone.utc).isoformat(), risk, scan_id),
            )

        _push(scan_id, "status", {"status": status, "risk_rating": risk})

        if status == "complete":
            total = len(rows)
            _log(scan_id,
                 f"Scan complete — {total} findings | Risk: {risk}",
                 "success" if risk in ("INFO", "LOW") else "critical")
    except Exception as e:
        _push(scan_id, "status", {"status": "error"})
        _log(scan_id, f"Finish error: {e}", "error")


# ─── Entry Point ──────────────────────────────────────────────────────────────

def run_dashboard(host="127.0.0.1", port=5000):
    init_db()
    print("\n" + "=" * 60)
    print("  CYBERBURG DASHBOARD")
    print(f"  http://{host}:{port}")
    print("  ⚖️  Ethical pentesting only — authorized targets")
    print("=" * 60 + "\n")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    run_dashboard()
