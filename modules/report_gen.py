"""
Report Generator Module — Cyberburg
Generates comprehensive HTML, JSON, and TXT security reports.
"""

import os
import json
import re
from datetime import datetime
from utils.helpers import get_filename_timestamp, severity_score, risk_rating
from utils.banner import DEVELOPER_INFO
from rich.console import Console

console = Console()


def generate_html_report(scan_results: dict, output_path: str = None) -> str:
    """Generate a comprehensive HTML penetration testing report."""
    target = scan_results.get("target", "Unknown Target")
    start_time = scan_results.get("start_time", "")
    end_time = scan_results.get("end_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Aggregate all findings
    all_findings = []
    for module_result in scan_results.get("modules", []):
        findings = module_result.get("findings", [])
        module_name = module_result.get("module", "Unknown")
        for finding in findings:
            finding["module"] = module_name
            all_findings.append(finding)

    # Calculate stats
    counts = severity_score(all_findings)
    total = len(all_findings)
    rating, rating_color = risk_rating(counts)

    if not output_path:
        ts = get_filename_timestamp()
        safe_target = re.sub(r'[^\w\-_]', '_', target)
        output_path = f"reports/cyberburg_{safe_target}_{ts}.html"

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else "reports", exist_ok=True)

    # Group findings by module
    modules_dict = {}
    for finding in all_findings:
        mod = finding.get("module", "General")
        if mod not in modules_dict:
            modules_dict[mod] = []
        modules_dict[mod].append(finding)

    # Generate findings HTML
    findings_html = ""
    for mod_name, mod_findings in modules_dict.items():
        findings_html += f"""
        <div class="module-section">
            <h3 class="module-title">
                <span class="module-icon">⚡</span> {mod_name}
                <span class="finding-count">{len(mod_findings)} findings</span>
            </h3>
            <div class="findings-list">
        """
        for f in mod_findings:
            sev = f.get("severity", "INFO").upper()
            sev_class = sev.lower()
            findings_html += f"""
                <div class="finding finding-{sev_class}">
                    <div class="finding-header">
                        <span class="severity-badge badge-{sev_class}">{sev}</span>
                        <span class="finding-type">{_escape_html(f.get('type', ''))}</span>
                    </div>
                    <div class="finding-value">{_escape_html(f.get('value', ''))}</div>
                </div>
            """
        findings_html += "</div></div>"

    # Severity chart data
    chart_data = json.dumps([
        counts.get("CRITICAL", 0),
        counts.get("HIGH", 0),
        counts.get("MEDIUM", 0),
        counts.get("LOW", 0),
        counts.get("INFO", 0),
    ])

    # Recommendations
    recommendations = _generate_recommendations(all_findings)
    recs_html = "".join(f"<li>{r}</li>" for r in recommendations)

    # Attack vectors used
    attack_vectors = _extract_attack_vectors(scan_results.get("modules", []))
    vectors_html = "".join(f"<li class='attack-vector'>{v}</li>" for v in attack_vectors)

    # Modules used
    modules_used = [m.get("module", "Unknown") for m in scan_results.get("modules", [])]
    modules_html = "".join(f"<span class='module-badge'>{m}</span>" for m in modules_used)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyberburg Security Report — {_escape_html(target)}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-primary: #0a0e1a;
            --bg-secondary: #0f1629;
            --bg-card: #141b2d;
            --bg-card2: #1a2235;
            --accent-red: #ff3b3b;
            --accent-orange: #ff6b35;
            --accent-blue: #00d4ff;
            --accent-green: #00ff88;
            --accent-purple: #a855f7;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --border: #1e2d4a;
            --critical: #ff1744;
            --high: #ff6d00;
            --medium: #ffd740;
            --low: #00e5ff;
            --info: #69f0ae;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        /* HEADER */
        .report-header {{
            background: linear-gradient(135deg, #0a0e1a 0%, #0f1629 50%, #1a0a2e 100%);
            border-bottom: 2px solid var(--accent-red);
            padding: 40px;
            position: relative;
            overflow: hidden;
        }}
        .report-header::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ff3b3b' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            opacity: 0.5;
        }}
        .header-content {{ position: relative; z-index: 1; }}
        .header-logo {{
            font-size: 42px;
            font-weight: 900;
            letter-spacing: 4px;
            background: linear-gradient(135deg, var(--accent-red), var(--accent-orange), var(--accent-blue));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
        }}
        .header-subtitle {{
            color: var(--text-secondary);
            font-size: 14px;
            letter-spacing: 3px;
            text-transform: uppercase;
            margin-bottom: 30px;
        }}
        .header-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .meta-item {{
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
        }}
        .meta-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: var(--text-muted);
            margin-bottom: 5px;
        }}
        .meta-value {{
            font-size: 16px;
            font-weight: 600;
            color: var(--accent-blue);
            word-break: break-all;
        }}
        /* RISK BANNER */
        .risk-banner {{
            padding: 25px 40px;
            display: flex;
            align-items: center;
            gap: 20px;
            border-bottom: 1px solid var(--border);
        }}
        .risk-badge {{
            font-size: 28px;
            font-weight: 900;
            letter-spacing: 3px;
            padding: 12px 30px;
            border-radius: 8px;
            border: 2px solid currentColor;
        }}
        .risk-critical {{ color: var(--critical); background: rgba(255,23,68,0.1); }}
        .risk-high {{ color: var(--high); background: rgba(255,109,0,0.1); }}
        .risk-medium {{ color: var(--medium); background: rgba(255,215,64,0.1); }}
        .risk-low {{ color: var(--low); background: rgba(0,229,255,0.1); }}
        .risk-info {{ color: var(--info); background: rgba(105,240,174,0.1); }}
        /* CONTAINER */
        .container {{ max-width: 1400px; margin: 0 auto; padding: 30px 40px; }}
        /* STATS GRID */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin: 30px 0;
        }}
        @media (max-width: 900px) {{ .stats-grid {{ grid-template-columns: repeat(2, 1fr); }} }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-3px); }}
        .stat-number {{
            font-size: 48px;
            font-weight: 900;
            line-height: 1;
            margin-bottom: 8px;
        }}
        .stat-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 2px; color: var(--text-muted); }}
        .stat-critical .stat-number {{ color: var(--critical); }}
        .stat-high .stat-number {{ color: var(--high); }}
        .stat-medium .stat-number {{ color: var(--medium); }}
        .stat-low .stat-number {{ color: var(--low); }}
        .stat-info .stat-number {{ color: var(--info); }}
        /* SECTIONS */
        .section {{ margin: 40px 0; }}
        .section-title {{
            font-size: 22px;
            font-weight: 700;
            color: var(--accent-blue);
            border-left: 4px solid var(--accent-red);
            padding-left: 15px;
            margin-bottom: 20px;
        }}
        /* CHART */
        .chart-container {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 30px;
            max-width: 400px;
        }}
        /* MODULE SECTIONS */
        .module-section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin: 15px 0;
            overflow: hidden;
        }}
        .module-title {{
            background: var(--bg-card2);
            padding: 15px 20px;
            font-size: 15px;
            font-weight: 700;
            color: var(--accent-blue);
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 1px solid var(--border);
        }}
        .module-icon {{ font-style: normal; }}
        .finding-count {{
            margin-left: auto;
            font-size: 12px;
            background: rgba(0,212,255,0.1);
            color: var(--accent-blue);
            padding: 3px 10px;
            border-radius: 20px;
            font-weight: 400;
        }}
        .findings-list {{ padding: 10px; }}
        /* FINDINGS */
        .finding {{
            border-radius: 8px;
            padding: 12px 15px;
            margin: 6px 0;
            border-left: 4px solid;
            background: rgba(255,255,255,0.02);
        }}
        .finding-critical {{ border-color: var(--critical); background: rgba(255,23,68,0.05); }}
        .finding-high {{ border-color: var(--high); background: rgba(255,109,0,0.05); }}
        .finding-medium {{ border-color: var(--medium); background: rgba(255,215,64,0.05); }}
        .finding-low {{ border-color: var(--low); background: rgba(0,229,255,0.05); }}
        .finding-info {{ border-color: var(--info); background: rgba(105,240,174,0.03); }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
        .severity-badge {{
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1px;
            padding: 2px 8px;
            border-radius: 4px;
            text-transform: uppercase;
            white-space: nowrap;
        }}
        .badge-critical {{ background: var(--critical); color: white; }}
        .badge-high {{ background: var(--high); color: white; }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); color: #000; }}
        .badge-info {{ background: var(--info); color: #000; }}
        .finding-type {{ font-weight: 600; font-size: 14px; }}
        .finding-value {{
            font-size: 13px;
            color: var(--text-secondary);
            word-break: break-all;
            padding-left: 5px;
        }}
        /* ATTACK VECTORS */
        .attack-vector {{
            background: var(--bg-card2);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 8px 12px;
            margin: 5px 0;
            font-size: 13px;
            color: var(--text-secondary);
            list-style: none;
        }}
        .attack-vector::before {{ content: "→ "; color: var(--accent-red); font-weight: bold; }}
        /* MODULES USED */
        .module-badge {{
            display: inline-block;
            background: rgba(0,212,255,0.1);
            border: 1px solid rgba(0,212,255,0.3);
            color: var(--accent-blue);
            font-size: 12px;
            padding: 4px 12px;
            border-radius: 20px;
            margin: 4px;
        }}
        /* RECOMMENDATIONS */
        .recommendations li {{
            padding: 10px 0;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
            color: var(--text-secondary);
            list-style: none;
        }}
        .recommendations li::before {{ content: "✓ "; color: var(--accent-green); font-weight: bold; }}
        /* FOOTER */
        .report-footer {{
            background: var(--bg-secondary);
            border-top: 1px solid var(--border);
            padding: 40px;
            text-align: center;
            margin-top: 60px;
        }}
        .footer-dev {{ font-size: 18px; font-weight: 700; color: var(--accent-red); margin-bottom: 10px; }}
        .footer-links a {{
            color: var(--accent-blue);
            text-decoration: none;
            margin: 0 15px;
            font-size: 14px;
        }}
        .footer-links a:hover {{ color: var(--accent-red); }}
        .footer-disclaimer {{
            margin-top: 20px;
            font-size: 12px;
            color: var(--text-muted);
            max-width: 700px;
            margin-left: auto;
            margin-right: auto;
        }}
        /* TABLE */
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: var(--bg-card2); padding: 12px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); }}
        td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }}
        /* MISC */
        .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media (max-width: 768px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
        .legal-notice {{
            background: rgba(255,55,55,0.05);
            border: 1px solid rgba(255,55,55,0.3);
            border-radius: 8px;
            padding: 15px 20px;
            font-size: 13px;
            color: var(--text-secondary);
            margin: 20px 0;
        }}
    </style>
</head>
<body>

<!-- HEADER -->
<div class="report-header">
    <div class="header-content">
        <div class="header-logo">CYBERBURG</div>
        <div class="header-subtitle">Advanced Web Penetration Testing Report</div>
        <div class="legal-notice">
            ⚠️ This report is generated for authorized security testing only.
            Unauthorized use of this tool against systems you don't own is illegal.
            Always obtain written permission before testing.
        </div>
        <div class="header-meta">
            <div class="meta-item">
                <div class="meta-label">Target</div>
                <div class="meta-value">{_escape_html(target)}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Scan Started</div>
                <div class="meta-value">{start_time}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Scan Completed</div>
                <div class="meta-value">{end_time}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Total Findings</div>
                <div class="meta-value" style="color: var(--accent-red)">{total}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Report Generated By</div>
                <div class="meta-value" style="color: var(--accent-green)">Cyberburg v2.0</div>
            </div>
        </div>
    </div>
</div>

<!-- RISK BANNER -->
<div class="risk-banner" style="background: var(--bg-secondary);">
    <div class="risk-badge risk-{rating.lower()}">{rating}</div>
    <div>
        <div style="font-size: 18px; font-weight: 700;">Overall Security Risk: {rating}</div>
        <div style="color: var(--text-secondary); font-size: 14px;">
            Based on {total} findings across {len(modules_used)} scan modules
        </div>
    </div>
</div>

<div class="container">

    <!-- STATS -->
    <div class="section">
        <div class="section-title">Vulnerability Summary</div>
        <div class="stats-grid">
            <div class="stat-card stat-critical">
                <div class="stat-number">{counts.get('CRITICAL', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card stat-high">
                <div class="stat-number">{counts.get('HIGH', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card stat-medium">
                <div class="stat-number">{counts.get('MEDIUM', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card stat-low">
                <div class="stat-number">{counts.get('LOW', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card stat-info">
                <div class="stat-number">{counts.get('INFO', 0)}</div>
                <div class="stat-label">Informational</div>
            </div>
        </div>
    </div>

    <!-- CHART + ATTACK VECTORS -->
    <div class="two-col">
        <div class="section">
            <div class="section-title">Severity Distribution</div>
            <div class="chart-container">
                <canvas id="sevChart" width="350" height="350"></canvas>
            </div>
        </div>
        <div class="section">
            <div class="section-title">Attack Vectors Used</div>
            <ul style="padding: 0;">
                {vectors_html}
            </ul>
            <br>
            <div class="section-title" style="margin-top: 20px">Modules Executed</div>
            <div>{modules_html}</div>
        </div>
    </div>

    <!-- FINDINGS -->
    <div class="section">
        <div class="section-title">Detailed Findings</div>
        {findings_html}
    </div>

    <!-- RECOMMENDATIONS -->
    <div class="section">
        <div class="section-title">Security Recommendations</div>
        <div class="module-section">
            <ul class="recommendations" style="padding: 20px 30px;">
                {recs_html}
            </ul>
        </div>
    </div>

    <!-- DISCLAIMER -->
    <div class="section">
        <div class="legal-notice">
            <strong>Legal Disclaimer:</strong> This penetration test was conducted for authorized security assessment purposes.
            All findings in this report should be treated as confidential and shared only with authorized personnel.
            Remediation of identified vulnerabilities should be prioritized based on severity ratings.
            Re-testing is recommended after all high and critical findings are remediated.
        </div>
    </div>

</div>

<!-- FOOTER -->
<div class="report-footer">
    <div class="footer-dev">Cyberburg — Advanced Web Penetration Testing Suite</div>
    <div class="footer-links">
        <a href="https://github.com/faizzyhon" target="_blank">GitHub: @faizzyhon</a>
        <a href="https://instagram.com/faizzyhon" target="_blank">Instagram: @faizzyhon</a>
        <a href="https://faizzyhon.online" target="_blank">faizzyhon.online</a>
    </div>
    <div class="footer-disclaimer">
        Developed by <strong>Faiz Zyhon</strong> | For authorized penetration testing and security research only.
        Unauthorized use is illegal. This tool is provided as-is without warranty.
        Always obtain written authorization before conducting security assessments.
    </div>
    <div style="margin-top: 15px; font-size: 12px; color: var(--text-muted);">
        Report generated: {end_time} | Cyberburg v2.0.0 | PHANTOM BLADE
    </div>
</div>

<script>
const ctx = document.getElementById('sevChart').getContext('2d');
new Chart(ctx, {{
    type: 'doughnut',
    data: {{
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{{
            data: {chart_data},
            backgroundColor: ['#ff1744', '#ff6d00', '#ffd740', '#00e5ff', '#69f0ae'],
            borderColor: '#0a0e1a',
            borderWidth: 3,
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{
            legend: {{
                labels: {{ color: '#e2e8f0', font: {{ size: 13 }} }}
            }}
        }}
    }}
}});
</script>

</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    console.print(f"[bold green][+][/bold green] HTML Report saved: [cyan]{output_path}[/cyan]")
    return output_path


def generate_json_report(scan_results: dict, output_path: str = None) -> str:
    """Generate a JSON report for machine-readable output."""
    target = scan_results.get("target", "unknown")

    if not output_path:
        ts = get_filename_timestamp()
        safe_target = re.sub(r'[^\w\-_]', '_', target)
        output_path = f"reports/cyberburg_{safe_target}_{ts}.json"

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else "reports", exist_ok=True)

    # Build clean JSON structure
    all_findings = []
    for module_result in scan_results.get("modules", []):
        for finding in module_result.get("findings", []):
            finding["module"] = module_result.get("module", "Unknown")
            all_findings.append(finding)

    counts = severity_score(all_findings)
    rating, _ = risk_rating(counts)

    report = {
        "meta": {
            "tool": "Cyberburg",
            "version": "2.0.0",
            "developer": "Faiz Zyhon",
            "github": "github.com/faizzyhon",
            "website": "faizzyhon.online",
            "generated": datetime.now().isoformat(),
        },
        "target": target,
        "start_time": scan_results.get("start_time", ""),
        "end_time": scan_results.get("end_time", ""),
        "risk_rating": rating,
        "summary": counts,
        "total_findings": len(all_findings),
        "modules_executed": [m.get("module", "Unknown") for m in scan_results.get("modules", [])],
        "findings": all_findings,
        "modules_raw": scan_results.get("modules", []),
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)

    console.print(f"[bold green][+][/bold green] JSON Report saved: [cyan]{output_path}[/cyan]")
    return output_path


def generate_txt_report(scan_results: dict, output_path: str = None) -> str:
    """Generate a plain text report."""
    target = scan_results.get("target", "Unknown")

    if not output_path:
        ts = get_filename_timestamp()
        safe_target = re.sub(r'[^\w\-_]', '_', target)
        output_path = f"reports/cyberburg_{safe_target}_{ts}.txt"

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else "reports", exist_ok=True)

    all_findings = []
    for module_result in scan_results.get("modules", []):
        for finding in module_result.get("findings", []):
            finding["module"] = module_result.get("module", "Unknown")
            all_findings.append(finding)

    counts = severity_score(all_findings)
    rating, _ = risk_rating(counts)

    lines = [
        "=" * 80,
        "  CYBERBURG — Web Penetration Testing Report",
        "  Developer: Faiz Zyhon | github.com/faizzyhon | faizzyhon.online",
        "=" * 80,
        "",
        f"Target    : {target}",
        f"Start Time: {scan_results.get('start_time', 'N/A')}",
        f"End Time  : {scan_results.get('end_time', 'N/A')}",
        f"Risk Level: {rating}",
        f"Total     : {len(all_findings)} findings",
        "",
        "SEVERITY SUMMARY",
        "-" * 40,
        f"  CRITICAL : {counts.get('CRITICAL', 0)}",
        f"  HIGH     : {counts.get('HIGH', 0)}",
        f"  MEDIUM   : {counts.get('MEDIUM', 0)}",
        f"  LOW      : {counts.get('LOW', 0)}",
        f"  INFO     : {counts.get('INFO', 0)}",
        "",
        "DETAILED FINDINGS",
        "=" * 80,
    ]

    # Group by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_findings = [f for f in all_findings if f.get("severity", "INFO").upper() == severity]
        if sev_findings:
            lines.append(f"\n[{severity}] — {len(sev_findings)} findings")
            lines.append("-" * 60)
            for f in sev_findings:
                lines.append(f"  Module : {f.get('module', 'Unknown')}")
                lines.append(f"  Type   : {f.get('type', '')}")
                lines.append(f"  Detail : {f.get('value', '')}")
                lines.append("")

    lines += [
        "=" * 80,
        "RECOMMENDATIONS",
        "=" * 80,
    ]
    for rec in _generate_recommendations(all_findings):
        lines.append(f"  • {rec}")

    lines += [
        "",
        "=" * 80,
        "LEGAL DISCLAIMER",
        "=" * 80,
        "This report was generated for authorized security testing purposes only.",
        "Unauthorized use is illegal. Always obtain written permission before testing.",
        "",
        f"Generated by Cyberburg v2.0.0 | github.com/faizzyhon",
        "=" * 80,
    ]

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    console.print(f"[bold green][+][/bold green] TXT Report saved: [cyan]{output_path}[/cyan]")
    return output_path


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (str(text)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))


def _generate_recommendations(findings: list) -> list:
    """Generate recommendations based on findings."""
    recs = set()
    finding_values = " ".join([f.get("value", "") + " " + f.get("type", "") for f in findings]).lower()

    if "sql injection" in finding_values:
        recs.add("Implement parameterized queries / prepared statements to prevent SQL injection attacks")
    if "xss" in finding_values:
        recs.add("Implement Content Security Policy (CSP) and sanitize all user inputs to prevent XSS")
    if "missing" in finding_values and "header" in finding_values:
        recs.add("Add all missing security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options")
    if "ssl" in finding_values or "tls" in finding_values:
        recs.add("Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1 — use only TLS 1.2 and TLS 1.3")
    if "weak cipher" in finding_values:
        recs.add("Remove weak cipher suites (RC4, DES, 3DES, NULL, EXPORT) from SSL/TLS configuration")
    if "open port" in finding_values or "dangerous port" in finding_values:
        recs.add("Close unnecessary ports and services — apply firewall rules to restrict access")
    if "directory" in finding_values and "found" in finding_values:
        recs.add("Disable directory listing on web server and restrict access to sensitive directories")
    if ".git" in finding_values or "git" in finding_values:
        recs.add("Remove .git directory from web root — it exposes source code and credentials")
    if ".env" in finding_values:
        recs.add("Remove .env files from web root — they contain sensitive credentials and configuration")
    if "wordpress" in finding_values:
        recs.add("Keep WordPress core, themes, and plugins updated. Use security plugins like Wordfence")
    if "waf" in finding_values and "no waf" in finding_values:
        recs.add("Implement a Web Application Firewall (WAF) such as ModSecurity, Cloudflare, or AWS WAF")
    if "zone transfer" in finding_values:
        recs.add("Disable DNS zone transfer (AXFR) — restrict to authorized secondary DNS servers only")
    if "cookie" in finding_values:
        recs.add("Add HttpOnly, Secure, and SameSite=Strict attributes to all session cookies")
    if "smtp" in finding_values or "email" in finding_values:
        recs.add("Configure SPF, DKIM, and DMARC DNS records to prevent email spoofing")
    if "expired" in finding_values:
        recs.add("Renew expired SSL certificates immediately and implement automated renewal (Let's Encrypt)")
    if "mysql" in finding_values or "database" in finding_values:
        recs.add("Never expose databases directly to the internet — use firewall rules and VPN access")
    if "default credentials" in finding_values or "default password" in finding_values:
        recs.add("Change all default credentials immediately — use strong, unique passwords")
    if "backup" in finding_values:
        recs.add("Remove backup files from web root — they may contain sensitive source code/configuration")
    if "http method" in finding_values or "put method" in finding_values:
        recs.add("Disable dangerous HTTP methods (PUT, DELETE, TRACE) unless explicitly required")
    if "information disclosure" in finding_values:
        recs.add("Remove or suppress Server and X-Powered-By headers to prevent technology fingerprinting")

    # Always add these baseline recommendations
    recs.add("Implement regular security scanning and penetration testing schedule")
    recs.add("Maintain an up-to-date asset inventory and patch management process")
    recs.add("Enable comprehensive logging and monitoring for all web application events")
    recs.add("Implement principle of least privilege for all service accounts and API keys")

    return sorted(list(recs))


def _extract_attack_vectors(modules: list) -> list:
    """Extract list of attack vectors used in the scan."""
    vector_map = {
        "Reconnaissance": "OSINT & Domain Reconnaissance",
        "WHOIS": "WHOIS Domain Intelligence Gathering",
        "DNS": "DNS Enumeration & Zone Transfer Testing",
        "Subdomain": "Subdomain Discovery & Enumeration",
        "Port": "Network Port Scanning & Service Fingerprinting",
        "Nmap": "Nmap Vulnerability Script Execution",
        "Nikto": "Web Server Vulnerability Analysis (Nikto)",
        "WhatWeb": "Technology Stack Fingerprinting",
        "WAF": "Web Application Firewall Detection",
        "HTTP": "HTTP Method & Security Header Analysis",
        "SQL": "SQL Injection Testing (Manual + SQLMap)",
        "XSS": "Cross-Site Scripting (XSS) Testing",
        "Directory": "Directory & File Bruteforcing",
        "SSL": "SSL/TLS Configuration Analysis",
        "Heartbleed": "Heartbleed (CVE-2014-0160) Testing",
        "Nuclei": "Template-Based Vulnerability Scanning",
        "CMS": "CMS Detection & Plugin Enumeration",
        "Email": "Email Harvesting & OSINT",
        "Geolocation": "IP Geolocation Mapping",
    }

    vectors = []
    for module in modules:
        mod_name = module.get("module", "")
        for key, vector in vector_map.items():
            if key.lower() in mod_name.lower() and vector not in vectors:
                vectors.append(vector)
                break

    if not vectors:
        vectors = ["Web Application Security Assessment"]

    return vectors
