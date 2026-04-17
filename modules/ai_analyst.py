#!/usr/bin/env python3
"""
AI Analyst — Cyberburg v4 DARK MATTER
Uses Claude AI (Anthropic API) to analyze all scan findings and generate:
- Professional penetration test executive summary
- Intelligent severity re-assessment
- Next attack vector suggestions
- Remediation roadmap ranked by impact

Requires: pip install anthropic
Set env var: ANTHROPIC_API_KEY=your_key_here
"""

import os
import json

from utils.helpers import get_timestamp
from utils.banner import print_info, print_success, print_warning, print_error
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

MODEL = "claude-sonnet-4-6"


def _get_api_key() -> str:
    """Get Anthropic API key from env or config file."""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        config_path = os.path.expanduser("~/.cyberburg_api_key")
        if os.path.exists(config_path):
            with open(config_path) as f:
                key = f.read().strip()
    return key


def _build_findings_summary(session_obj) -> str:
    """Build a concise text summary of all findings for the AI prompt."""
    lines = [
        f"Target: {session_obj.target}",
        f"URL: {session_obj.url}",
        f"IP: {session_obj.ip}",
        f"Scan started: {session_obj.start_time}",
        "",
        "=== FINDINGS ===",
    ]

    findings = session_obj.all_findings()
    by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in by_severity:
            by_severity[sev].append(f)

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        items = by_severity[sev]
        if items:
            lines.append(f"\n[{sev}] — {len(items)} finding(s):")
            for f in items[:15]:  # Cap per severity
                lines.append(f"  • [{f.get('module','?')}] {f.get('type','')}: {f.get('value','')[:120]}")

    lines += [
        "",
        f"Total findings: {len(findings)}",
        f"Critical: {len(by_severity['CRITICAL'])}",
        f"High: {len(by_severity['HIGH'])}",
        f"Medium: {len(by_severity['MEDIUM'])}",
        f"Low: {len(by_severity['LOW'])}",
    ]

    return "\n".join(lines)


def run_ai_analysis(session_obj, output_dir: str) -> dict:
    """
    Send scan findings to Claude AI and get professional pentesting analysis.
    """
    result = {
        "module": "AI Analysis — Claude Intelligence",
        "target": session_obj.target,
        "timestamp": get_timestamp(),
        "raw": "",
        "findings": [],
        "ai_report": ""
    }

    if not HAS_ANTHROPIC:
        print_warning("anthropic package not installed. Run: pip install anthropic")
        result["findings"].append({
            "type": "AI Analysis",
            "value": "anthropic package not available — install with: pip install anthropic",
            "severity": "INFO"
        })
        return result

    api_key = _get_api_key()
    if not api_key:
        print_warning("ANTHROPIC_API_KEY not set.")
        console.print("[dim]  Set via: export ANTHROPIC_API_KEY=your_key[/dim]")
        console.print("[dim]  Or save to: ~/.cyberburg_api_key[/dim]")
        result["findings"].append({
            "type": "AI Analysis",
            "value": "ANTHROPIC_API_KEY not configured — set env var or save to ~/.cyberburg_api_key",
            "severity": "INFO"
        })
        return result

    print_info("Sending findings to Claude AI for expert analysis...")
    loot_dir = os.path.join(output_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)

    findings_summary = _build_findings_summary(session_obj)

    system_prompt = """You are a senior penetration tester with 20 years of experience.
You specialize in web application security, network penetration testing, and vulnerability assessment.
You write clear, professional, actionable penetration test reports.
You think like an attacker and communicate findings like a trusted security advisor."""

    user_prompt = f"""Analyze the following penetration test findings and provide:

1. **Executive Summary** (3-4 sentences for a non-technical audience)
2. **Risk Assessment** — Overall risk rating with justification
3. **Critical Finding Analysis** — Deep dive on the most severe findings with attack chain explanation
4. **Attack Chain** — How an attacker could chain these findings for maximum impact
5. **Next Attack Vectors** — Based on what was found, what should be tested next?
6. **Remediation Roadmap** — Top 5 fixes ranked by impact/effort ratio
7. **Evidence of Compromise Check** — Do any findings suggest this target may already be compromised?

Be direct, specific, and professional. Use pentest report language.

SCAN FINDINGS:
{findings_summary}"""

    try:
        client = anthropic.Anthropic(api_key=api_key)

        # Use streaming for better UX
        console.print("\n[bold cyan]  ╔══════════════════════════════════════╗[/bold cyan]")
        console.print("[bold cyan]  ║   CLAUDE AI — EXPERT ANALYSIS        ║[/bold cyan]")
        console.print("[bold cyan]  ╚══════════════════════════════════════╝[/bold cyan]\n")

        ai_response = ""
        with client.messages.stream(
            model=MODEL,
            max_tokens=2000,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}]
        ) as stream:
            for text in stream.text_stream:
                print(text, end="", flush=True)
                ai_response += text
        print()  # newline after stream

        result["ai_report"] = ai_response
        result["raw"] = f"Model: {MODEL}\nTokens: ~{len(ai_response.split())}"

        # Save AI report
        loot_path = os.path.join(loot_dir, "ai_analysis.md")
        with open(loot_path, "w", encoding="utf-8") as f:
            f.write(f"# AI Penetration Test Analysis\n\n")
            f.write(f"**Target:** {session_obj.target}\n")
            f.write(f"**Generated:** {get_timestamp()}\n")
            f.write(f"**Model:** {MODEL}\n\n---\n\n")
            f.write(ai_response)
        console.print(f"\n  [bold green]AI analysis saved to: {loot_path}[/bold green]")

        result["findings"].append({
            "type": "AI Analysis Complete",
            "value": f"Claude AI expert analysis generated — {len(ai_response)} characters",
            "severity": "INFO"
        })

        # Extract any critical insights Claude flagged
        if any(kw in ai_response.lower() for kw in ("already compromised", "active exploitation", "evidence of breach")):
            result["findings"].append({
                "type": "AI: Potential Compromise Detected",
                "value": "Claude AI flagged potential signs of existing compromise — review AI report immediately",
                "severity": "CRITICAL"
            })
            print_error("CRITICAL: Claude AI suspects existing compromise — review the AI report!")

    except anthropic.AuthenticationError:
        print_error("Invalid ANTHROPIC_API_KEY — check your API key")
        result["findings"].append({
            "type": "AI Analysis",
            "value": "Authentication failed — invalid API key",
            "severity": "INFO"
        })
    except anthropic.RateLimitError:
        print_warning("Anthropic API rate limit — try again in a moment")
        result["findings"].append({
            "type": "AI Analysis",
            "value": "Rate limit reached — retry in 60 seconds",
            "severity": "INFO"
        })
    except Exception as e:
        print_error(f"AI analysis error: {e}")
        result["findings"].append({
            "type": "AI Analysis Error",
            "value": str(e),
            "severity": "INFO"
        })

    return result


def configure_api_key():
    """Interactive setup to save API key to ~/.cyberburg_api_key."""
    console.print("\n[bold cyan]Anthropic API Key Setup[/bold cyan]")
    console.print("[dim]Get your key at: https://console.anthropic.com/[/dim]\n")

    try:
        from rich.prompt import Prompt
        key = Prompt.ask("  Enter your ANTHROPIC_API_KEY", password=True)
        if key.strip():
            config_path = os.path.expanduser("~/.cyberburg_api_key")
            with open(config_path, "w") as f:
                f.write(key.strip())
            os.chmod(config_path, 0o600)
            console.print(f"  [bold green]API key saved to {config_path}[/bold green]")
            return True
    except Exception as e:
        print_error(f"Failed to save API key: {e}")

    return False
