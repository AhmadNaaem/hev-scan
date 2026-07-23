#!/usr/bin/env python3
"""HEV-Scan: Host Enumeration & Vulnerability Scanner.

Recon-to-risk CLI: resolves a host, scans it with nmap, matches detected
services against known CVEs via the NVD API, and renders a self-contained
HTML report. Built for defensive/educational use against systems you own
or are authorized to test.
"""

import argparse
import html
import os
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

import pyfiglet
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

VERSION = "1.0.0"
ORANGE = "#ff6b00"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

LOGO_ART = r"""
                    #####
             #######    ###########
        ####         ####  ############
      ##                 ##  #######V#####
    ##        __           ## #############
   #         /  \            ############
  ##        /    \          ##########
 ##         /     \           #####
 ##        /       \          ####
 ##        /        \         ##
 ##       /          \        ##
  ##      /          \       ##
   #     /            \      #
    ##                     ##
      ##                 ##
        ####         ####
             #######
""".strip("\n")

SEVERITY_STYLES = {
    "CRITICAL": "bold white on red3",
    "HIGH": f"bold {ORANGE}",
    "MEDIUM": "bold yellow3",
    "LOW": "bold green3",
    "UNKNOWN": "dim white",
}

SEVERITY_BADGE_COLORS = {
    "CRITICAL": ("#ff3b3b", "#2a0000"),
    "HIGH": ("#ff6b00", "#2a1500"),
    "MEDIUM": ("#ffd23f", "#2a2200"),
    "LOW": ("#4caf50", "#0a2a0a"),
    "UNKNOWN": ("#888888", "#1a1a1a"),
}

console = Console()


# --------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------

def print_banner():
    major_digit = VERSION.split(".")[0][:1] or "?"
    art = LOGO_ART.replace("V", major_digit)
    for line in art.splitlines():
        console.print(line, style=f"bold {ORANGE}", markup=False, highlight=False)

    try:
        wordmark = pyfiglet.figlet_format("HEV-Scan", font="slant")
    except Exception:
        wordmark = pyfiglet.figlet_format("HEV-Scan")
    console.print(Text(wordmark.rstrip("\n"), style=f"bold {ORANGE}"))

    body = Text()
    body.append("Host Enumeration & Vulnerability Scanner\n", style="bold white")
    body.append(f"v{VERSION}\n", style=ORANGE)
    body.append("CYFOR / Cyber Fort", style="dim white")
    console.print(Panel(body, border_style=ORANGE, expand=False))
    console.print()


# --------------------------------------------------------------------------
# Recon: DNS resolution
# --------------------------------------------------------------------------

def resolve_host(host):
    """Resolve a hostname to its IP addresses. Returns (ips, error)."""
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return ips, None
    except socket.gaierror as e:
        return [], str(e)
    except Exception as e:
        return [], str(e)


# --------------------------------------------------------------------------
# Scan: nmap
# --------------------------------------------------------------------------

def nmap_available():
    return shutil.which("nmap") is not None


def run_nmap(host, top_ports):
    """Run nmap -sV against host, returning XML text or None on failure."""
    cmd = ["nmap", "-sV", "--top-ports", str(top_ports), "-oX", "-", host]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=max(120, top_ports * 3)
        )
    except FileNotFoundError:
        console.print("[yellow][!] nmap binary not found on PATH.[/yellow]")
        return None
    except subprocess.TimeoutExpired:
        console.print("[yellow][!] nmap scan timed out.[/yellow]")
        return None
    except Exception as e:
        console.print(f"[yellow][!] nmap execution failed: {e}[/yellow]")
        return None

    if result.returncode != 0 and not result.stdout.strip():
        stderr = result.stderr.strip() or "unknown error"
        console.print(f"[yellow][!] nmap exited with an error: {stderr}[/yellow]")
        return None

    if not result.stdout.strip():
        console.print("[yellow][!] nmap returned no output.[/yellow]")
        return None

    return result.stdout


def parse_nmap_xml(xml_text):
    """Parse nmap XML output into a list of open-port service dicts."""
    services = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        console.print(f"[yellow][!] Could not parse nmap output: {e}[/yellow]")
        return services

    for host_el in root.findall("host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            name = product = version = ""
            if service_el is not None:
                name = service_el.get("name", "") or ""
                product = service_el.get("product", "") or ""
                version = service_el.get("version", "") or ""

            try:
                port_num = int(port_el.get("portid"))
            except (TypeError, ValueError):
                continue

            services.append(
                {
                    "port": port_num,
                    "protocol": port_el.get("protocol", "tcp"),
                    "service": name,
                    "product": product,
                    "version": version,
                }
            )

    services.sort(key=lambda s: s["port"])
    return services


# --------------------------------------------------------------------------
# CVE matching: NVD
# --------------------------------------------------------------------------

def severity_from_score(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def extract_cvss(metrics):
    """Pull (score, severity) from an NVD metrics block, preferring v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss_data = entry.get("cvssData", {})
        score = cvss_data.get("baseScore")
        if score is None:
            continue
        severity = cvss_data.get("baseSeverity") or entry.get("baseSeverity")
        if not severity:
            severity = severity_from_score(score)
        return float(score), severity.upper()
    return None, "UNKNOWN"


def nvd_lookup(keyword, api_key):
    """Query the NVD keyword search API. Returns a list of finding dicts."""
    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": keyword, "resultsPerPage": 20}

    try:
        resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=20)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        console.print(f"[yellow][!] NVD lookup failed for '{keyword}': {e}[/yellow]")
        return []

    try:
        data = resp.json()
    except ValueError:
        console.print(f"[yellow][!] NVD returned unparseable data for '{keyword}'.[/yellow]")
        return []

    findings = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        score, severity = extract_cvss(cve.get("metrics", {}))
        findings.append(
            {
                "id": cve_id,
                "score": score,
                "severity": severity,
                "description": description,
            }
        )
    return findings


def gather_findings(services, api_key):
    """Run NVD lookups for every service that has both product and version."""
    candidates = [s for s in services if s["product"] and s["version"]]
    if not candidates:
        return []

    sleep_time = 0.8 if api_key else 6.0
    findings = []

    for i, svc in enumerate(candidates):
        keyword = f"{svc['product']} {svc['version']}".strip()
        console.print(f"  [dim]-> querying NVD for[/dim] [{ORANGE}]{keyword}[/{ORANGE}]")
        results = nvd_lookup(keyword, api_key)
        for r in results:
            r["port"] = svc["port"]
            r["service_label"] = f"{svc['service'] or 'unknown'} ({keyword})"
        findings.extend(results)

        if i < len(candidates) - 1:
            time.sleep(sleep_time)

    findings.sort(key=lambda f: f["score"] if f["score"] is not None else -1, reverse=True)
    return findings


# --------------------------------------------------------------------------
# Terminal output
# --------------------------------------------------------------------------

def print_services_table(services):
    table = Table(title="Open Services", border_style=ORANGE, header_style=f"bold {ORANGE}")
    table.add_column("Port")
    table.add_column("Proto")
    table.add_column("Service")
    table.add_column("Product")
    table.add_column("Version")

    if not services:
        console.print("[yellow]No open ports/services detected.[/yellow]")
        return

    for s in services:
        table.add_row(
            str(s["port"]), s["protocol"], s["service"] or "-", s["product"] or "-", s["version"] or "-"
        )
    console.print(table)


def print_findings_table(findings):
    if not findings:
        console.print("[yellow]No CVE findings.[/yellow]")
        return

    table = Table(title="CVE Findings", border_style=ORANGE, header_style=f"bold {ORANGE}")
    table.add_column("Severity")
    table.add_column("CVE ID")
    table.add_column("Score")
    table.add_column("Service")
    table.add_column("Description", overflow="fold", max_width=60)

    for f in findings:
        style = SEVERITY_STYLES.get(f["severity"], SEVERITY_STYLES["UNKNOWN"])
        score_str = f"{f['score']:.1f}" if f["score"] is not None else "-"
        table.add_row(
            Text(f["severity"], style=style),
            f["id"],
            score_str,
            f.get("service_label", "-"),
            f["description"],
        )
    console.print(table)


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

def render_html(host, ips, timestamp, services, findings, nmap_ok, cve_enabled):
    esc = html.escape

    ip_str = ", ".join(ips) if ips else "unresolved"

    services_rows = ""
    if services:
        for s in services:
            services_rows += (
                "<tr>"
                f"<td>{esc(str(s['port']))}</td>"
                f"<td>{esc(s['protocol'])}</td>"
                f"<td>{esc(s['service'] or '-')}</td>"
                f"<td>{esc(s['product'] or '-')}</td>"
                f"<td>{esc(s['version'] or '-')}</td>"
                "</tr>"
            )
    else:
        reason = "nmap was unavailable or the scan failed" if not nmap_ok else "no open ports were found"
        services_rows = f'<tr><td colspan="5" class="empty">No services detected ({esc(reason)}).</td></tr>'

    findings_rows = ""
    if findings:
        for f in findings:
            severity = f["severity"]
            fg, bg = SEVERITY_BADGE_COLORS.get(severity, SEVERITY_BADGE_COLORS["UNKNOWN"])
            score_str = f"{f['score']:.1f}" if f["score"] is not None else "-"
            cve_id = esc(f["id"])
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            findings_rows += (
                "<tr>"
                f'<td><span class="badge" style="color:{fg};background:{bg};border-color:{fg};">{esc(severity)}</span></td>'
                f'<td><a href="{link}" target="_blank" rel="noopener noreferrer">{cve_id}</a></td>'
                f"<td>{esc(score_str)}</td>"
                f"<td>{esc(f.get('service_label', '-'))}</td>"
                f"<td>{esc(f['description'])}</td>"
                "</tr>"
            )
    else:
        if not cve_enabled:
            reason = "CVE lookup was skipped (--no-cve)."
        else:
            reason = "no CVEs were matched for the detected services."
        findings_rows = f'<tr><td colspan="5" class="empty">{esc(reason)}</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HEV-Scan Report - {esc(host)}</title>
<style>
  :root {{
    --bg: #0a0a0a;
    --panel: #121212;
    --border: #2a2a2a;
    --orange: #ff6b00;
    --text: #e6e6e6;
    --dim: #8a8a8a;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: "Consolas", "Courier New", monospace;
    margin: 0;
    padding: 2rem;
    line-height: 1.5;
  }}
  header {{
    border: 1px solid var(--orange);
    border-radius: 6px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 2rem;
    background: linear-gradient(180deg, rgba(255,107,0,0.08), transparent);
  }}
  header h1 {{
    margin: 0 0 0.5rem 0;
    color: var(--orange);
    font-size: 1.6rem;
    letter-spacing: 0.05em;
  }}
  header .meta {{ color: var(--dim); font-size: 0.9rem; }}
  header .meta span {{ color: var(--text); }}
  h2 {{
    color: var(--orange);
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.4rem;
    margin-top: 2.5rem;
    font-size: 1.15rem;
    letter-spacing: 0.03em;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--panel);
    border: 1px solid var(--border);
    margin-top: 1rem;
  }}
  th, td {{
    text-align: left;
    padding: 0.55rem 0.75rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem;
    vertical-align: top;
  }}
  th {{
    color: var(--orange);
    text-transform: uppercase;
    font-size: 0.78rem;
    letter-spacing: 0.05em;
    border-bottom: 1px solid var(--orange);
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,107,0,0.05); }}
  td.empty {{ color: var(--dim); text-align: center; padding: 1.25rem; }}
  a {{ color: var(--orange); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .badge {{
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 3px;
    border: 1px solid;
    font-size: 0.75rem;
    font-weight: bold;
    letter-spacing: 0.04em;
  }}
  footer {{
    margin-top: 3rem;
    color: var(--dim);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    padding-top: 1rem;
  }}
</style>
</head>
<body>
<header>
  <h1>HEV-Scan Report</h1>
  <div class="meta">Target: <span>{esc(host)}</span> &nbsp;|&nbsp; Resolved IP(s): <span>{esc(ip_str)}</span></div>
  <div class="meta">Generated: <span>{esc(timestamp)}</span></div>
</header>

<h2>Open Services</h2>
<table>
  <thead>
    <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>
  </thead>
  <tbody>
    {services_rows}
  </tbody>
</table>

<h2>CVE Findings (sorted by severity)</h2>
<table>
  <thead>
    <tr><th>Severity</th><th>CVE ID</th><th>CVSS</th><th>Service</th><th>Description</th></tr>
  </thead>
  <tbody>
    {findings_rows}
  </tbody>
</table>

<footer>
  Generated by HEV-Scan v{esc(VERSION)} - CYFOR / Cyber Fort. CVE data from the NVD keyword search API is fuzzy,
  not exact CPE matching; treat findings as leads for manual verification, not ground truth.
</footer>
</body>
</html>
"""


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="hev-scan",
        description="HEV-Scan: Host Enumeration & Vulnerability Scanner - "
        "recon-to-risk pipeline for authorized security testing.",
    )
    parser.add_argument("host", nargs="?", default=None, help="target hostname or IP")
    parser.add_argument(
        "-o", "--output", default="hev_report.html", help="HTML report path (default: hev_report.html)"
    )
    parser.add_argument(
        "-p", "--top-ports", type=int, default=100, help="number of top ports for nmap to scan (default: 100)"
    )
    parser.add_argument("--no-cve", action="store_true", help="skip NVD CVE lookups, scan only")
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    print_banner()

    host = args.host
    if not host:
        try:
            host = console.input(f"[bold {ORANGE}]Target host or IP:[/bold {ORANGE}] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]No target provided. Exiting.[/yellow]")
            sys.exit(1)
        if not host:
            console.print("[red]No target provided. Exiting.[/red]")
            sys.exit(1)

    with console.status(f"[{ORANGE}]Resolving {host}...[/{ORANGE}]", spinner="dots"):
        ips, dns_error = resolve_host(host)
    if dns_error:
        console.print(f"[yellow][!] Could not resolve {host}: {dns_error} - continuing with hostname as-is.[/yellow]")
    else:
        console.print(f"[green][OK][/green] Resolved {host} -> {', '.join(ips)}")

    services = []
    nmap_ok = nmap_available()
    if not nmap_ok:
        console.print("[yellow][!] nmap not found on PATH - skipping port scan. Install nmap to enable service detection.[/yellow]")
    else:
        with console.status(f"[{ORANGE}]Scanning {host} (top {args.top_ports} ports)...[/{ORANGE}]", spinner="dots"):
            xml_text = run_nmap(host, args.top_ports)
        if xml_text:
            services = parse_nmap_xml(xml_text)
            console.print(f"[green][OK][/green] Found {len(services)} open port(s).")

    console.print()
    print_services_table(services)

    findings = []
    api_key = os.environ.get("NVD_API_KEY")
    if args.no_cve:
        console.print("\n[dim]Skipping CVE lookup (--no-cve).[/dim]")
    else:
        candidates = [s for s in services if s["product"] and s["version"]]
        if candidates:
            console.print(f"\n[{ORANGE}]Querying NVD for {len(candidates)} versioned service(s)...[/{ORANGE}]")
            if not api_key:
                console.print("[dim]  (no NVD_API_KEY set - using the unauthenticated rate limit)[/dim]")
            findings = gather_findings(services, api_key)
        else:
            console.print("\n[dim]No services with both product and version detected - skipping CVE lookup.[/dim]")

    console.print()
    print_findings_table(findings)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_html = render_html(host, ips, timestamp, services, findings, nmap_ok, not args.no_cve)

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_html)
        console.print(f"\n[green][OK][/green] Report written to [bold {ORANGE}]{args.output}[/bold {ORANGE}]")
    except OSError as e:
        console.print(f"\n[red][FAIL] Failed to write report to {args.output}: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
