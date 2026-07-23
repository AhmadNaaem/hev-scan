#!/usr/bin/env python3
"""HEV-Scan: Host Enumeration & Vulnerability Scanner.

Recon-to-risk CLI: resolves a host, scans it with nmap, matches detected
services against known CVEs via the NVD API, and renders a self-contained
HTML report. Built for defensive/educational use against systems you own
or are authorized to test.
"""

import argparse
import os
import sys
from datetime import datetime, timezone

import recon
import scanner
import vulndb
import report
from config import ORANGE
from ui import console, print_banner, print_services_table, print_findings_table


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
        ips, dns_error = recon.resolve_host(host)
    if dns_error:
        console.print(f"[yellow][!] Could not resolve {host}: {dns_error} - continuing with hostname as-is.[/yellow]")
    else:
        console.print(f"[green][OK][/green] Resolved {host} -> {', '.join(ips)}")

    services = []
    nmap_ok = scanner.nmap_available()
    if not nmap_ok:
        console.print("[yellow][!] nmap not found on PATH - skipping port scan. Install nmap to enable service detection.[/yellow]")
    else:
        with console.status(f"[{ORANGE}]Scanning {host} (top {args.top_ports} ports)...[/{ORANGE}]", spinner="dots"):
            xml_text = scanner.run_nmap(host, args.top_ports)
        if xml_text:
            services = scanner.parse_nmap_xml(xml_text)
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
            findings = vulndb.gather_findings(services, api_key)
        else:
            console.print("\n[dim]No services with both product and version detected - skipping CVE lookup.[/dim]")

    console.print()
    print_findings_table(findings)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_html = report.render_html(host, ips, timestamp, services, findings, nmap_ok, not args.no_cve)

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
