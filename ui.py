"""Banner rendering and terminal table output for HEV-Scan."""

import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config import ORANGE, VERSION, SEVERITY_STYLES

LOGO_ART = r"""
       ################
    #####    ############
   ##    ##      ########
 ###      ##       #####
 ##       ###      ####
 ##      #####      ###
 ##    ###  ###    ###
 ###  ###    ####  ##
   ###           ###
     #####  ######
        ######
""".strip("\n")

console = Console()


# --------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------

def print_banner():
    art_lines = LOGO_ART.splitlines()
    for line in art_lines:
        console.print(line, style=f"bold {ORANGE}", markup=False, highlight=False)

    art_width = max(len(line) for line in art_lines)
    version_text = f"v{VERSION}"
    padding = max(0, (art_width - len(version_text)) // 2)
    console.print(" " * padding + version_text, style=f"bold {ORANGE}", markup=False, highlight=False)
    console.print()

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
