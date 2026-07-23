"""nmap invocation and XML parsing for HEV-Scan."""

import shutil
import subprocess
from xml.etree import ElementTree as ET

from ui import console


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
