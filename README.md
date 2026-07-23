# HEV-Scan — Host Enumeration & Vulnerability Scanner

HEV-Scan is a modular CLI recon-to-risk pipeline: it resolves a host,
scans its services with `nmap`, matches detected software against known
CVEs via the NVD API, and renders the results as a self-contained HTML
report. Built for a defensive/educational security course — run it against
hosts you own or are explicitly authorized to test, such as your own lab VM.

## Features

- DNS resolution of the target hostname (warns and continues if it fails)
- `nmap -sV` service/version detection over the top N ports, parsed from XML
- CVE matching against the NVD `keywordSearch` API for services with a
  known product + version, respecting NVD rate limits
- Findings sorted across all services by CVSS score, highest first
- Dark, terminal-styled, self-contained HTML report (no external assets)
- Colorized `rich` output in the terminal: status spinners between phases
  plus severity-coded tables, in addition to the HTML file
- Graceful degradation: missing `nmap`, failed DNS, NVD errors, or
  unparseable scan output all produce a warning instead of a crash

## Prerequisites

- Python 3
- [`nmap`](https://nmap.org/) installed and on your `PATH` (ships with Kali
  by default). If it's missing, HEV-Scan will warn and skip the port scan
  rather than crash.

## Install

```bash
git clone <this-repo-url>
cd hev-scan
pip install -r requirements.txt
```

Recent Kali (and other externally-managed Python installs) will refuse a
system-wide `pip install` with an `externally-managed-environment` error.
Either use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

or override the guard directly:

```bash
pip install -r requirements.txt --break-system-packages
```

## Optional: NVD API key

NVD's public keyword search API works without a key at 5 requests/30s.
Set `NVD_API_KEY` to raise that to 50 requests/30s and speed up scans with
many services:

```bash
export NVD_API_KEY=your-key-here
```

Request a key at <https://nvd.nist.gov/developers/request-an-api-key>. The
key is only ever read from the environment — never hardcode it.

## Usage

```bash
python3 hev_scan.py <host>
```

If `host` is omitted, HEV-Scan prompts for it interactively.

```
positional arguments:
  host                  target hostname or IP

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   HTML report path (default: hev_report.html)
  -p, --top-ports TOP_PORTS
                        number of top ports for nmap to scan (default: 100)
  --no-cve              skip NVD CVE lookups, scan only
```

Examples:

```bash
# Scan a lab VM with defaults, write hev_report.html
python3 hev_scan.py 192.168.56.10

# Scan the top 1000 ports and write to a custom path
python3 hev_scan.py testvm.local -p 1000 -o testvm_report.html

# Port/service scan only, no NVD lookups
python3 hev_scan.py 192.168.56.10 --no-cve
```
