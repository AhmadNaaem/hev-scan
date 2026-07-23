"""HTML report generation for HEV-Scan."""

import html

from config import VERSION, SEVERITY_BADGE_COLORS


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
