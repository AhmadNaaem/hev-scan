"""NVD querying and CVSS extraction for HEV-Scan."""

import time

import requests

from config import NVD_API_URL, NVD_DELAY_WITH_KEY, NVD_DELAY_WITHOUT_KEY, ORANGE
from ui import console


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

    sleep_time = NVD_DELAY_WITH_KEY if api_key else NVD_DELAY_WITHOUT_KEY
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
