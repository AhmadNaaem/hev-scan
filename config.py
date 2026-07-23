"""HEV-Scan constants: version, endpoints, rate limits, colour maps."""

VERSION = "1.0.0"
ORANGE = "#ff6b00"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_DELAY_WITH_KEY = 0.8
NVD_DELAY_WITHOUT_KEY = 6.0

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
