"""Host resolution for HEV-Scan."""

import socket


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
