"""Canonical authority formatting shared with the host analyzer."""
import ipaddress

import idna


def canonical_authority(host: str, port: int = 443) -> str:
    """Return lower-case IDNA host or IP, always including port."""
    h = host.strip().rstrip(".")
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
        return f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
    except ValueError:
        return f"{idna.encode(h.lower(), uts46=True).decode('ascii')}:{port}"
