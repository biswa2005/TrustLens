from __future__ import annotations

import ipaddress

import idna
import tldextract
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from links.models_tls import HostnameStatus

_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)


def verify_hostname(cert: x509.Certificate, host: str):
    try:
        target_ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        target_ip = None
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return HostnameStatus.MISSING_SAN_IP_MISMATCHED if target_ip else HostnameStatus.MISSING_SAN_MISMATCHED, {}
    if target_ip:
        ips = san.get_values_for_type(x509.IPAddress)
        return (HostnameStatus.MATCHED if target_ip in ips else HostnameStatus.IP_MISMATCH,
                {"target": str(target_ip), "san_ip_count": len(ips)})
    try:
        target = idna.encode(host.rstrip(".").lower(), uts46=True).decode("ascii")
    except idna.IDNAError:
        return HostnameStatus.INVALID_TARGET, {"target": host}
    dns_sans = san.get_values_for_type(x509.DNSName)
    rejected = []
    for raw in dns_sans:
        pattern = raw.strip().lower().rstrip(".")
        if pattern.startswith("*."):
            base = pattern[2:]
            if not base or "*" in base:
                continue
            reg = _extract(base)
            if not reg.domain and reg.suffix:
                rejected.append(pattern)
                continue
            suffix = "." + base
            if target.endswith(suffix) and target.count(".") == base.count(".") + 1:
                return HostnameStatus.MATCHED, {"target": target}
        elif "*" not in pattern:
            try:
                if idna.encode(pattern, uts46=True).decode("ascii") == target:
                    return HostnameStatus.MATCHED, {"target": target}
            except idna.IDNAError:
                continue
    if rejected:
        return HostnameStatus.PUBLIC_SUFFIX_WILDCARD_REJECTED, {"target": target, "rejected": rejected}
    return HostnameStatus.MISMATCHED, {"target": target, "sans": dns_sans}
