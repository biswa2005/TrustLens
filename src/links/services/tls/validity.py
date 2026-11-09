from datetime import date, datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


def maximum_public_lifetime(not_before: datetime) -> int:
    issued = not_before.date()
    if issued < date(2026, 3, 15): return 398
    if issued < date(2027, 3, 15): return 200
    if issued < date(2029, 3, 15): return 100
    return 47


def excessive_lifetime(leaf: x509.Certificate, *, chain_trusted: bool, is_ca: bool | None = None,
                       now: datetime | None = None):
    if not chain_trusted:
        return None
    try:
        ca = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        ca = bool(is_ca)
    if ca:
        return None
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            return None
    except x509.ExtensionNotFound:
        pass
    start, end = leaf.not_valid_before_utc, leaf.not_valid_after_utc
    measured = end - start
    limit = timedelta(days=maximum_public_lifetime(start))
    if measured <= limit:
        return None
    return {"measured_seconds": measured.total_seconds(), "limit_days": limit.days,
            "policy": "cabf-br-validity-schedule@2026-11-09"}
