"""Fail-closed TLS trust verdict decision table."""
from links.models_tls import (CADistrustClassification as D, ChainStatus as C,
                              HostnameStatus as H, RevocationStatus as R,
                              TrustVerdict as V)

_INVALID_CHAIN = {C.NOT_YET_VALID, C.EXPIRED, C.SIGNATURE_INVALID, C.PATH_CONSTRAINT_VIOLATED}
_BAD_HOST = {H.MISMATCHED, H.MISSING_SAN_MISMATCHED, H.MISSING_SAN_IP_MISMATCHED,
             H.IP_MISMATCH, H.PUBLIC_SUFFIX_WILDCARD_REJECTED}
_BROKEN = {"broken_key_size", "broken_hash"}
_WEAK = {"weak_key_size", "legacy_hash", "excessive_validity_period"}


def compute_trust_verdict(*, chain, hostname, revocation, distrust, fired: set[str]):
    if distrust == D.COMPROMISED: return V.COMPROMISED
    if distrust == D.DISTRUSTED: return V.DISTRUSTED
    if revocation == R.REVOKED: return V.INVALID
    if chain in _INVALID_CHAIN: return V.INVALID
    if hostname in _BAD_HOST: return V.INVALID
    if fired & _BROKEN: return V.INVALID
    if chain in (C.SELF_SIGNED, C.UNTRUSTED_ROOT): return V.UNTRUSTED
    if chain == C.INCOMPLETE_CHAIN: return V.INCOMPLETE
    if chain in (C.INCONCLUSIVE, C.RESOURCE_LIMIT_EXCEEDED) or "unsupported_algorithm" in fired:
        return V.INCONCLUSIVE
    if hostname in (H.INVALID_TARGET, H.NOT_EVALUATED): return V.INCONCLUSIVE
    if distrust == D.NOT_EVALUATED: return V.INCONCLUSIVE
    if chain != C.VALID_TRUSTED or hostname != H.MATCHED: return V.INCONCLUSIVE
    if fired & _WEAK: return V.CONFIGURATION_ISSUES
    return V.VALID
