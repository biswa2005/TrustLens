"""Immutable TLS analysis results and status contracts."""
from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChainStatus(StrEnum):
    VALID_TRUSTED = "valid_trusted"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    SIGNATURE_INVALID = "signature_invalid"
    PATH_CONSTRAINT_VIOLATED = "path_constraint_violated"
    SELF_SIGNED = "self_signed"
    UNTRUSTED_ROOT = "untrusted_root"
    INCOMPLETE_CHAIN = "incomplete_chain"
    INCONCLUSIVE = "inconclusive"
    RESOURCE_LIMIT_EXCEEDED = "resource_limit_exceeded"


class HostnameStatus(StrEnum):
    MATCHED = "matched"
    MISMATCHED = "mismatched"
    MISSING_SAN_MISMATCHED = "missing_san_mismatched"
    MISSING_SAN_IP_MISMATCHED = "missing_san_ip_mismatched"
    IP_MISMATCH = "ip_mismatch"
    PUBLIC_SUFFIX_WILDCARD_REJECTED = "public_suffix_wildcard_rejected"
    INVALID_TARGET = "invalid_target"
    NOT_EVALUATED = "not_evaluated"


class CADistrustClassification(StrEnum):
    """TRUSTED means no match in the recorded dataset version, not universal trust."""
    TRUSTED = "trusted"
    DISTRUSTED = "distrusted"
    COMPROMISED = "compromised"
    NOT_EVALUATED = "not_evaluated"


class RevocationStatus(StrEnum):
    NOT_EVALUATED = "not_evaluated"
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


class TrustVerdict(StrEnum):
    VALID = "valid"
    CONFIGURATION_ISSUES = "configuration_issues"
    INVALID = "invalid"
    UNTRUSTED = "untrusted"
    INCOMPLETE = "incomplete"
    INCONCLUSIVE = "inconclusive"
    DISTRUSTED = "distrusted"
    COMPROMISED = "compromised"


class TLSProbeErrorKind(StrEnum):
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    RESOURCE_LIMIT = "resource_limit"
    CONNECTION_REFUSED = "connection_refused"
    DNS_FAILURE = "dns_failure"
    HANDSHAKE_FAILED = "handshake_failed"
    INTERNAL_ERROR = "internal_error"
    UNSUPPORTED_SCOPE = "unsupported_scope"


class CertificateDetails(BaseModel):
    model_config = ConfigDict(frozen=True)
    subject: str
    issuer: str
    serial_number: str
    fingerprint_sha256: str | None = None
    spki_sha256: str | None = None
    not_before: datetime
    not_after: datetime
    san_dns: tuple[str, ...] = ()
    san_ip: tuple[str, ...] = ()
    key_usage: tuple[str, ...] = ()
    public_key_algorithm: str = "unknown"
    public_key_size: int | None = None
    signature_hash: str | None = None
    is_ca: bool = False


class TLSReport(BaseModel):
    model_config = ConfigDict(frozen=True)
    canonical_authority: str
    target_kind: Literal["input", "final_destination"]
    probe_ok: bool
    probe_error_kind: str | None = None
    probe_error_detail: str | None = None
    limitations: tuple[str, ...] = ()
    trust_store_version: str | None = None
    distrust_dataset_version: str | None = None
    chain_status: ChainStatus = ChainStatus.INCONCLUSIVE
    hostname_status: HostnameStatus = HostnameStatus.NOT_EVALUATED
    distrust: CADistrustClassification = CADistrustClassification.NOT_EVALUATED
    revocation: RevocationStatus = RevocationStatus.NOT_EVALUATED
    trust_verdict: TrustVerdict = TrustVerdict.INCONCLUSIVE
    transport_eligibility: bool = False
    certificates: tuple[CertificateDetails, ...] = ()
    findings: tuple[str, ...] = ()
    negotiated_protocol: str | None = None
    negotiated_cipher: str | None = None
    ct_status: str = "not_evaluated"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def inconclusive_report(host: str, port: int, kind: str, reason: str,
                        target_kind: Literal["input", "final_destination"]) -> TLSReport:
    from links.services.authority import canonical_authority
    return TLSReport(canonical_authority=canonical_authority(host, port), target_kind=target_kind,
                     probe_ok=False, probe_error_kind=kind, probe_error_detail=reason[:120],
                     limitations=(reason[:120],))
