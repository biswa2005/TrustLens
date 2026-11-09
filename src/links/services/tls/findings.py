"""TLS finding contracts and severity mapping."""
from links.models import Finding

RULES = {
    "compromised_ca": ("strong", "reputation_ca", "reputation"),
    "distrusted_ca": ("strong", "reputation_ca", "reputation"),
    "signature_invalid": ("strong", "tls_trust", "infrastructure"),
    "broken_key_size": ("strong", "tls_trust", "infrastructure"),
    "broken_hash": ("strong", "tls_trust", "infrastructure"),
    "ocsp_revoked": ("strong", "tls_trust", "infrastructure"),
    "hostname_mismatch": ("moderate", "tls_trust", "infrastructure"),
    "cert_expired": ("moderate", "tls_trust", "infrastructure"),
    "cert_not_yet_valid": ("moderate", "tls_trust", "infrastructure"),
    "untrusted_root": ("moderate", "tls_trust", "infrastructure"),
    "self_signed": ("moderate", "tls_trust", "infrastructure"),
    "chain_incomplete": ("moderate", "tls_trust", "infrastructure"),
    "path_constraint_violated": ("moderate", "tls_trust", "infrastructure"),
    "weak_key_size": ("weak", "tls_trust", "infrastructure"),
    "legacy_hash": ("weak", "tls_trust", "infrastructure"),
    "excessive_validity_period": ("weak", "tls_trust", "infrastructure"),
    "unsupported_algorithm": ("moderate", "tls_trust", "infrastructure"),
    "resource_limit": ("moderate", "tls_trust", "infrastructure"),
    "ocsp_unauthenticated": ("info", "tls_trust", "infrastructure"),
    "ocsp_stale": ("info", "tls_trust", "infrastructure"),
    "ocsp_malformed": ("info", "tls_trust", "infrastructure"),
    "probe_error": ("info", "tls_trust", "infrastructure"),
}
EVIDENCE_GROUPS = {
    "tls_trust": {"class": "infrastructure", "rules": frozenset(rule for rule, value in RULES.items() if value[1] == "tls_trust")},
    "reputation_ca": {"class": "reputation", "rules": frozenset(rule for rule, value in RULES.items() if value[1] == "reputation_ca")},
}


def finding(rule: str, target: str, evidence: dict | None = None) -> Finding:
    severity, group, cls = RULES[rule]
    return Finding(id=f"tls_certificate.{rule}", check_id="tls_certificate", category="tls_certificate",
                   title=rule.replace("_", " ").capitalize(), severity=severity,
                   evidence_group=group, evidence_class=cls, target=target,
                   source="local-rules", evidence=evidence or {})
