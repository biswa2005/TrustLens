from __future__ import annotations

import ipaddress
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.verification import DNSName, IPAddress, PolicyBuilder, Store, VerificationError

from links.models_tls import ChainStatus
from links.services.tls.signature_verifier import verify_certificate_signature
from links.services.tls.trust_store import TrustStore


def _spki_hash(cert: x509.Certificate) -> bytes:
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).digest()


def _aki_ski_agree(cert: x509.Certificate, root: x509.Certificate) -> bool:
    try:
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    except x509.ExtensionNotFound:
        aki = None
    try:
        ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        ski = None
    return aki is None or ski is None or aki == ski


def _find_anchor(path: list[x509.Certificate], store: TrustStore):
    """Return the first supplied trust anchor or direct child of a store root."""
    root_spki = {_spki_hash(root) for root in store.certs}
    for index, cert in enumerate(path):
        fingerprint = cert.fingerprint(hashes.SHA256())
        if fingerprint in store.fingerprints:
            return index, store.store
        if _spki_hash(cert) in root_spki:
            # Trust the supplied cross-certificate at this boundary.  Its key
            # is already represented by a certificate in the configured store.
            return index, Store([*store.certs, cert])
        issuer_der = cert.issuer.public_bytes()
        if any(root.subject.public_bytes() == issuer_der and _aki_ski_agree(cert, root)
               for root in store.certs):
            return index, store.store
    return None


def validate_chain(leaf: x509.Certificate, supplied: list[x509.Certificate], host: str, now, store: TrustStore):
    path = [leaf]
    used = {leaf.fingerprint(hashes.SHA256())}
    while True:
        child = path[-1]
        parent = next((c for c in supplied if c.subject == child.issuer and
                       c.fingerprint(hashes.SHA256()) not in used), None)
        if parent is None:
            break
        path.append(parent); used.add(parent.fingerprint(hashes.SHA256()))
        if len(path) > 10:
            return ChainStatus.RESOURCE_LIMIT_EXCEEDED, {"reason": "chain_depth"}

    anchor = _find_anchor(path, store)
    if anchor is not None:
        anchor_index, verifier_store = anchor
        path = path[:anchor_index + 1]

    for index, cert in enumerate(path):
        if now < cert.not_valid_before_utc: return ChainStatus.NOT_YET_VALID, {"index": index}
        if now > cert.not_valid_after_utc: return ChainStatus.EXPIRED, {"index": index}
    for index, (child, parent) in enumerate(zip(path, path[1:])):
        signature = verify_certificate_signature(child, parent)
        if signature == "invalid": return ChainStatus.SIGNATURE_INVALID, {"index": index}
        if signature == "unsupported": return ChainStatus.INCONCLUSIVE, {"reason": "unsupported_algorithm", "index": index}
    top = path[-1]
    if top.subject == top.issuer:
        signature = verify_certificate_signature(top, top)
        if signature == "invalid": return ChainStatus.SIGNATURE_INVALID, {"reason": "self_issued_not_self_signed"}
        if signature == "unsupported": return ChainStatus.INCONCLUSIVE, {"reason": "unsupported_algorithm"}
    cas = path[1:]
    for index, ca in enumerate(cas, start=1):
        try: constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound: return ChainStatus.PATH_CONSTRAINT_VIOLATED, {"index": index, "reason": "no_basic_constraints"}
        if not constraints.ca: return ChainStatus.PATH_CONSTRAINT_VIOLATED, {"index": index, "reason": "not_a_ca"}
        if constraints.path_length is not None and constraints.path_length < index - 1:
            return ChainStatus.PATH_CONSTRAINT_VIOLATED, {"index": index, "reason": "path_length_exceeded"}
        try:
            usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
            if not usage.key_cert_sign: return ChainStatus.PATH_CONSTRAINT_VIOLATED, {"index": index, "reason": "no_key_cert_sign"}
        except x509.ExtensionNotFound: pass
    if anchor is None:
        return (ChainStatus.SELF_SIGNED if len(path) == 1 and top.subject == top.issuer
                else ChainStatus.UNTRUSTED_ROOT if top.subject == top.issuer
                else ChainStatus.INCOMPLETE_CHAIN), {"issuer": top.issuer.rfc4514_string()}
    identity = IPAddress(ipaddress.ip_address(host)) if _is_ip(host) else DNSName(host)
    anchor_index, verifier_store = anchor
    if path[anchor_index].fingerprint(hashes.SHA256()) in store.fingerprints:
        intermediates = path[1:anchor_index]
    elif _spki_hash(path[anchor_index]) in {_spki_hash(root) for root in store.certs}:
        intermediates = path[1:anchor_index]
    else:
        intermediates = path[1:]
    try:
        verifier = PolicyBuilder().store(verifier_store).time(now).build_server_verifier(identity)
        verifier.verify(leaf, intermediates)
    except VerificationError as exc:
        return ChainStatus.INCONCLUSIVE, {"reason": type(exc).__name__}
    except (ValueError, TypeError) as exc:
        return ChainStatus.INCONCLUSIVE, {"reason": type(exc).__name__}
    return ChainStatus.VALID_TRUSTED, {"reason": "ok"}


def _is_ip(host: str) -> bool:
    try: ipaddress.ip_address(host.strip("[]")); return True
    except ValueError: return False
