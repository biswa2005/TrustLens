from __future__ import annotations

from datetime import timedelta

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import ocsp

from links.models_tls import RevocationStatus

SKEW = timedelta(minutes=5)
MAX_AGE_NO_NEXT_UPDATE = timedelta(days=7)


def _key_bits(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return None


def _digest(algorithm, data: bytes) -> bytes:
    digest = hashes.Hash(algorithm); digest.update(data); return digest.finalize()


def _certid_matches(response, leaf, issuer) -> bool:
    try:
        key_bits = _key_bits(issuer.public_key())
        return (key_bits is not None and response.serial_number == leaf.serial_number
                and response.issuer_name_hash == _digest(response.hash_algorithm, issuer.subject.public_bytes())
                and response.issuer_key_hash == _digest(response.hash_algorithm, key_bits))
    except (UnsupportedAlgorithm, ValueError, TypeError):
        return False


def _responder_is_issuer(response, issuer) -> bool:
    if response.responder_name is not None:
        return response.responder_name == issuer.subject
    if response.responder_key_hash is not None:
        bits = _key_bits(issuer.public_key())
        return bits is not None and response.responder_key_hash == _digest(hashes.SHA1(), bits)
    return False


def _signature_ok(response, public_key) -> str:
    try:
        algorithm = response.signature_hash_algorithm
        if isinstance(public_key, rsa.RSAPublicKey):
            params = getattr(response, "signature_algorithm_parameters", None) or padding.PKCS1v15()
            public_key.verify(response.signature, response.tbs_response_bytes, params, algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(response.signature, response.tbs_response_bytes, ec.ECDSA(algorithm))
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(response.signature, response.tbs_response_bytes)
        else:
            return "unsupported"
        return "ok"
    except InvalidSignature:
        return "bad"
    except (UnsupportedAlgorithm, ValueError, TypeError, AttributeError):
        return "unsupported"


def evaluate_ocsp(staple: bytes | None, leaf: x509.Certificate,
                  chain: list[x509.Certificate], now):
    """Return status and optional informational/strong rule. Only direct issuer authenticates."""
    if not staple:
        return RevocationStatus.NOT_EVALUATED, None, {}
    try:
        response = ocsp.load_der_ocsp_response(staple)
    except (ValueError, UnsupportedAlgorithm):
        return RevocationStatus.UNAVAILABLE, "ocsp_malformed", {}
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return RevocationStatus.UNAVAILABLE, None, {"response_status": response.response_status.name}
    issuer = next((cert for cert in chain if cert.subject == leaf.issuer), None)
    if issuer is None:
        return RevocationStatus.UNAVAILABLE, None, {"reason": "issuer_not_present"}
    if not _certid_matches(response, leaf, issuer):
        return RevocationStatus.UNAVAILABLE, "ocsp_malformed", {"reason": "cert_id_mismatch"}
    try:
        produced, updated = response.produced_at_utc, response.this_update_utc
        next_update = response.next_update_utc
    except AttributeError:
        return RevocationStatus.UNAVAILABLE, "ocsp_malformed", {"reason": "freshness_fields_unavailable"}
    if produced > now + SKEW or updated > now + SKEW:
        return RevocationStatus.UNAVAILABLE, "ocsp_stale", {"reason": "future_update"}
    if next_update is not None and next_update < now - SKEW:
        return RevocationStatus.UNAVAILABLE, "ocsp_stale", {"reason": "expired_next_update"}
    if next_update is None and now - updated > MAX_AGE_NO_NEXT_UPDATE:
        return RevocationStatus.UNAVAILABLE, "ocsp_stale", {"reason": "old_without_next_update"}
    if response.certificates:
        return RevocationStatus.UNAVAILABLE, "ocsp_unauthenticated", {"reason": "delegated_responder_out_of_scope"}
    if not _responder_is_issuer(response, issuer):
        return RevocationStatus.UNAVAILABLE, "ocsp_unauthenticated", {"reason": "responder_not_issuer"}
    signature = _signature_ok(response, issuer.public_key())
    if signature != "ok":
        return RevocationStatus.UNAVAILABLE, "ocsp_unauthenticated", {"reason": f"signature_{signature}"}
    status = {
        ocsp.OCSPCertStatus.GOOD: RevocationStatus.GOOD,
        ocsp.OCSPCertStatus.REVOKED: RevocationStatus.REVOKED,
        ocsp.OCSPCertStatus.UNKNOWN: RevocationStatus.UNKNOWN,
    }[response.certificate_status]
    return status, "ocsp_revoked" if status == RevocationStatus.REVOKED else None, {}
