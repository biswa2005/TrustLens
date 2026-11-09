from __future__ import annotations

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import SignatureAlgorithmOID


def inspect_crypto(cert, *, is_anchor: bool = False) -> list[tuple[str, dict]]:
    findings = []
    try:
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            bits = key.key_size
            if bits < 1024: findings.append(("broken_key_size", {"algorithm": "RSA", "bits": bits}))
            elif bits < 2048: findings.append(("weak_key_size", {"algorithm": "RSA", "bits": bits}))
        elif isinstance(key, ec.EllipticCurvePublicKey):
            bits = key.curve.key_size
            if bits < 160: findings.append(("broken_key_size", {"algorithm": "EC", "bits": bits}))
            elif bits < 224: findings.append(("weak_key_size", {"algorithm": "EC", "bits": bits}))
        elif isinstance(key, dsa.DSAPublicKey):
            findings.append(("weak_key_size", {"algorithm": "DSA", "bits": key.key_size}))
        elif not isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            findings.append(("unsupported_algorithm", {"where": "public_key"}))
    except (UnsupportedAlgorithm, ValueError):
        findings.append(("unsupported_algorithm", {"where": "public_key"}))
    if not is_anchor:
        try:
            algorithm = cert.signature_hash_algorithm
            if algorithm is None: return findings
            name = algorithm.name.lower()
            if name in {"md2", "md5"}: findings.append(("broken_hash", {"algorithm": name}))
            elif name == "sha1": findings.append(("legacy_hash", {"algorithm": name}))
        except (UnsupportedAlgorithm, ValueError):
            findings.append(("unsupported_algorithm", {"where": "signature_hash"}))
    return findings
