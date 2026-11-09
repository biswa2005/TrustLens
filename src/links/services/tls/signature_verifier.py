from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, ed25519


def verify_certificate_signature(child, parent) -> str:
    """Tri-state certificate signature check: valid, invalid, unsupported."""
    try:
        key = parent.public_key()
        signature = child.signature
        data = child.tbs_certificate_bytes
        algorithm = child.signature_hash_algorithm
        if isinstance(key, rsa.RSAPublicKey):
            params = getattr(child, "signature_algorithm_parameters", None)
            key.verify(signature, data, params or padding.PKCS1v15(), algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, ec.ECDSA(algorithm))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, data)
        else:
            return "unsupported"
        return "valid"
    except InvalidSignature:
        return "invalid"
    except (UnsupportedAlgorithm, ValueError, TypeError, AttributeError):
        return "unsupported"
