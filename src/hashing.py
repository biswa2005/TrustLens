import hashlib
import json
import secrets
from typing import Any, Dict


def canonicalize(payload: Dict[str, Any]) -> str:
    """Deterministic canonical JSON representation."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_nonce() -> str:
    return secrets.token_hex(32)


def fingerprint(payload: Dict[str, Any], nonce: str) -> str:
    """SHA-256 commitment (32 bytes as hex) of a threat report payload."""
    body = dict(payload)
    body["_nonce"] = nonce
    canonical = canonicalize(body)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def to_bytes32(hexdigest: str) -> bytes:
    if len(hexdigest) != 64:
        raise ValueError("expected 32-byte hex digest")
    return bytes.fromhex(hexdigest)
