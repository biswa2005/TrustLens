"""Load only CA distrust records whose committed certificate matches its manifest."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

log = logging.getLogger(__name__)
DATA = Path(__file__).resolve().parents[2] / "data" / "ca_distrust"


@dataclass(frozen=True)
class DistrustRecord:
    id: str
    classification: str
    fingerprint: bytes
    spki_hash: bytes
    entity: str
    scope: dict


@dataclass(frozen=True)
class DistrustDataset:
    version: str
    records: tuple[DistrustRecord, ...]


def validate_manifest(root: Path = DATA) -> dict:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for item in manifest.get("records", []):
        expected = str(item.get("expected_cert_sha256", "")).replace(":", "")
        if "<ENTER" in expected.upper() or len(expected) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in expected):
            raise ValueError(f"invalid or placeholder CA fingerprint for {item.get('id', 'unknown')}")
        if not item.get("cert_file") or not item.get("id"):
            raise ValueError("CA distrust record is missing its id or certificate file")
        if item.get("classification") not in {"compromised", "distrusted"}:
            raise ValueError(f"invalid CA distrust classification for {item.get('id', 'unknown')}")
    return manifest


def load_dataset(root: Path = DATA) -> DistrustDataset:
    manifest = validate_manifest(root)
    records = []
    for item in manifest.get("records", []):
        try:
            cert = x509.load_pem_x509_certificate((root / item["cert_file"]).read_bytes())
            fingerprint = cert.fingerprint(hashes.SHA256())
            expected = bytes.fromhex(item["expected_cert_sha256"].replace(":", ""))
            if fingerprint != expected:
                log.error("CA distrust record %s rejected: certificate fingerprint mismatch",
                          item.get("id", "unknown"))
                continue
            spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            records.append(DistrustRecord(item["id"], item["classification"], fingerprint,
                                          hashlib.sha256(spki).digest(), item["entity"], item.get("scope", {"type": "all"})))
        except (OSError, KeyError, ValueError, TypeError) as exc:
            log.exception("CA distrust dataset rejected: invalid record")
            raise ValueError("CA distrust dataset contains an invalid record") from exc
    version = f"{manifest['version']}+{len(records)}-verified"
    return DistrustDataset(version, tuple(records))


def matching_records(cert, dataset: DistrustDataset, *, leaf_not_before=None) -> tuple[DistrustRecord, ...]:
    fp = cert.fingerprint(hashes.SHA256())
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    spki_hash = hashlib.sha256(spki).digest()
    matches = []
    for record in dataset.records:
        if fp != record.fingerprint and spki_hash != record.spki_hash:
            continue
        scope = record.scope or {"type": "all"}
        if scope.get("type") == "leaf_not_before_gte":
            from datetime import date
            cutoff = date.fromisoformat(scope["cutoff"][:10])
            effective_leaf_date = (leaf_not_before or cert.not_valid_before_utc).date()
            if effective_leaf_date < cutoff:
                continue
        elif scope.get("type") != "all":
            continue
        matches.append(record)
    return tuple(matches)
