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
    classification: str
    fingerprint: bytes
    spki_hash: bytes
    entity: str
    scope: dict


@dataclass(frozen=True)
class DistrustDataset:
    version: str
    records: tuple[DistrustRecord, ...]


def load_dataset(root: Path = DATA) -> DistrustDataset:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    records = []
    for item in manifest.get("records", []):
        try:
            cert = x509.load_pem_x509_certificate((root / item["cert_file"]).read_bytes())
            fingerprint = cert.fingerprint(hashes.SHA256())
            expected = bytes.fromhex(item["expected_cert_sha256"].replace(":", ""))
            if fingerprint != expected:
                log.error("CA distrust record rejected: fingerprint mismatch for %s", item.get("id", "unknown"))
                continue
            spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            records.append(DistrustRecord(item["classification"], fingerprint,
                                          hashlib.sha256(spki).digest(), item["entity"], item.get("scope", {"type": "all"})))
        except (OSError, KeyError, ValueError, TypeError):
            log.exception("CA distrust record rejected: invalid record")
    version = f"{manifest['version']}+{len(records)}-verified"
    return DistrustDataset(version, tuple(records))
