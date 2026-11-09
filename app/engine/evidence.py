"""Tamper-evident evidence ledger.

Every observation is chained with HMAC-SHA256 over the previous hash and a
canonical JSON representation of the evidence.  Verification recomputes the
whole chain, so a modified or re-ordered evidence item invalidates the report.
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.config import Settings, get_settings
from app.engine.utils import hmac_chain, new_id, sha256_text, stable_json
from app.schemas import Evidence, EvidenceKind


def verify_evidence_chain(evidence: list[Evidence], signing_key: bytes) -> tuple[bool, list[str]]:
    """Recompute the SHA-256 + HMAC chain for an arbitrary evidence list."""

    errors: list[str] = []
    prev = "GENESIS"
    for index, item in enumerate(evidence):
        payload = item.digest_payload()
        expected_sha = sha256_text(stable_json(payload))
        if item.sha256 != expected_sha:
            errors.append(
                f"Evidence {item.id} at index {index} has been modified (sha256 mismatch)."
            )
        if item.prev_hash != prev:
            errors.append(
                f"Evidence {item.id} at index {index} breaks the hash chain (prev_hash mismatch)."
            )
        expected_chain = hmac_chain(signing_key, prev, payload)
        if item.chain_hash != expected_chain:
            errors.append(
                f"Evidence {item.id} at index {index} has an invalid HMAC chain hash."
            )
        prev = item.chain_hash
    return (not errors, errors)


class EvidenceStore:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._items: list[Evidence] = []
        self._by_id: dict[str, Evidence] = {}
        self._last_hash = "GENESIS"

    def __len__(self) -> int:
        return len(self._items)

    @property
    def items(self) -> list[Evidence]:
        return list(self._items)

    def get(self, evidence_id: str) -> Evidence | None:
        return self._by_id.get(evidence_id)

    def add(
        self,
        kind: EvidenceKind | str,
        *,
        source: str,
        summary: str,
        data: dict[str, Any] | None = None,
        confidence: float = 0.8,
        verified: bool = False,
        verification_notes: list[str] | None = None,
        evidence_id: str | None = None,
    ) -> Evidence:
        evidence = Evidence(
            id=evidence_id or new_id("ev"),
            kind=EvidenceKind(kind),
            source=source,
            summary=summary,
            data=data or {},
            confidence=max(0.0, min(1.0, confidence)),
            verified=verified,
            verification_notes=list(verification_notes or []),
        )
        payload = evidence.digest_payload()
        evidence.sha256 = sha256_text(stable_json(payload))
        evidence.prev_hash = self._last_hash
        evidence.chain_hash = hmac_chain(self.settings.signing_key, self._last_hash, payload)
        self._last_hash = evidence.chain_hash
        self._items.append(evidence)
        self._by_id[evidence.id] = evidence
        return evidence

    def mark_verified(self, evidence_id: str, note: str) -> bool:
        evidence = self._by_id.get(evidence_id)
        if evidence is None:
            return False
        evidence.verified = True
        if note not in evidence.verification_notes:
            evidence.verification_notes.append(note)
        return True

    def add_note(self, evidence_id: str, note: str) -> bool:
        evidence = self._by_id.get(evidence_id)
        if evidence is None:
            return False
        if note not in evidence.verification_notes:
            evidence.verification_notes.append(note)
        return True

    def verify(self) -> tuple[bool, list[str]]:
        return verify_evidence_chain(self._items, self.settings.signing_key)

    def verified_ratio(self) -> float:
        if not self._items:
            return 0.0
        return sum(1 for item in self._items if item.verified) / len(self._items)

    def evidence_ids(self) -> list[str]:
        return [item.id for item in self._items]

    def digest(self, *, limit: int = 30, max_chars: int = 1200) -> list[dict[str, Any]]:
        """Compact evidence view for model prompts (never includes secrets)."""

        selected = self._items[-limit:]
        return [
            {
                "id": item.id,
                "kind": item.kind.value,
                "source": item.source,
                "summary": item.summary,
                "verified": item.verified,
                "confidence": round(item.confidence, 2),
                "data": stable_json(item.data)[:max_chars],
            }
            for item in selected
        ]

    def fingerprint(self) -> str:
        if not self._items:
            return hashlib.sha256(b"empty").hexdigest()
        return self._items[-1].chain_hash
