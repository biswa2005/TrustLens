"""Evidence Verification Agent.

This agent is the quality gate between specialist findings and the final report.
It checks the HMAC evidence chain, removes findings that cite no real evidence,
downgrades high-severity claims without adequate support, and asks the URL agent
for one more pass when obvious links were never investigated.
"""

from __future__ import annotations

import time
from typing import Any

from app.agents.runtime import AgentRuntime
from app.agents.state import InvestigationState
from app.engine.urls import extract_urls, normalize_url
from app.engine.utils import truncate
from app.schemas import (
    AgentTraceEntry,
    EvidenceKind,
    Severity,
)

_DOWNGRADE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
    Severity.INFO: Severity.INFO,
}


class EvidenceVerificationAgent:
    name = "evidence"
    display_name = "Evidence Verification Agent"

    async def run(
        self, state: InvestigationState, runtime: AgentRuntime
    ) -> dict[str, Any]:
        started = time.perf_counter()
        trace: list[AgentTraceEntry] = []
        findings = list(state.get("findings") or [])
        valid_ids = runtime.evidence_ids()
        evidence_by_id = {item.id: item for item in runtime.store.items}

        chain_valid, chain_errors = runtime.store.verify()
        dropped: list[str] = []
        updates: dict[str, dict[str, Any]] = {}
        notes: list[str] = []

        for finding in findings:
            refs = [item for item in finding.evidence_ids if item in valid_ids]
            if not refs:
                dropped.append(finding.id)
                notes.append(
                    f"Dropped '{truncate(finding.title, 120)}': it cited no evidence present in the ledger."
                )
                continue

            update: dict[str, Any] = {}
            if refs != finding.evidence_ids:
                update["evidence_ids"] = refs
                notes.append(
                    f"Removed {len(finding.evidence_ids) - len(refs)} unknown evidence reference(s) "
                    f"from '{truncate(finding.title, 120)}'."
                )

            supported = [
                evidence_by_id[item]
                for item in refs
                if evidence_by_id[item].verified or evidence_by_id[item].confidence >= 0.8
            ]
            if finding.severity.rank >= Severity.HIGH.rank and not supported:
                downgraded = _DOWNGRADE.get(finding.severity, Severity.MEDIUM)
                update["severity"] = downgraded.value
                notes.append(
                    f"Downgraded '{truncate(finding.title, 120)}' from {finding.severity.value} "
                    f"to {downgraded.value}: none of its evidence is independently verified or "
                    "high-confidence."
                )
            if update:
                updates[finding.id] = update

        # ------------------------------------------------------- URL coverage
        requested: list[str] = []
        pending_urls: list[str] = []
        missing_urls = self._missing_urls(state, runtime)
        rework_count = int(state.get("rework_count") or 0)
        if missing_urls:
            if rework_count < 2:
                requested = ["url"]
                pending_urls = missing_urls
                notes.append(
                    "Queued a URL rework pass for "
                    + ", ".join(missing_urls[:4])
                    + ("…" if len(missing_urls) > 4 else "")
                    + ": these links appear in the input but have no URL evidence yet."
                )
            else:
                notes.append(
                    "URL rework limit reached; some links in the input remain uninvestigated."
                )

        if chain_valid:
            notes.append(
                f"Evidence hash chain verified across {len(runtime.store)} item(s)."
            )
        else:
            notes.append(
                "Evidence hash chain verification FAILED: "
                + "; ".join(chain_errors[:4])
            )

        verification_evidence = runtime.store.add(
            EvidenceKind.VERIFICATION,
            source="evidence-agent",
            summary=(
                f"Evidence verification: {len(findings) - len(dropped)} finding(s) kept, "
                f"{len(dropped)} dropped, chain {'valid' if chain_valid else 'invalid'}"
            ),
            data={
                "chain_valid_before_verification_item": chain_valid,
                "chain_errors": chain_errors[:20],
                "findings_checked": len(findings),
                "dropped_finding_ids": dropped,
                "finding_updates": updates,
                "missing_urls": missing_urls,
                "rework_requested": bool(requested),
                "notes": notes,
            },
            confidence=0.99,
            verified=True,
        )
        final_valid, final_errors = runtime.store.verify()
        if not final_valid:
            notes.append(
                "Final evidence chain verification failed after adding the verification record: "
                + "; ".join(final_errors[:4])
            )

        verification = {
            "evidence_id": verification_evidence.id,
            "chain_valid": final_valid,
            "chain_errors": final_errors[:20],
            "dropped_finding_ids": dropped,
            "finding_updates": updates,
            "findings_checked": len(findings),
            "findings_kept": len(findings) - len(dropped),
            "missing_urls": missing_urls,
            "notes": notes,
        }

        trace.append(
            AgentTraceEntry(
                agent=self.name,
                step="verification",
                action="Verified evidence chain and finding support",
                detail=(
                    f"{len(findings)} finding(s) checked; {len(dropped)} dropped; "
                    f"{len(updates)} updated; chain {'valid' if final_valid else 'INVALID'}"
                ),
                status="ok" if final_valid else "error",
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        )
        if requested:
            trace.append(
                AgentTraceEntry(
                    agent=self.name,
                    step="rework",
                    action="Requested URL Intelligence rework",
                    detail="Missing URL coverage: " + ", ".join(missing_urls[:5]),
                    status="warning",
                )
            )

        return {
            "verification": verification,
            "evidence_chain_valid": final_valid,
            "requested_agents": requested,
            "pending_urls": pending_urls,
            "rework_count": rework_count + (1 if requested else 0),
            "trace": trace,
            "visited": [self.name],
            "agent_summaries": [
                {
                    "agent": self.name,
                    "summary": " ".join(notes[:6]),
                    "findings": len(findings) - len(dropped),
                    "evidence_collected": 1,
                }
            ],
            "entities": state.get("entities") or {},
        }

    @staticmethod
    def _missing_urls(state: InvestigationState, runtime: AgentRuntime) -> list[str]:
        candidates: list[str] = []
        payload = state.get("input") or {}
        for key in ("text", "message", "body"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                candidates.extend(item.normalized for item in extract_urls(value, limit=20))

        artifacts = state.get("artifacts") or {}
        parsed = artifacts.get("parsed_email") or {}
        if isinstance(parsed, dict):
            for item in parsed.get("urls") or []:
                if isinstance(item, dict):
                    candidates.append(str(item.get("url") or ""))
                else:
                    candidates.append(str(item))
            if parsed.get("body_text"):
                candidates.extend(
                    item.normalized
                    for item in extract_urls(str(parsed["body_text"]), limit=20)
                )

        candidates.extend(str(item) for item in (state.get("pending_urls") or []))

        for evidence in runtime.store.items:
            if evidence.kind not in {
                EvidenceKind.URL_REFERENCE,
                EvidenceKind.QR_PAYLOAD,
                EvidenceKind.MESSAGE_TEXT,
                EvidenceKind.EMAIL_BODY,
            }:
                continue
            data = evidence.data or {}
            for key in ("url", "urls", "payload", "text"):
                value = data.get(key)
                if isinstance(value, str):
                    if value.startswith(("http://", "https://")):
                        candidates.append(value)
                    else:
                        candidates.extend(
                            item.normalized for item in extract_urls(value, limit=20)
                        )
                elif isinstance(value, list):
                    for item in value:
                        text = item.get("url") if isinstance(item, dict) else item
                        if isinstance(text, str) and text.startswith(("http://", "https://")):
                            candidates.append(text)

        investigated: set[str] = set()
        for evidence in runtime.store.items:
            if evidence.kind != EvidenceKind.URL_STATIC:
                continue
            data = evidence.data or {}
            for key in ("url", "normalized_url", "final_url"):
                value = str(data.get(key) or "")
                if value:
                    investigated.add(normalize_url(value))

        missing: list[str] = []
        for candidate in candidates:
            try:
                normalized = normalize_url(candidate)
            except Exception:
                continue
            if normalized and normalized not in investigated and normalized not in missing:
                missing.append(normalized)
        return missing[: runtime.settings.max_urls_per_investigation]
