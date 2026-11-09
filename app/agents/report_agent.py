"""Final Report Generation Agent.

Filters verified findings, recomputes the transparent risk assessment, asks the
explainer for a narrative that is grounded in the evidence ledger, and stores a
structured, human-readable investigation report.
"""

from __future__ import annotations

import time
from typing import Any

from app.agents.runtime import AgentRuntime
from app.agents.state import InvestigationState
from app.engine.explain import Explainer
from app.engine.risk import RiskEngine
from app.schemas import (
    IOC,
    AgentTraceEntry,
    EvidenceKind,
    Finding,
    Severity,
    Verdict,
)


class FinalReportAgent:
    name = "report"
    display_name = "Final Report Generation Agent"

    async def run(
        self, state: InvestigationState, runtime: AgentRuntime
    ) -> dict[str, Any]:
        started = time.perf_counter()
        module = str(state.get("module") or runtime.module)
        verification = state.get("verification") or {}
        dropped = set(verification.get("dropped_finding_ids") or [])
        updates = verification.get("finding_updates") or {}
        valid_ids = runtime.evidence_ids()

        findings = self._verified_findings(
            list(state.get("findings") or []), dropped, updates, valid_ids
        )
        evidence = runtime.store.items
        signals = list(state.get("signals") or [])
        iocs = dedupe_iocs(list(state.get("iocs") or []))
        entities = dict(state.get("entities") or {})

        plan = dict(state.get("plan") or {})
        visited = list(dict.fromkeys(state.get("visited") or []))
        planned = [item for item in (plan.get("agents") or []) if isinstance(item, str)]
        completeness = (
            min(1.0, len(set(visited) & set(planned)) / len(planned))
            if planned
            else 1.0
        )

        risk = RiskEngine().assess(
            signals,
            evidence,
            module=module,
            completeness=completeness,
        )
        risk = self._adjust_incomplete_risk(module, risk, evidence)

        context = self._context(module, findings, evidence, iocs, state, runtime)
        findings_payload = [
            {
                "title": item.title,
                "severity": item.severity.value,
                "confidence": item.confidence,
                "evidence_ids": item.evidence_ids,
                "description": item.description,
                "tags": item.tags,
            }
            for item in findings
        ]
        brand = self._brand(evidence, state)
        explainer = Explainer(runtime.llm)
        executive, technical, recommendations, used_llm = await explainer.explain(
            module=module,
            language=str(state.get("language") or runtime.language),
            risk=risk,
            findings=findings_payload,
            evidence_digest=runtime.evidence_digest(limit=40),
            context=context,
            brand=brand,
        )

        metadata = self._metadata(
            state=state,
            runtime=runtime,
            verification=verification,
            evidence=evidence,
            risk=risk,
            completeness=completeness,
            used_llm=used_llm,
        )
        report = runtime.report_builder.build(
            module=module,
            language=str(state.get("language") or runtime.language),
            input_summary=str(state.get("input_summary") or self._input_summary(state)),
            risk=risk,
            findings=findings,
            evidence=evidence,
            recommendations=recommendations,
            iocs=iocs,
            entities=entities,
            plan=plan,
            trace=list(state.get("trace") or []),
            model_info=runtime.llm.model_info(),
            executive_summary=executive,
            technical_summary=technical,
            evidence_chain_valid=bool(
                state.get("evidence_chain_valid")
                if state.get("evidence_chain_valid") is not None
                else verification.get("chain_valid")
            ),
            metadata=metadata,
            report_id=runtime.investigation_id,
        )

        trace = [
            AgentTraceEntry(
                agent=self.name,
                step="report",
                action="Built and stored the final investigation report",
                detail=(
                    f"Verdict {report.verdict.value} at {report.risk_score}/100; "
                    f"{len(findings)} finding(s); {len(evidence)} evidence item(s); "
                    f"narrative {'model-generated' if used_llm else 'deterministic template'}"
                ),
                status="ok" if report.evidence_chain_valid else "warning",
                latency_ms=int((time.perf_counter() - started) * 1000),
                model=runtime.llm.model_info().text_model if used_llm else None,
            )
        ]
        report.agent_trace = list(report.agent_trace) + trace
        report.markdown = runtime.report_builder.render_markdown(report)
        runtime.services.reports.add(report)
        summary = (
            f"Final report generated. Verdict: {report.verdict.value.replace('_', ' ')} "
            f"({report.risk_score}/100, {report.severity.value}). "
            f"{len(findings)} finding(s) survived evidence verification."
        )
        return {
            "report": report,
            "status": "completed",
            "trace": trace,
            "visited": [self.name],
            "agent_summaries": [
                {
                    "agent": self.name,
                    "summary": summary,
                    "findings": len(findings),
                    "evidence_collected": 0,
                }
            ],
            "entities": entities,
        }

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _adjust_incomplete_risk(module: str, risk: Any, evidence: list[Any]) -> Any:
        """Do not return a benign verdict when a visual/QR check never ran.

        A screenshot with no vision/OCR observation, or a QR image that could not
        be decoded, has no probative content.  Treating that as "benign" would be
        misleading; the verdict is inconclusive while the collected evidence stays
        in the ledger.
        """

        kinds = {item.kind for item in evidence}
        if module == "visual" and not (
            kinds & {EvidenceKind.VLM_OBSERVATION, EvidenceKind.OCR_TEXT}
        ):
            if risk.score >= 20:
                # Other evidence (for example a lookalike URL) is still probative.
                return risk
            return risk.model_copy(
                update={
                    "verdict": Verdict.INCONCLUSIVE,
                    "confidence": min(0.4, risk.confidence),
                    "summary": (
                        "The screenshot could not be visually analysed (no vision model or OCR "
                        "observation), so no impersonation verdict can be supported."
                    ),
                }
            )
        if module == "qr" and not (
            kinds & {EvidenceKind.QR_PAYLOAD, EvidenceKind.UPI_URI}
        ):
            if risk.score >= 20:
                return risk
            return risk.model_copy(
                update={
                    "verdict": Verdict.INCONCLUSIVE,
                    "confidence": min(0.4, risk.confidence),
                    "summary": (
                        "No QR payload could be decoded, so the image cannot support a fraud "
                        "or safety verdict."
                    ),
                }
            )
        return risk

    @staticmethod
    def _verified_findings(
        findings: list[Finding],
        dropped: set[str],
        updates: dict[str, dict[str, Any]],
        valid_ids: set[str],
    ) -> list[Finding]:
        verified: list[Finding] = []
        for finding in findings:
            if finding.id in dropped:
                continue
            refs = [item for item in finding.evidence_ids if item in valid_ids]
            if not refs:
                continue
            update: dict[str, Any] = {"evidence_ids": refs}
            change = updates.get(finding.id) or {}
            if change.get("evidence_ids"):
                update["evidence_ids"] = [
                    item for item in change["evidence_ids"] if item in valid_ids
                ] or refs
            if change.get("severity"):
                try:
                    update["severity"] = Severity(str(change["severity"]))
                except ValueError:
                    pass
            verified.append(finding.model_copy(update=update) if update else finding)
        return verified

    @staticmethod
    def _context(
        module: str,
        findings: list[Finding],
        evidence: list[Any],
        iocs: list[IOC],
        state: InvestigationState,
        runtime: AgentRuntime,
    ) -> dict[str, Any]:
        kinds = {item.kind for item in evidence}
        tags = {tag for finding in findings for tag in finding.tags}
        text = " ".join(
            [finding.title + " " + finding.description for finding in findings]
        ).lower()
        urls = [
            str((item.data or {}).get("normalized_url"))
            for item in evidence
            if item.kind == EvidenceKind.URL_STATIC
            and (item.data or {}).get("normalized_url")
        ]
        auth = next(
            (
                item.data
                for item in evidence
                if item.kind == EvidenceKind.EMAIL_AUTH and (item.data or {}).get("enabled")
            ),
            None,
        )
        if auth is None:
            auth = next(
                (
                    item.data
                    for item in evidence
                    if item.kind == EvidenceKind.EMAIL_AUTH
                    and isinstance((item.data or {}).get("spf"), dict)
                ),
                None,
            )
        return {
            "module": module,
            "scam_types": sorted(
                {tag for tag in tags if tag and tag not in {"email", "url", "visual", "qr"}}
            )[:6],
            "urls": list(dict.fromkeys(urls))[:6],
            "brand": FinalReportAgent._brand(evidence, state),
            "auth_summary": (auth or {}).get("summary", ""),
            "tags": sorted(tags),
            "has_url": bool(kinds & {EvidenceKind.URL_STATIC, EvidenceKind.URL_FETCH})
            or bool(state.get("pending_urls")),
            "has_upi": EvidenceKind.UPI_URI in kinds
            or any(item.type == "upi_id" for item in iocs),
            "has_otp": "otp_request" in tags or "otp" in text,
            "has_attachment": EvidenceKind.EMAIL_ATTACHMENT in kinds,
            "investigated_domains": sorted(
                {
                    str((item.data or {}).get("registered_domain"))
                    for item in evidence
                    if item.kind == EvidenceKind.URL_STATIC
                    and (item.data or {}).get("registered_domain")
                }
            )[:10],
            "reasoning_mode": runtime.llm.reasoning_mode,
        }

    @staticmethod
    def _brand(evidence: list[Any], state: InvestigationState) -> str | None:
        for item in evidence:
            data = item.data or {}
            if item.kind == EvidenceKind.VLM_OBSERVATION:
                guess = data.get("brand_guess")
                if guess:
                    return str(guess)
            if item.kind == EvidenceKind.URL_STATIC and data.get("brand_match"):
                return str(data["brand_match"])
        artifacts = state.get("artifacts") or {}
        payload = state.get("input") or {}
        hint = artifacts.get("brand_hint") or payload.get("brand_hint")
        return str(hint) if hint else None

    @staticmethod
    def _input_summary(state: InvestigationState) -> str:
        payload = state.get("input") or {}
        for key in ("summary", "text", "message", "body", "subject"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:1200]
        return f"{state.get('module', 'unknown')} investigation"

    @staticmethod
    def _metadata(
        *,
        state: InvestigationState,
        runtime: AgentRuntime,
        verification: dict[str, Any],
        evidence: list[Any],
        risk: Any,
        completeness: float,
        used_llm: bool,
    ) -> dict[str, Any]:
        email_auth = next(
            (
                item.data
                for item in evidence
                if item.kind == EvidenceKind.EMAIL_AUTH
                and isinstance((item.data or {}).get("spf"), dict)
            ),
            None,
        )
        return {
            "verification": verification,
            "agent_summaries": list(state.get("agent_summaries") or []),
            "plan": dict(state.get("plan") or {}),
            "evidence_fingerprint": runtime.store.fingerprint(),
            "evidence_count": len(evidence),
            "investigation_completeness": round(completeness, 2),
            "narrative_source": "huggingface" if used_llm else "deterministic-template",
            "reasoning_mode": runtime.llm.reasoning_mode,
            "degraded": runtime.llm.degraded,
            "email_auth": email_auth,
            "risk_confidence_basis": risk.confidence_basis,
            "limitations": [
                "Threat-intelligence absence is not proof of safety.",
                "Attachments are never executed; archives are never extracted.",
                "Domain, DNS and certificate data are point-in-time observations.",
                "Visual/OCR observations can be incomplete or misread; confirm against the evidence ledger.",
            ],
        }


def dedupe_iocs(items: list[IOC]) -> list[IOC]:
    best: dict[tuple[str, str], IOC] = {}
    for item in items:
        key = (item.type, item.value.strip().lower())
        existing = best.get(key)
        if existing is None or item.risk.rank > existing.risk.rank:
            if existing is not None:
                item = item.model_copy(
                    update={
                        "evidence_ids": list(
                            dict.fromkeys(existing.evidence_ids + item.evidence_ids)
                        ),
                        "context": existing.context or item.context,
                    }
                )
            best[key] = item
        else:
            existing.evidence_ids = list(
                dict.fromkeys(existing.evidence_ids + item.evidence_ids)
            )
    return list(best.values())
