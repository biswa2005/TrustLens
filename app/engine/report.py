"""Structured investigation reports and an in-process report store."""

from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any

from app.config import Settings
from app.engine.utils import new_id, truncate
from app.schemas import (
    IOC,
    AgentTraceEntry,
    Evidence,
    Finding,
    InvestigationReport,
    ModelInfo,
    Recommendation,
    ReportSummary,
    RiskAssessment,
    Verdict,
)


def _cell(value: Any, limit: int = 180) -> str:
    text = truncate(str(value or "").replace("\n", " ").replace("|", "\\|"), limit)
    return text


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_No entries._"
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_cell(value) for value in row) + " |")
    return "\n".join(lines)


class ReportBuilder:
    def render_markdown(self, report: InvestigationReport) -> str:
        risk = report.risk
        verdict_label = report.verdict.value.replace("_", " ").title()
        created = report.created_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
        lines: list[str] = [
            "# ThreatLens Investigation Report",
            "",
            f"**Investigation:** `{report.id}`  ",
            f"**Module:** {report.module}  ",
            f"**Created:** {created}  ",
            f"**Language:** {report.language}  ",
            f"**Report version:** {report.report_version}",
            "",
            "## Verdict",
            "",
            _table(
                ["Risk score", "Verdict", "Severity", "Confidence", "Evidence chain"],
                [[
                    f"{report.risk_score}/100",
                    verdict_label,
                    report.severity.value,
                    f"{int(report.confidence * 100)}%",
                    "valid" if report.evidence_chain_valid else "INVALID",
                ]],
            ),
            "",
            f"> {report.executive_summary}",
            "",
            "## Input examined",
            "",
            report.input_summary or "_No input summary available._",
            "",
            "## Key findings",
            "",
        ]
        if report.findings:
            for index, finding in enumerate(
                sorted(report.findings, key=lambda item: (item.severity.rank, item.confidence), reverse=True),
                start=1,
            ):
                evidence_links = ", ".join(f"`{item}`" for item in finding.evidence_ids) or "_none_"
                tags = ", ".join(finding.tags) if finding.tags else "—"
                lines.extend(
                    [
                        f"### {index}. {finding.title}",
                        "",
                        f"**Severity:** {finding.severity.value} · **Confidence:** {int(finding.confidence * 100)}% "
                        f"· **Agent:** `{finding.agent}`  ",
                        f"**Evidence:** {evidence_links}  ",
                        f"**Techniques/tags:** {tags}",
                        "",
                        finding.description,
                        "",
                    ]
                )
        else:
            lines.extend(["_No findings were raised._", ""])

        lines.extend(
            [
                "## Risk breakdown",
                "",
                (
                    f"Category points: {risk.category_scores}  "
                    f"**Confidence basis:** {risk.confidence_basis}"
                    if risk
                    else "_No risk assessment._"
                ),
                "",
            ]
        )
        if risk:
            lines.append(
                _table(
                    ["Category", "Factor", "Points", "Reason"],
                    [
                        [factor.category.value, factor.label, factor.weight, factor.reason]
                        for factor in risk.factors[:25]
                    ],
                )
            )
        lines.extend(["", "## Evidence ledger", ""])
        lines.append(
            _table(
                ["ID", "Kind", "Source", "Verified", "Conf.", "Observation"],
                [
                    [
                        item.id,
                        item.kind.value,
                        item.source,
                        "yes" if item.verified else "no",
                        f"{int(item.confidence * 100)}%",
                        item.summary,
                    ]
                    for item in report.evidence
                ],
            )
        )

        if report.iocs:
            lines.extend(["", "## Indicators of compromise", ""])
            lines.append(
                _table(
                    ["Type", "Value", "Risk", "Context"],
                    [[ioc.type, ioc.value, ioc.risk.value, ioc.context] for ioc in report.iocs[:60]],
                )
            )

        lines.extend(["", "## Recommended actions", ""])
        if report.recommendations:
            for index, rec in enumerate(report.recommendations, start=1):
                lines.append(
                    f"{index}. **[{rec.priority.value.upper()}] {rec.title}** "
                    f"({rec.category.value}) — {rec.detail}"
                )
        else:
            lines.append("_No recommendations._")

        if report.module == "email":
            auth = report.metadata.get("email_auth") or {}
            if auth:
                lines.extend(
                    [
                        "",
                        "## Email authentication",
                        "",
                        _table(
                            ["Check", "Result", "Detail"],
                            [
                                ["SPF", (auth.get("spf") or {}).get("result", "n/a"), (auth.get("spf") or {}).get("explanation", "")],
                                ["DKIM", (auth.get("dkim") or {}).get("result", "n/a"), "; ".join((auth.get("dkim") or {}).get("errors", [])) or (auth.get("dkim") or {}).get("method", "")],
                                ["DMARC", (auth.get("dmarc") or {}).get("result", "n/a"), (auth.get("dmarc") or {}).get("explanation", "")],
                            ],
                        ),
                        "",
                        f"**Summary:** {auth.get('summary', '')}",
                    ]
                )

        lines.extend(
            [
                "",
                "## Agent collaboration trace",
                "",
                _table(
                    ["Agent", "Step", "Action", "Tool", "Status", "Latency"],
                    [
                        [
                            entry.agent,
                            entry.step,
                            entry.action,
                            entry.tool or "—",
                            entry.status,
                            f"{entry.latency_ms} ms",
                        ]
                        for entry in report.agent_trace
                    ],
                ),
                "",
                "## Methodology & limitations",
                "",
                "- Static parsing, DNS/RDAP/TLS inspection and optional public threat-intelligence checks "
                "produce an evidence ledger; the language model reasons over that ledger but does not "
                "invent infrastructure facts.",
                "- Absence of a threat-intelligence match is **not** proof of safety. New phishing domains "
                "are often unlisted, and some providers are optional.",
                "- Attachments are never executed and archives are never extracted. A sandbox detonation "
                "may still reveal additional behaviour.",
                "- Domain and certificate data are point-in-time observations and can change.",
                f"- Reasoning mode: **{(report.model.reasoning_mode if report.model else 'unknown')}**"
                + (" (degraded/offline fallback)" if report.degraded else ""),
                "",
                "## Disclaimer",
                "",
                "This report supports, but does not replace, professional incident response or legal advice. "
                "Do not interact with suspected fraud infrastructure. Report incidents to the relevant "
                "bank, platform and law-enforcement channel.",
                "",
            ]
        )
        return "\n".join(lines)

    def build(
        self,
        *,
        module: str,
        language: str,
        input_summary: str,
        risk: RiskAssessment,
        findings: list[Finding],
        evidence: list[Evidence],
        recommendations: list[Recommendation],
        iocs: list[IOC],
        entities: dict[str, Any],
        plan: dict[str, Any],
        trace: list[AgentTraceEntry],
        model_info: ModelInfo,
        executive_summary: str,
        technical_summary: str,
        evidence_chain_valid: bool,
        metadata: dict[str, Any] | None = None,
        report_id: str | None = None,
        created_at: datetime | None = None,
    ) -> InvestigationReport:
        now = datetime.now(UTC)
        report = InvestigationReport(
            id=report_id or new_id("inv"),
            module=module,  # type: ignore[arg-type]
            created_at=created_at or now,
            completed_at=now,
            language=language,
            input_summary=truncate(input_summary, 1600),
            verdict=risk.verdict if risk.verdict != Verdict.INCONCLUSIVE or evidence else Verdict.INCONCLUSIVE,
            severity=risk.severity,
            risk_score=risk.score,
            confidence=risk.confidence,
            executive_summary=executive_summary,
            technical_summary=technical_summary,
            risk=risk,
            findings=sorted(findings, key=lambda item: (item.severity.rank, item.confidence), reverse=True),
            evidence=evidence,
            recommendations=recommendations,
            iocs=iocs,
            entities=entities,
            agent_trace=trace,
            plan=plan,
            model=model_info,
            metadata=metadata or {},
            evidence_chain_valid=evidence_chain_valid,
            degraded=model_info.degraded,
        )
        report.markdown = self.render_markdown(report)
        return report


class ReportStore:
    """Bounded in-memory report cache.

    Production deployments should replace this with a database and object
    storage.  The interface is intentionally small so that swap is easy.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._reports: OrderedDict[str, InvestigationReport] = OrderedDict()
        self._lock = threading.Lock()

    def add(self, report: InvestigationReport) -> None:
        with self._lock:
            self._reports[report.id] = report
            self._reports.move_to_end(report.id)
            while len(self._reports) > self.settings.report_cache_size:
                self._reports.popitem(last=False)

    def get(self, report_id: str) -> InvestigationReport | None:
        with self._lock:
            return self._reports.get(report_id)

    def list(self, *, limit: int = 50, module: str | None = None) -> list[ReportSummary]:
        with self._lock:
            reports = list(reversed(self._reports.values()))
        summaries = [
            ReportSummary(
                id=report.id,
                module=report.module,
                created_at=report.created_at,
                verdict=report.verdict,
                severity=report.severity,
                risk_score=report.risk_score,
                input_summary=truncate(report.input_summary, 200),
            )
            for report in reports
            if module is None or report.module == module
        ]
        return summaries[:limit]

    def clear(self) -> None:
        with self._lock:
            self._reports.clear()
