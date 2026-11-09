"""Base ReAct-style agent with deterministic tools and evidence grounding."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.agents.prompts import AGENT_PROMPTS, COMMON_RULES, FINDING_CONTRACT
from app.agents.runtime import AgentRuntime
from app.agents.state import InvestigationState
from app.agents.types import ToolResult
from app.engine.hf import LLMUnavailable
from app.engine.llm import extract_json
from app.engine.utils import dedupe, new_id, truncate
from app.schemas import AgentTraceEntry, Finding, Severity

logger = logging.getLogger(__name__)

_ALLOWED_AGENTS = {"message", "qr", "visual", "email", "url"}


def safe_input_view(value: dict[str, Any]) -> dict[str, Any]:
    view: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, bytes):
            view[key] = f"<{len(item)} bytes>"
        elif isinstance(item, str):
            view[key] = truncate(item, 4000)
        elif isinstance(item, (dict, list, int, float, bool)) or item is None:
            view[key] = item
        else:
            view[key] = truncate(str(item), 500)
    return view


class BaseAgent:
    name = "agent"
    display_name = "Agent"
    llm_tools: list[str] = []

    def plan_tools(self, state: InvestigationState, runtime: AgentRuntime) -> list[tuple[str, dict[str, Any]]]:
        return []

    def deterministic_findings(
        self,
        state: InvestigationState,
        results: list[ToolResult],
        analysis: dict[str, Any] | None,
        runtime: AgentRuntime,
    ) -> list[Finding]:
        return []

    def finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        confidence: float,
        evidence_ids: list[str],
        *,
        tags: list[str] | None = None,
        techniques: list[str] | None = None,
    ) -> Finding:
        return Finding(
            id=new_id("fnd"),
            agent=self.name,
            title=truncate(title, 180),
            description=truncate(description, 2400),
            severity=severity,
            confidence=max(0.0, min(1.0, confidence)),
            evidence_ids=dedupe(evidence_ids),
            tags=dedupe(tags or []),
            techniques=dedupe(techniques or []),
        )

    async def run(self, state: InvestigationState, runtime: AgentRuntime) -> dict[str, Any]:
        started = time.perf_counter()
        trace: list[AgentTraceEntry] = []
        results: list[ToolResult] = []

        for tool_name, args in self.plan_tools(state, runtime):
            tool_started = time.perf_counter()
            try:
                result = await runtime.toolbox.call(tool_name, args)
                results.append(result)
                trace.append(
                    AgentTraceEntry(
                        agent=self.name,
                        step="evidence-collection",
                        action=f"Ran {tool_name}",
                        tool=tool_name,
                        detail=truncate(result.summary, 500),
                        status="ok",
                        latency_ms=int((time.perf_counter() - tool_started) * 1000),
                    )
                )
            except Exception as exc:  # a failed tool must not kill the investigation
                logger.warning("%s: tool %s failed: %s", self.name, tool_name, exc)
                trace.append(
                    AgentTraceEntry(
                        agent=self.name,
                        step="evidence-collection",
                        action=f"Ran {tool_name}",
                        tool=tool_name,
                        detail=truncate(f"{type(exc).__name__}: {exc}", 500),
                        status="error",
                        latency_ms=int((time.perf_counter() - tool_started) * 1000),
                    )
                )

        analysis: dict[str, Any] | None = None
        if runtime.llm.available:
            try:
                analysis, llm_trace = await self._reason(state, runtime, results)
                trace.extend(llm_trace)
            except LLMUnavailable as exc:
                runtime.llm.mark_degraded(str(exc))
                trace.append(
                    AgentTraceEntry(
                        agent=self.name,
                        step="reasoning",
                        action="Model synthesis unavailable; deterministic findings used",
                        detail=truncate(str(exc), 400),
                        status="warning",
                    )
                )
        else:
            trace.append(
                AgentTraceEntry(
                    agent=self.name,
                    step="reasoning",
                    action="Offline expert-system mode (no Hugging Face token)",
                    status="skipped",
                )
            )

        findings = self.deterministic_findings(state, results, analysis, runtime)
        findings.extend(self._llm_findings(analysis, runtime))
        findings = self._merge_findings(findings)
        signals = [signal for result in results for signal in result.signals]
        iocs = [ioc for result in results for ioc in result.iocs]
        pending_urls = dedupe([url for result in results for url in result.pending_urls])
        pending_domains = dedupe([domain for result in results for domain in result.pending_domains])
        entities: dict[str, Any] = {}
        for result in results:
            candidate = result.data.get("entities")
            if isinstance(candidate, dict):
                for key, value in candidate.items():
                    if isinstance(value, list):
                        entities[key] = dedupe([str(item) for item in value])
                    elif value:
                        entities[key] = value
        if analysis:
            for key in ("additional_urls", "additional_domains"):
                values = analysis.get(key) or []
                if not isinstance(values, list):
                    continue
                if key == "additional_urls":
                    pending_urls = dedupe(pending_urls + [str(item) for item in values if str(item).startswith(("http://", "https://"))])
                else:
                    pending_domains = dedupe(pending_domains + [str(item).lower().strip(".") for item in values if "." in str(item)])
            requested = [
                item for item in (analysis.get("requested_agents") or [])
                if isinstance(item, str) and item in _ALLOWED_AGENTS
            ]
        else:
            requested = []

        summary = (
            str(analysis.get("summary") or "").strip()
            if analysis
            else ""
        )
        if not summary:
            summary = " ".join(result.summary for result in results[:4]) or "No observations were collected."
        if findings:
            summary += f" Findings raised: {len(findings)}."
        trace.append(
            AgentTraceEntry(
                agent=self.name,
                step="complete",
                action=f"Contributed {len(findings)} finding(s), {len(signals)} signal(s), {len(results)} tool result(s)",
                status="ok",
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        )
        return {
            "findings": findings,
            "signals": signals,
            "iocs": iocs,
            "trace": trace,
            "visited": [self.name],
            "agent_summaries": [
                {
                    "agent": self.name,
                    "summary": truncate(summary, 1200),
                    "findings": len(findings),
                    "evidence_collected": sum(len(result.evidence) for result in results),
                }
            ],
            "pending_urls": pending_urls,
            "pending_domains": pending_domains,
            "requested_agents": requested,
            "entities": entities,
        }

    async def _reason(
        self,
        state: InvestigationState,
        runtime: AgentRuntime,
        results: list[ToolResult],
    ) -> tuple[dict[str, Any] | None, list[AgentTraceEntry]]:
        trace: list[AgentTraceEntry] = []
        specs = runtime.toolbox.specs(self.llm_tools)
        tools = [spec.openai_schema() for spec in specs]
        system = (
            f"{COMMON_RULES}\n\n{AGENT_PROMPTS.get(self.name, '')}\n\n"
            f"You are the {self.display_name}. {FINDING_CONTRACT}"
        )
        focus = (state.get("plan") or {}).get("focus") or []
        user = json.dumps(
            {
                "investigation_id": state.get("investigation_id"),
                "module": state.get("module"),
                "target_language": runtime.language,
                "input": safe_input_view(state.get("input") or {}),
                "plan_focus": focus,
                "tool_observations": [
                    {
                        "tool": result.name,
                        "summary": result.summary,
                        "evidence_ids": [item.id for item in result.evidence],
                        "signal_labels": [signal.label for signal in result.signals],
                        "data": result.data,
                    }
                    for result in results
                ],
                "evidence_digest": runtime.evidence_digest(30),
                "existing_findings": [
                    {"title": item.title, "severity": item.severity.value, "evidence_ids": item.evidence_ids}
                    for item in (state.get("findings") or [])
                ],
                "pending_urls": state.get("pending_urls") or [],
                "pending_domains": state.get("pending_domains") or [],
                "optional_tools": [spec.name for spec in specs],
            },
            default=str,
            ensure_ascii=False,
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": truncate(user, 24_000)},
        ]
        parsed: dict[str, Any] | None = None
        max_steps = max(1, runtime.settings.llm_max_tool_steps)
        for step in range(max_steps):
            call_started = time.perf_counter()
            response = await runtime.llm.chat(
                messages,
                tools=tools or None,
                max_tokens=runtime.settings.llm_max_tokens,
            )
            trace.append(
                AgentTraceEntry(
                    agent=self.name,
                    step=f"reasoning-{step + 1}",
                    action="Hugging Face model call",
                    tool=None,
                    detail=truncate(response.content, 300) or "Tool selection requested",
                    status="ok",
                    latency_ms=int((time.perf_counter() - call_started) * 1000),
                    model=response.model or runtime.settings.text_model,
                )
            )
            if response.tool_calls:
                messages.append(
                    {
                        "role": "assistant",
                        "content": response.content or "",
                        "tool_calls": [
                            {
                                "id": call.id,
                                "type": "function",
                                "function": {
                                    "name": call.name,
                                    "arguments": json.dumps(call.arguments, ensure_ascii=False),
                                },
                            }
                            for call in response.tool_calls
                        ],
                    }
                )
                for call in response.tool_calls:
                    tool_started = time.perf_counter()
                    try:
                        tool_result = await runtime.toolbox.call(call.name, call.arguments)
                        results.append(tool_result)
                        content = json.dumps(
                            {
                                "summary": tool_result.summary,
                                "evidence_ids": [item.id for item in tool_result.evidence],
                                "signals": [
                                    {"label": signal.label, "weight": signal.weight}
                                    for signal in tool_result.signals
                                ],
                                "data": tool_result.data,
                            },
                            default=str,
                            ensure_ascii=False,
                        )
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": call.id,
                                "name": call.name,
                                "content": truncate(content, 8000),
                            }
                        )
                        trace.append(
                            AgentTraceEntry(
                                agent=self.name,
                                step=f"tool-{step + 1}",
                                action=f"Model requested {call.name}",
                                tool=call.name,
                                detail=truncate(tool_result.summary, 400),
                                status="ok",
                                latency_ms=int((time.perf_counter() - tool_started) * 1000),
                            )
                        )
                    except Exception as exc:
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": call.id,
                                "name": call.name,
                                "content": json.dumps({"error": truncate(str(exc), 400)}),
                            }
                        )
                        trace.append(
                            AgentTraceEntry(
                                agent=self.name,
                                step=f"tool-{step + 1}",
                                action=f"Model requested {call.name}",
                                tool=call.name,
                                detail=truncate(str(exc), 400),
                                status="error",
                                latency_ms=int((time.perf_counter() - tool_started) * 1000),
                            )
                        )
                continue

            parsed = extract_json(response.content)
            if isinstance(parsed, dict):
                break
            if step + 1 < max_steps:
                messages.append({"role": "assistant", "content": response.content})
                messages.append(
                    {
                        "role": "user",
                        "content": "Return the required JSON object now, with no markdown or commentary.",
                    }
                )
        if parsed is None:
            trace.append(
                AgentTraceEntry(
                    agent=self.name,
                    step="reasoning",
                    action="Model output could not be parsed as JSON; deterministic findings retained",
                    status="warning",
                )
            )
        return parsed, trace

    def _llm_findings(self, analysis: dict[str, Any] | None, runtime: AgentRuntime) -> list[Finding]:
        if not analysis:
            return []
        raw_findings = analysis.get("findings") or []
        if not isinstance(raw_findings, list):
            return []
        valid_ids = runtime.evidence_ids()
        defaults = runtime.default_evidence_ids(3)
        findings: list[Finding] = []
        for raw in raw_findings[:8]:
            if not isinstance(raw, dict):
                continue
            title = str(raw.get("title") or "").strip()
            description = str(raw.get("description") or "").strip()
            if not title or not description:
                continue
            try:
                severity = Severity(str(raw.get("severity") or "medium").lower())
            except ValueError:
                severity = Severity.MEDIUM
            try:
                confidence = float(raw.get("confidence", 0.7))
            except (TypeError, ValueError):
                confidence = 0.7
            refs = [
                str(item) for item in (raw.get("evidence_ids") or []) if str(item) in valid_ids
            ]
            if not refs:
                refs = defaults
            findings.append(
                self.finding(
                    title,
                    description,
                    severity,
                    confidence,
                    refs,
                    tags=[str(item) for item in (raw.get("tags") or [])][:6],
                    techniques=[str(item) for item in (raw.get("techniques") or [])][:4],
                )
            )
        return findings

    @staticmethod
    def _merge_findings(findings: list[Finding]) -> list[Finding]:
        merged: dict[str, Finding] = {}
        for finding in findings:
            key = " ".join(finding.title.lower().split())
            existing = merged.get(key)
            if existing is None or len(finding.description) > len(existing.description):
                merged[key] = finding
        return list(merged.values())
