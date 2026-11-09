"""Master Investigation Orchestrator."""

from __future__ import annotations

import time
from typing import Any

from app.agents.prompts import AGENT_PROMPTS, COMMON_RULES
from app.agents.runtime import AgentRuntime
from app.agents.state import InvestigationState
from app.engine.hf import LLMUnavailable
from app.engine.urls import extract_urls
from app.schemas import AgentTraceEntry

FOCUS: dict[str, list[str]] = {
    "message": [
        "Identify the most likely scam category and the evidence supporting it.",
        "Map the psychological manipulation tactics with short quotes.",
        "Extract payment identifiers, phone numbers and links that need separate investigation.",
        "State clearly what remains unverified.",
    ],
    "qr": [
        "Decode every QR payload and classify its semantics.",
        "Explain whether the QR initiates a payment or another action.",
        "Identify destination URLs that need infrastructure investigation.",
        "Check for contradictory 'receive money' or prize claims.",
    ],
    "visual": [
        "OCR the page, including the address bar and form labels.",
        "Identify the brand the page appears to claim.",
        "Look for visual inconsistencies and credential-harvesting fields.",
        "Separate visual similarity from domain ownership evidence.",
    ],
    "email": [
        "Verify sender identity, Reply-To/Return-Path and header alignment.",
        "Independently verify SPF, DKIM and DMARC where possible.",
        "Assess Business Email Compromise, invoice and payment-change patterns.",
        "Triage attachments statically and identify links/domains for the URL agent.",
    ],
}

PLAN_SCHEMA = """Return ONLY JSON:
{
  "primary": "message|qr|visual|email",
  "agents": ["message|qr|visual|email|url|evidence|report"],
  "rationale": "why this plan is sufficient",
  "focus": ["specific investigative questions"],
  "depth": "quick|standard|deep"
}"""


class OrchestratorAgent:
    name = "orchestrator"
    display_name = "Master Investigation Orchestrator"

    async def run(self, state: InvestigationState, runtime: AgentRuntime) -> dict[str, Any]:
        started = time.perf_counter()
        module = state.get("module") or "message"
        primary = module if module in {"message", "qr", "visual", "email"} else "message"
        plan = {
            "primary": primary,
            "agents": [primary, "url", "evidence", "report"],
            "rationale": (
                f"The {primary} module collects domain-specific evidence; the URL agent is included "
                "conditionally for any extracted links/domains, followed by evidence verification and "
                "final reporting."
            ),
            "focus": FOCUS.get(primary, []),
            "depth": "standard",
            "mode": "offline-planner",
        }
        trace: list[AgentTraceEntry] = []

        if runtime.llm.available:
            call_started = time.perf_counter()
            input_view = {
                key: (f"<{len(value)} bytes>" if isinstance(value, bytes) else value)
                for key, value in (state.get("input") or {}).items()
                if key not in {"raw", "image_bytes", "eml_bytes"}
            }
            user = (
                f"Module: {primary}\nLanguage: {runtime.language}\n"
                f"Input summary: {state.get('input_summary') or input_view}\n"
                f"Available specialists: message, qr, visual, email, url, evidence, report.\n"
                f"The URL agent should be included whenever links or domains may need investigation.\n"
                f"Always include evidence verification and report generation.\n{PLAN_SCHEMA}"
            )
            try:
                parsed, response = await runtime.llm.json_chat(
                    f"{COMMON_RULES}\n\n{AGENT_PROMPTS['orchestrator']}\n\n{PLAN_SCHEMA}",
                    user,
                    max_tokens=700,
                    schema_hint=PLAN_SCHEMA,
                )
                if parsed:
                    agents = [
                        item for item in (parsed.get("agents") or [])
                        if isinstance(item, str)
                        and item in {"message", "qr", "visual", "email", "url", "evidence", "report"}
                    ]
                    agents = [
                        item for item in agents
                        if item in {primary, "url", "evidence", "report"}
                    ]
                    if primary not in agents:
                        agents.insert(0, primary)
                    for required in ("evidence", "report"):
                        if required not in agents:
                            agents.append(required)
                    if "url" not in agents:
                        agents.append("url")
                    plan.update(
                        {
                            "agents": agents,
                            "rationale": str(parsed.get("rationale") or plan["rationale"])[:800],
                            "focus": [
                                str(item)[:300] for item in (parsed.get("focus") or []) if str(item).strip()
                            ][:8]
                            or plan["focus"],
                            "depth": str(parsed.get("depth") or "standard")[:20],
                            "mode": "llm-planner",
                        }
                    )
                    trace.append(
                        AgentTraceEntry(
                            agent=self.name,
                            step="planning",
                            action="Model-generated investigation plan",
                            detail=plan["rationale"][:400],
                            status="ok",
                            latency_ms=int((time.perf_counter() - call_started) * 1000),
                            model=(response.model if response else None) or runtime.settings.text_model,
                        )
                    )
            except LLMUnavailable as exc:
                runtime.llm.mark_degraded(str(exc))
                trace.append(
                    AgentTraceEntry(
                        agent=self.name,
                        step="planning",
                        action="Model planner unavailable; rule-based plan used",
                        detail=str(exc)[:400],
                        status="warning",
                    )
                )

        # Deterministic guardrail: if the input visibly contains URLs, URL work is mandatory.
        text_for_urls = ""
        if primary == "message":
            text_for_urls = str((state.get("input") or {}).get("text") or "")
        if text_for_urls:
            found = extract_urls(text_for_urls, limit=10)
            if found and "url" not in plan["agents"]:
                plan["agents"].append("url")
                plan["rationale"] += " Links were detected in the input, so URL investigation was added."

        trace.append(
            AgentTraceEntry(
                agent=self.name,
                step="plan",
                action="Investigation plan selected",
                detail=" → ".join(plan["agents"]),
                status="ok",
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        )
        return {
            "plan": plan,
            "trace": trace,
            "visited": [self.name],
            "requested_agents": [],
            "rework_count": state.get("rework_count", 0),
            "entities": state.get("entities") or {},
        }
