"""LangGraph investigation workflow.

The graph is a shared blackboard: each node contributes findings, signals, IOCs
and trace entries, while the evidence ledger itself lives outside graph state in
:class:`~app.engine.evidence.EvidenceStore`.  Routing is conditional, so the URL
agent only runs when links exist and the evidence agent can request one bounded
rework pass.
"""

from __future__ import annotations

import logging
from typing import Any

from langgraph.graph import END, START, StateGraph

from app.agents.email_agent import EmailForensicsAgent
from app.agents.evidence_agent import EvidenceVerificationAgent
from app.agents.message_agent import MessageInvestigationAgent
from app.agents.orchestrator import OrchestratorAgent
from app.agents.qr_agent import QRInvestigationAgent
from app.agents.report_agent import FinalReportAgent
from app.agents.runtime import AgentRuntime
from app.agents.state import InvestigationState
from app.agents.toolbox import Toolbox
from app.agents.url_agent import URLIntelligenceAgent
from app.agents.visual_agent import VisualWebsiteAgent
from app.engine.evidence import EvidenceStore
from app.engine.report import ReportBuilder
from app.engine.utils import new_id
from app.services import ForensicServices

logger = logging.getLogger(__name__)

SPECIALISTS = {"message", "qr", "visual", "email"}


def _has_url_work(state: InvestigationState) -> bool:
    return bool(state.get("pending_urls") or state.get("pending_domains"))


def build_graph(runtime: AgentRuntime):
    """Build a compiled LangGraph for one investigation."""

    orchestrator = OrchestratorAgent()
    specialists = {
        "message": MessageInvestigationAgent(),
        "qr": QRInvestigationAgent(),
        "visual": VisualWebsiteAgent(),
        "email": EmailForensicsAgent(),
    }
    url_agent = URLIntelligenceAgent()
    evidence_agent = EvidenceVerificationAgent()
    report_agent = FinalReportAgent()

    async def run_orchestrator(state: InvestigationState) -> dict[str, Any]:
        return await orchestrator.run(state, runtime)

    graph = StateGraph(InvestigationState)
    graph.add_node("orchestrator", run_orchestrator)
    for name, agent in specialists.items():

        async def run_specialist(
            state: InvestigationState, _agent=agent
        ) -> dict[str, Any]:
            return await _agent.run(state, runtime)

        graph.add_node(name, run_specialist)

    async def run_url(state: InvestigationState) -> dict[str, Any]:
        return await url_agent.run(state, runtime)

    async def run_evidence(state: InvestigationState) -> dict[str, Any]:
        return await evidence_agent.run(state, runtime)

    async def run_report(state: InvestigationState) -> dict[str, Any]:
        return await report_agent.run(state, runtime)

    graph.add_node("url", run_url)
    graph.add_node("evidence", run_evidence)
    graph.add_node("report", run_report)

    graph.add_edge(START, "orchestrator")
    graph.add_conditional_edges(
        "orchestrator",
        lambda state: _route_after_orchestrator(state, runtime),
        {**{name: name for name in SPECIALISTS}, "url": "url", "evidence": "evidence", "report": "report"},
    )
    for name in SPECIALISTS:
        graph.add_conditional_edges(
            name,
            _route_after_specialist,
            {"url": "url", "evidence": "evidence"},
        )
    graph.add_edge("url", "evidence")
    graph.add_conditional_edges(
        "evidence",
        _route_after_evidence,
        {**{name: name for name in SPECIALISTS}, "url": "url", "report": "report"},
    )
    graph.add_edge("report", END)
    return graph.compile()


def _route_after_orchestrator(state: InvestigationState, runtime: AgentRuntime) -> str:
    plan = state.get("plan") or {}
    primary = str(plan.get("primary") or state.get("module") or "message")
    if primary not in SPECIALISTS:
        primary = "message"
    if primary not in (state.get("visited") or []):
        return primary
    if _has_url_work(state) or "url" in (state.get("requested_agents") or []):
        return "url"
    if "evidence" not in (state.get("visited") or []):
        return "evidence"
    return "report"


def _route_after_specialist(state: InvestigationState) -> str:
    if _has_url_work(state) or "url" in (state.get("requested_agents") or []):
        return "url"
    return "evidence"


def _route_after_evidence(state: InvestigationState) -> str:
    requested = [
        item
        for item in (state.get("requested_agents") or [])
        if isinstance(item, str)
    ]
    rework_count = int(state.get("rework_count") or 0)
    if "url" in requested and rework_count <= 2 and _has_url_work(state):
        return "url"
    for name in ("message", "qr", "visual", "email"):
        if name in requested and name not in (state.get("visited") or []):
            return name
    return "report"


async def run_investigation(
    *,
    services: ForensicServices,
    module: str,
    language: str,
    payload: dict[str, Any],
    artifacts: dict[str, Any],
    input_summary: str,
    investigation_id: str | None = None,
    max_steps: int = 40,
) -> InvestigationState:
    """Create an isolated runtime, execute the graph and return final state."""

    settings = services.settings
    inv_id = investigation_id or new_id("inv")
    store = EvidenceStore(settings)
    toolbox = Toolbox(settings, services.llm, services, store, artifacts)
    runtime = AgentRuntime(
        settings=settings,
        llm=services.llm,
        services=services,
        store=store,
        toolbox=toolbox,
        report_builder=ReportBuilder(),
        module=module,
        language=language,
        investigation_id=inv_id,
    )
    graph = build_graph(runtime)
    initial: InvestigationState = {
        "investigation_id": inv_id,
        "module": module,
        "language": language,
        "input": payload,
        "input_summary": input_summary,
        "artifacts": artifacts,
        "findings": [],
        "signals": [],
        "iocs": [],
        "trace": [],
        "visited": [],
        "agent_summaries": [],
        "entities": {},
        "pending_urls": [],
        "pending_domains": [],
        "requested_agents": [],
        "rework_count": 0,
        "status": "running",
        "error": None,
    }
    config = {"recursion_limit": max_steps}
    try:
        result = await graph.ainvoke(initial, config=config)
    except Exception as exc:
        logger.exception("Investigation graph failed: %s", exc)
        # Preserve the evidence ledger and still produce a report, clearly marked
        # as failed/degraded, rather than losing the collected evidence.
        failure_state: InvestigationState = {
            **initial,
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}",
            "input_summary": input_summary + f" (workflow error: {type(exc).__name__})",
        }
        try:
            failure_state.update(await FinalReportAgent().run(failure_state, runtime))
        except Exception:
            logger.exception("Fallback report generation also failed")
            raise exc
        return failure_state
    result.setdefault("status", "completed")
    return result  # type: ignore[return-value]
