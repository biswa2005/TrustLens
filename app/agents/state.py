"""LangGraph shared blackboard state."""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from app.schemas import IOC, AgentTraceEntry, Finding, InvestigationReport, Signal


def _merge_lists(left: list | None, right: list | None) -> list:
    return (left or []) + (right or [])


class InvestigationState(TypedDict, total=False):
    # request
    investigation_id: str
    module: str
    language: str
    input: dict[str, Any]
    input_summary: str
    artifacts: dict[str, Any]

    # orchestration
    plan: dict[str, Any]
    pending_urls: list[str]
    pending_domains: list[str]
    requested_agents: list[str]
    rework_count: int

    # blackboard
    findings: Annotated[list[Finding], _merge_lists]
    signals: Annotated[list[Signal], _merge_lists]
    iocs: Annotated[list[IOC], _merge_lists]
    trace: Annotated[list[AgentTraceEntry], _merge_lists]
    visited: Annotated[list[str], _merge_lists]
    agent_summaries: Annotated[list[dict[str, Any]], _merge_lists]
    entities: dict[str, Any]

    # outputs
    verification: dict[str, Any]
    evidence_chain_valid: bool
    report: InvestigationReport | None
    status: str
    error: str | None
