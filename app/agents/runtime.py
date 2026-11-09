"""Per-investigation runtime handed to every LangGraph node."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.agents.toolbox import Toolbox
from app.config import Settings
from app.engine.evidence import EvidenceStore
from app.engine.llm import LLMService
from app.engine.report import ReportBuilder
from app.services import ForensicServices


@dataclass
class AgentRuntime:
    settings: Settings
    llm: LLMService
    services: ForensicServices
    store: EvidenceStore
    toolbox: Toolbox
    report_builder: ReportBuilder
    module: str
    language: str
    investigation_id: str

    def evidence_digest(self, limit: int = 30) -> list[dict[str, Any]]:
        return self.store.digest(limit=limit, max_chars=900)

    def evidence_ids(self) -> set[str]:
        return set(self.store.evidence_ids())

    def default_evidence_ids(self, limit: int = 3) -> list[str]:
        return self.store.evidence_ids()[-limit:]
