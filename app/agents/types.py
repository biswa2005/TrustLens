"""Shared types for the agent layer."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from app.schemas import IOC, Evidence, EvidenceKind, Signal


@dataclass
class EvidenceDraft:
    kind: EvidenceKind
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.85
    verified: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class ToolResult:
    name: str
    summary: str
    evidence: list[Evidence] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    pending_urls: list[str] = field(default_factory=list)
    pending_domains: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[[dict[str, Any]], Awaitable[ToolResult]]

    def openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }
