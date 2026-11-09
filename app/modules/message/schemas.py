"""Request models for the message module."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class MessageAnalysisRequest(BaseModel):
    text: str = Field(
        min_length=1,
        max_length=20_000,
        description="The SMS/chat message body to investigate.",
    )
    language: Literal["auto", "en", "hi", "bn", "hinglish"] = "auto"
    channel: Literal["sms", "whatsapp", "chat", "email", "other"] = "sms"
    sender: str | None = Field(default=None, max_length=200)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-sensitive context (campaign, recipient segment, etc.).",
    )
