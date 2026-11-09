"""High-level LLM facade used by every agent.

Responsibilities:
* build chat calls against a Hugging Face-hosted instruction model;
* enforce JSON contracts (generative models are asked for structured output);
* keep an honest record of whether reasoning was model-driven or the offline
  expert-system fallback;
* expose vision calls for the screenshot and QR modules.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from app.config import Settings
from app.engine.hf import HFClient, LLMResponse, LLMUnavailable
from app.engine.utils import truncate
from app.schemas import ModelInfo

logger = logging.getLogger(__name__)

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_json(text: str) -> Any | None:
    """Extract the first balanced JSON object/array from model output."""

    if not text:
        return None
    candidates: list[str] = []
    fence = _FENCE_RE.search(text)
    if fence:
        candidates.append(fence.group(1).strip())
    candidates.append(text.strip())

    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
        start_positions = [idx for idx in (candidate.find("{"), candidate.find("[")) if idx >= 0]
        for start in sorted(start_positions):
            depth = 0
            in_string = False
            escape = False
            for index in range(start, len(candidate)):
                char = candidate[index]
                if in_string:
                    if escape:
                        escape = False
                    elif char == "\\":
                        escape = True
                    elif char == '"':
                        in_string = False
                    continue
                if char == '"':
                    in_string = True
                elif char in "{[":
                    depth += 1
                elif char in "}]":
                    depth -= 1
                    if depth == 0:
                        snippet = candidate[start : index + 1]
                        try:
                            return json.loads(snippet)
                        except json.JSONDecodeError:
                            # common model mistake: trailing commas
                            patched = re.sub(r",\s*([}\]])", r"\1", snippet)
                            try:
                                return json.loads(patched)
                            except json.JSONDecodeError:
                                break
    return None


class LLMService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = HFClient(settings)
        self.calls = 0
        self.failures = 0
        self.last_error: str | None = None
        self._used_llm = False
        self._degraded = not settings.hf_enabled

    @property
    def available(self) -> bool:
        return self.settings.hf_enabled

    @property
    def reasoning_mode(self) -> str:
        return "huggingface" if self._used_llm and not self._degraded else "offline-expert-system"

    @property
    def degraded(self) -> bool:
        return self._degraded

    def mark_degraded(self, reason: str) -> None:
        self._degraded = True
        self.last_error = reason
        logger.warning("LLM degraded: %s", truncate(reason, 300))

    async def close(self) -> None:
        await self.client.close()

    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResponse:
        if not self.available:
            raise LLMUnavailable("Hugging Face reasoning is not configured (LLM_MODE=offline or no HF_TOKEN)")
        self.calls += 1
        try:
            response = await self.client.chat(
                messages,
                tools=tools,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            self._used_llm = True
            return response
        except LLMUnavailable as exc:
            self.failures += 1
            self.last_error = str(exc)
            raise

    async def json_chat(
        self,
        system: str,
        user: str,
        *,
        model: str | None = None,
        max_tokens: int | None = None,
        schema_hint: str | None = None,
    ) -> tuple[dict[str, Any] | None, LLMResponse | None]:
        """Ask the model for one JSON object, with a single repair attempt."""

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        response = await self.chat(messages, model=model or self.settings.text_model, max_tokens=max_tokens)
        parsed = extract_json(response.content)
        if isinstance(parsed, dict):
            return parsed, response
        if isinstance(parsed, list):
            return {"items": parsed}, response

        repair_messages = messages + [
            {"role": "assistant", "content": truncate(response.content, 4000)},
            {
                "role": "user",
                "content": (
                    "Your previous answer was not valid JSON. Return ONLY a single valid JSON "
                    "object, with no markdown or commentary."
                    + (f" Required shape: {schema_hint}" if schema_hint else "")
                ),
            },
        ]
        repaired = await self.chat(
            repair_messages,
            model=model or self.settings.text_model,
            max_tokens=max_tokens,
            temperature=0.0,
        )
        parsed = extract_json(repaired.content)
        if isinstance(parsed, dict):
            return parsed, repaired
        if isinstance(parsed, list):
            return {"items": parsed}, repaired
        self.mark_degraded("Model returned invalid JSON twice")
        return None, repaired

    async def vision_json(
        self,
        system: str,
        prompt: str,
        images: list[tuple[bytes, str]],
        *,
        model: str | None = None,
        max_tokens: int | None = None,
    ) -> tuple[dict[str, Any] | None, LLMResponse | None]:
        if not self.available:
            raise LLMUnavailable("Vision reasoning is not configured")

        self.calls += 1
        try:
            response = await self.client.vision(
                prompt,
                images,
                system=system,
                model=model or self.settings.vision_model,
                json_mode=True,
                max_tokens=max_tokens,
            )
            self._used_llm = True
        except LLMUnavailable as exc:
            self.failures += 1
            self.last_error = str(exc)
            raise

        parsed = extract_json(response.content)
        if isinstance(parsed, dict):
            return parsed, response
        if isinstance(parsed, list):
            return {"items": parsed}, response
        self.mark_degraded("Vision model returned invalid JSON")
        return None, response

    def model_info(self) -> ModelInfo:
        return ModelInfo(
            text_model=self.settings.text_model,
            vision_model=self.settings.vision_model,
            reasoning_mode="huggingface" if self._used_llm and not self._degraded else "offline-expert-system",
            degraded=self.degraded,
            providers=["huggingface-router"] if self.settings.hf_enabled else [],
            notes=(
                "Pretrained instruction-tuned model reasoning over tool-produced evidence."
                if self.settings.hf_enabled and not self.degraded
                else (
                    "Offline expert-system fallback: every observation still comes from the "
                    "deterministic forensic tools, but narrative synthesis is template-based. "
                    "Set HF_TOKEN to enable generative reasoning."
                )
            ),
        )
