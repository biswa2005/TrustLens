"""Hugging Face Inference client (OpenAI-compatible router).

Only pretrained generative models are used.  There is no classifier training,
fine-tuning or scikit-learn model anywhere in this project: the language model
reasons over evidence produced by deterministic forensic tools.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import Settings
from app.engine.utils import truncate

logger = logging.getLogger(__name__)


class LLMUnavailable(RuntimeError):
    """Raised when the configured model cannot be reached or refuses to answer."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    raw_arguments: str = ""


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    model: str = ""
    usage: dict[str, Any] = field(default_factory=dict)
    finish_reason: str = "stop"


class HFClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client: httpx.AsyncClient | None = None
        self.last_error: str | None = None

    @property
    def token(self) -> str:
        return self.settings.hf_token.get_secret_value() if self.settings.hf_token else ""

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.settings.hf_base_url.rstrip("/"),
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "User-Agent": self.settings.user_agent,
                },
                timeout=httpx.Timeout(self.settings.llm_timeout_seconds, connect=15.0),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> LLMResponse:
        if not self.token:
            raise LLMUnavailable("HF_TOKEN is not configured")

        payload: dict[str, Any] = {
            "model": model or self.settings.text_model,
            "messages": messages,
            "temperature": (
                self.settings.llm_temperature if temperature is None else temperature
            ),
            "max_tokens": max_tokens or self.settings.llm_max_tokens,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if response_format:
            payload["response_format"] = response_format

        data = await self._post_with_retries(payload)
        return self._parse_response(data)

    async def vision(
        self,
        prompt: str,
        images: list[tuple[bytes, str]],
        *,
        system: str | None = None,
        model: str | None = None,
        json_mode: bool = True,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        if not self.token:
            raise LLMUnavailable("HF_TOKEN is not configured")
        content: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
        for blob, mime in images:
            encoded = base64.b64encode(blob).decode("ascii")
            content.append(
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:{mime};base64,{encoded}"},
                }
            )
        messages: list[dict[str, Any]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": content})
        payload: dict[str, Any] = {
            "model": model or self.settings.vision_model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": max_tokens or self.settings.llm_max_tokens,
            "stream": False,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        data = await self._post_with_retries(payload)
        return self._parse_response(data)

    async def _post_with_retries(self, payload: dict[str, Any]) -> dict[str, Any]:
        attempts = max(1, self.settings.llm_retries + 1)
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                client = self._get_client()
                response = await client.post("/chat/completions", json=payload)
                if response.status_code in {429, 500, 502, 503, 504} and attempt + 1 < attempts:
                    delay = 1.25 * (2**attempt)
                    logger.warning(
                        "HF router returned %s; retrying in %.1fs", response.status_code, delay
                    )
                    await asyncio.sleep(delay)
                    continue
                if response.status_code >= 400:
                    detail = truncate(response.text, 700)
                    self.last_error = f"HTTP {response.status_code}: {detail}"
                    raise LLMUnavailable(self.last_error)
                return response.json()
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                self.last_error = f"{type(exc).__name__}: {exc}"
                if attempt + 1 < attempts:
                    await asyncio.sleep(1.25 * (2**attempt))
                    continue
                raise LLMUnavailable(self.last_error) from exc
        raise LLMUnavailable(f"HF request failed: {last_exc or self.last_error}")

    @staticmethod
    def _parse_response(data: dict[str, Any]) -> LLMResponse:
        try:
            choice = data["choices"][0]
        except (KeyError, IndexError, TypeError) as exc:  # pragma: no cover - defensive
            raise LLMUnavailable(f"Unexpected HF response shape: {truncate(json.dumps(data), 400)}") from exc

        message = choice.get("message") or {}
        content = message.get("content") or ""
        if isinstance(content, list):  # some providers return content parts
            content = "\n".join(
                part.get("text", "") for part in content if isinstance(part, dict)
            )
        tool_calls: list[ToolCall] = []
        for index, call in enumerate(message.get("tool_calls") or []):
            function = call.get("function") or {}
            raw_args = function.get("arguments") or "{}"
            try:
                arguments = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError:
                arguments = {}
            tool_calls.append(
                ToolCall(
                    id=call.get("id") or f"call_{index}",
                    name=function.get("name") or "",
                    arguments=arguments if isinstance(arguments, dict) else {},
                    raw_arguments=raw_args if isinstance(raw_args, str) else "",
                )
            )
        return LLMResponse(
            content=content.strip(),
            tool_calls=tool_calls,
            model=data.get("model") or "",
            usage=data.get("usage") or {},
            finish_reason=choice.get("finish_reason") or "stop",
        )
