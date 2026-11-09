"""Small, dependency-free helpers shared across the engine."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import unicodedata
from collections.abc import Iterable
from datetime import UTC
from typing import Any

ZERO_WIDTH_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
WHITESPACE_RE = re.compile(r"[ \t\u00a0]+")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def utc_iso() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat()


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def hmac_chain(secret: bytes, prev_hash: str, payload: Any) -> str:
    import hmac

    message = f"{prev_hash}|{stable_json(payload)}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def normalize_text(text: str, *, max_chars: int = 50_000) -> str:
    """Unicode-normalise and remove invisible characters used for obfuscation."""

    text = unicodedata.normalize("NFKC", text or "")
    text = ZERO_WIDTH_RE.sub("", text)
    text = CONTROL_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text[:max_chars]


def compact_whitespace(text: str) -> str:
    return WHITESPACE_RE.sub(" ", text).strip()


def truncate(value: str, limit: int = 600) -> str:
    value = value or ""
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = value.strip()
        if key and key not in seen:
            seen.add(key)
            result.append(key)
    return result


def is_public_ip(value: str) -> bool:
    """SSRF guard: only globally routable addresses may be fetched."""

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
    )


def redact_secrets(value: str) -> str:
    """Best-effort redaction of credentials in URLs before logging/storing."""

    value = re.sub(r"(?i)(token|key|secret|password|apikey|api_key)=([^&\s]+)", r"\1=***", value)
    value = re.sub(r"(?i)(https?://)([^/@\s]+)@", r"\1***@", value)
    return value


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def signal_id(prefix: str, *parts: str) -> str:
    raw = "|".join(parts)
    return f"{prefix}_{hashlib.sha256(raw.encode()).hexdigest()[:10]}"


def language_name(code: str) -> str:
    return {
        "en": "English",
        "hi": "Hindi",
        "bn": "Bengali",
        "hinglish": "Hinglish (Hindi written in Latin script)",
        "auto": "the sender's language",
    }.get(code, code)
