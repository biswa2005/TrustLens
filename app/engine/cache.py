"""Tiny async TTL cache used for DNS, RDAP and threat-intelligence lookups."""

from __future__ import annotations

import time
from typing import Any


class TTLCache:
    def __init__(self, max_size: int = 2048, default_ttl: int = 3600) -> None:
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._data: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires_at, value = item
        if expires_at < time.monotonic():
            self._data.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        if len(self._data) >= self.max_size:
            # evict the oldest insertion (good enough for this workload)
            oldest = min(self._data, key=lambda k: self._data[k][0])
            self._data.pop(oldest, None)
        self._data[key] = (time.monotonic() + (ttl or self.default_ttl), value)

    def clear(self) -> None:
        self._data.clear()
