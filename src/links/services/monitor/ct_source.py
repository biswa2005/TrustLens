from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path


class CTSource(ABC):
    @abstractmethod
    async def connect(self): ...

    @abstractmethod
    async def messages(self): ...


class WebSocketCTSource(CTSource):
    def __init__(self, uri: str = "wss://certstream.calidog.io"):
        self.uri = uri
        self._socket = None

    async def connect(self):
        from websockets.asyncio.client import connect
        self._socket = await connect(self.uri, max_size=2 * 1024 * 1024, open_timeout=10, ping_interval=20)
        return self

    async def messages(self):
        if self._socket is None:
            raise RuntimeError("CT source is not connected")
        async for frame in self._socket:
            try:
                item = json.loads(frame)
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(item, dict):
                yield item

    async def close(self):
        if self._socket is not None:
            await self._socket.close()
            self._socket = None


class ReplayFixtureCTSource(CTSource):
    def __init__(self, fixture_path: Path):
        self.fixture_path = fixture_path
        self.lines: list[str] = []

    async def connect(self):
        self.lines = self.fixture_path.read_text(encoding="utf-8").splitlines()
        return self

    async def messages(self):
        for line in self.lines:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                yield item
