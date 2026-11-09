"""Uvicorn startup helpers for the supported host platforms."""
from __future__ import annotations

import asyncio
import sys


def event_loop_factory(platform: str | None = None):
    """Return the Psycopg-compatible Windows loop factory when needed."""
    current = sys.platform if platform is None else platform
    return asyncio.SelectorEventLoop if current == "win32" else None


def run_uvicorn(app: str, *, host: str, port: int) -> None:
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port))
    factory = event_loop_factory()
    if factory is None:
        server.run()
    else:
        # Uvicorn 0.54 selects ProactorEventLoop itself on Windows. Calling
        # serve() under asyncio.run bypasses that factory and uses Selector.
        asyncio.run(server.serve(), loop_factory=factory)
