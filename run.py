"""Convenience launcher for ThreatLens.

Usage:
    python run.py                 # http://127.0.0.1:8000 (docs at /docs)
    python run.py --port 9000
    python run.py --host 0.0.0.0 --port 8000 --reload

Equivalent to: uvicorn app.main:app --host ... --port ...
"""

from __future__ import annotations

import argparse

import uvicorn
from app.config import get_settings


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Run the ThreatLens API server.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    args = parser.parse_args()

    print(
        f"ThreatLens {settings.app_version} -> http://{args.host}:{args.port} "
        f"(docs: http://{args.host}:{args.port}/docs, env: {settings.environment})"
    )
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
