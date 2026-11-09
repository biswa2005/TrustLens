"""FastAPI dependencies."""

from __future__ import annotations

from fastapi import Request

from app.services import ForensicServices


def get_services(request: Request) -> ForensicServices:
    services = getattr(request.app.state, "services", None)
    if services is None:  # pragma: no cover - lifespan always sets this
        raise RuntimeError("Forensic services are not initialised")
    return services
