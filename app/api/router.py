"""Aggregate API router."""

from __future__ import annotations

import sys
from pathlib import Path

# Allow importing the dev-branch URL-trust analysis service (src/).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from fastapi import APIRouter

from app.api.health import router as health_router
from app.api.investigations import router as investigations_router
from app.modules.email.router import router as email_router
from app.modules.message.router import router as message_router
from app.modules.qr.router import router as qr_router
from app.modules.visual.router import router as visual_router

try:
    from app.modules.threat_reports.router import router as threat_reports_router
except Exception:  # pragma: no cover - optional if web3/aiohttp unavailable
    threat_reports_router = None

try:
    from links.routes import router as links_router
except Exception:  # pragma: no cover - optional dev feature
    links_router = None

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(message_router)
api_router.include_router(qr_router)
api_router.include_router(visual_router)
api_router.include_router(email_router)
api_router.include_router(investigations_router)
if threat_reports_router is not None:
    api_router.include_router(threat_reports_router)
