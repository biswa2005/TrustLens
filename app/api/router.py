"""Aggregate API router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.health import router as health_router
from app.api.investigations import router as investigations_router
from app.modules.email.router import router as email_router
from app.modules.message.router import router as message_router
from app.modules.qr.router import router as qr_router
from app.modules.visual.router import router as visual_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(message_router)
api_router.include_router(qr_router)
api_router.include_router(visual_router)
api_router.include_router(email_router)
api_router.include_router(investigations_router)
