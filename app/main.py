"""ThreatLens FastAPI application."""

from __future__ import annotations
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from dotenv import load_dotenv

# Ensure src/* components (threat reports, chain, db) see .env variables.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.api.health import router as health_router
from app.api.router import api_router
from app.config import Settings, get_settings
from app.services import ForensicServices, build_services

logger = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    services: ForensicServices | None = None,
) -> FastAPI:
    resolved = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        runtime_services = services or build_services(resolved)
        app.state.services = runtime_services
        app.state.settings = resolved
        logger.info(
            "%s %s starting (reasoning=%s, network=%s)",
            resolved.app_name,
            resolved.app_version,
            runtime_services.llm.reasoning_mode,
            resolved.allow_network,
        )
        try:
            yield
        finally:
            await runtime_services.close()

    app = FastAPI(
        title=resolved.app_name,
        version=resolved.app_version,
        description=(
            "Evidence-first, multi-agent digital-fraud investigation API. "
            "Modules: multilingual message analysis, QR/UPI decoding, screenshot "
            "brand-impersonation detection and email forensics (SPF/DKIM/DMARC, BEC, "
            "attachment triage). Every finding cites tamper-evident evidence."
        ),
        lifespan=lifespan,
        openapi_tags=[
            {"name": "Service", "description": "Health, capability and model metadata."},
            {"name": "Message Investigation", "description": "SMS/WhatsApp/chat scams."},
            {"name": "QR Investigation", "description": "QR payloads, UPI and URLs."},
            {"name": "Visual Investigation", "description": "Screenshot impersonation."},
            {"name": "Email Investigation", "description": "EML, authentication and BEC."},
            {"name": "Investigations", "description": "Stored reports and chain verification."},
        ],
    )

    origins = resolved.cors_origin_list
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router, prefix=resolved.api_prefix)
    app.include_router(health_router)

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse(url="/docs")

    return app


app = create_app()
