"""Service metadata and health routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_services
from app.schemas import ModelInfo
from app.services import ForensicServices

router = APIRouter(tags=["Service"])

MODULES = {
    "message": "Multilingual SMS/chat scam and manipulation analysis",
    "qr": "QR decoding, UPI semantics, URL extraction and infrastructure checks",
    "visual": "Screenshot brand-impersonation and credential-phishing analysis",
    "email": "EML parsing, SPF/DKIM/DMARC verification, BEC and attachment triage",
}


@router.get("/health", summary="Liveness and reasoning-mode health check")
async def health(services: ForensicServices = Depends(get_services)) -> dict[str, object]:
    return {
        "status": "ok",
        "app": services.settings.app_name,
        "version": services.settings.app_version,
        "environment": services.settings.environment,
        "reasoning_mode": services.llm.reasoning_mode,
        "degraded": services.llm.degraded,
        "network_enabled": services.settings.allow_network,
        "reports_cached": len(services.reports.list(limit=200)),
    }


@router.get("/meta", summary="Capabilities, configured providers and limits")
async def meta(services: ForensicServices = Depends(get_services)) -> dict[str, object]:
    settings = services.settings
    model: ModelInfo = services.llm.model_info()
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "modules": MODULES,
        "models": model.model_dump(mode="json"),
        "capabilities": {
            "multilingual": ["en", "hi", "bn", "hinglish"],
            "languages_supported": ["auto", "en", "hi", "bn", "hinglish"],
            "agents": [
                "orchestrator",
                "message",
                "qr",
                "visual",
                "email",
                "url",
                "evidence",
                "report",
            ],
            "evidence_chain": "HMAC-SHA256 hash chain",
            "risk_model": "additive category-capped rule engine (not ML)",
        },
        "limits": {
            "max_upload_mb": settings.max_upload_mb,
            "max_email_bytes": settings.max_email_bytes,
            "max_image_pixels": settings.max_image_pixels,
            "max_urls_per_investigation": settings.max_urls_per_investigation,
            "network_timeout_seconds": settings.network_timeout_seconds,
        },
        "network": {
            "allow_network": settings.allow_network,
            "page_fetch_enabled": settings.enable_page_fetch,
        },
        "threat_intelligence": settings.threat_intel_configured(),
    }
