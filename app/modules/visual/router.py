"""Visual module HTTP routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, UploadFile

from app.api.deps import get_services
from app.modules.common import envelope, read_upload
from app.modules.visual.service import analyze
from app.schemas import ReportEnvelope
from app.services import ForensicServices

router = APIRouter(prefix="/visual", tags=["Visual Investigation"])


@router.post(
    "/analyze",
    response_model=ReportEnvelope,
    summary="Detect brand impersonation and credential phishing in a screenshot",
)
async def analyze_screenshot(
    image: Annotated[UploadFile, File(description="Website screenshot (PNG/JPEG/WebP)")],
    brand_hint: Annotated[
        str | None, Form(description="Brand the page appears to claim")
    ] = None,
    claimed_url: Annotated[
        str | None, Form(description="URL shown in the screenshot or supplied by the user")
    ] = None,
    language: Annotated[str, Form(description="auto|en|hi|bn|hinglish")] = "auto",
    services: ForensicServices = Depends(get_services),
) -> ReportEnvelope:
    raw = await read_upload(
        image,
        services.settings.max_upload_mb * 1024 * 1024,
        kind="screenshot",
    )
    report = await analyze(
        services,
        image_bytes=raw,
        filename=image.filename or "screenshot",
        content_type=image.content_type,
        brand_hint=brand_hint,
        claimed_url=claimed_url,
        language=language,
    )
    return envelope(report)
