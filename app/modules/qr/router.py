"""QR module HTTP routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, UploadFile

from app.api.deps import get_services
from app.modules.common import envelope, read_upload
from app.modules.qr.service import analyze
from app.schemas import ReportEnvelope
from app.services import ForensicServices

router = APIRouter(prefix="/qr", tags=["QR Investigation"])


@router.post(
    "/analyze",
    response_model=ReportEnvelope,
    summary="Decode a QR image and investigate its payment/URL semantics",
)
async def analyze_qr(
    image: Annotated[UploadFile, File(description="QR code image (PNG/JPEG/WebP)")],
    caption: Annotated[
        str | None, Form(description="Visible text or claim surrounding the QR code")
    ] = None,
    language: Annotated[str, Form(description="auto|en|hi|bn|hinglish")] = "auto",
    services: ForensicServices = Depends(get_services),
) -> ReportEnvelope:
    raw = await read_upload(
        image,
        services.settings.max_upload_mb * 1024 * 1024,
        kind="QR image",
    )
    report = await analyze(
        services,
        image_bytes=raw,
        filename=image.filename or "qr-image",
        content_type=image.content_type,
        caption=caption,
        language=language,
    )
    return envelope(report)
