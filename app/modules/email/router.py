"""Email module HTTP routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from app.api.deps import get_services
from app.modules.common import envelope, read_upload
from app.modules.email.service import analyze
from app.schemas import ReportEnvelope
from app.services import ForensicServices

router = APIRouter(prefix="/email", tags=["Email Investigation"])


@router.post(
    "/analyze",
    response_model=ReportEnvelope,
    summary="Parse an EML file, verify SPF/DKIM/DMARC and investigate BEC/phishing",
)
async def analyze_email(
    eml: Annotated[UploadFile, File(description="Raw RFC 822 / .eml message")],
    language: Annotated[str, Form(description="auto|en|hi|bn|hinglish")] = "auto",
    services: ForensicServices = Depends(get_services),
) -> ReportEnvelope:
    limit = min(
        services.settings.max_email_bytes,
        services.settings.max_upload_mb * 1024 * 1024,
    )
    raw = await read_upload(eml, limit, kind="email")
    probe = raw[:65_536].lower()
    if b"from:" not in probe and b"subject:" not in probe:
        raise HTTPException(
            status_code=422,
            detail="The uploaded file does not look like an RFC 822 / .eml message.",
        )
    report = await analyze(
        services,
        eml_bytes=raw,
        filename=eml.filename or "message.eml",
        content_type=eml.content_type,
        language=language,
    )
    return envelope(report)
