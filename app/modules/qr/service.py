"""QR-code investigation module."""

from __future__ import annotations

from app.engine.utils import truncate
from app.modules.common import execute, safe_language, validate_image
from app.schemas import InvestigationReport
from app.services import ForensicServices


async def analyze(
    services: ForensicServices,
    *,
    image_bytes: bytes,
    filename: str,
    content_type: str | None,
    caption: str | None,
    language: str,
) -> InvestigationReport:
    settings = services.settings
    width, height, fmt = validate_image(image_bytes, settings.max_image_pixels)
    payload = {
        "filename": filename,
        "size": len(image_bytes),
        "content_type": content_type,
        "width": width,
        "height": height,
        "format": fmt,
        "caption": caption,
    }
    summary = f"QR image '{filename}' ({width}×{height}, {fmt})"
    if caption:
        summary += f". User-supplied context: {truncate(caption, 200)}"
    return await execute(
        services=services,
        module="qr",
        language=safe_language(language),
        payload=payload,
        artifacts={"image_bytes": image_bytes, "caption": caption or ""},
        input_summary=summary,
    )
