"""Screenshot / visual website impersonation module."""

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
    brand_hint: str | None,
    claimed_url: str | None,
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
        "brand_hint": brand_hint,
        "claimed_url": claimed_url,
    }
    summary = f"Website screenshot '{filename}' ({width}×{height}, {fmt})"
    if brand_hint:
        summary += f", claimed brand: {truncate(brand_hint, 80)}"
    if claimed_url:
        summary += f", claimed URL: {truncate(claimed_url, 160)}"
    return await execute(
        services=services,
        module="visual",
        language=safe_language(language),
        payload=payload,
        artifacts={
            "image_bytes": image_bytes,
            "brand_hint": brand_hint or "",
            "claimed_url": claimed_url or "",
        },
        input_summary=summary,
    )
