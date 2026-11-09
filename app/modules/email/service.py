"""Email forensics module."""

from __future__ import annotations

from app.modules.common import execute, safe_language
from app.schemas import InvestigationReport
from app.services import ForensicServices


async def analyze(
    services: ForensicServices,
    *,
    eml_bytes: bytes,
    filename: str,
    content_type: str | None,
    language: str,
) -> InvestigationReport:
    payload = {
        "filename": filename,
        "size": len(eml_bytes),
        "content_type": content_type,
    }
    return await execute(
        services=services,
        module="email",
        language=safe_language(language),
        payload=payload,
        artifacts={"eml_bytes": eml_bytes},
        input_summary=f"Uploaded email '{filename}' ({len(eml_bytes)} bytes)",
    )
