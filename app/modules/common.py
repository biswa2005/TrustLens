"""Shared helpers for the four HTTP modules."""

from __future__ import annotations

import io
from typing import Any

from fastapi import HTTPException, UploadFile
from PIL import Image, UnidentifiedImageError

from app.agents.graph import run_investigation
from app.engine.utils import truncate
from app.schemas import InvestigationReport, ReportEnvelope
from app.services import ForensicServices


async def read_upload(file: UploadFile, max_bytes: int, *, kind: str) -> bytes:
    if file is None or not file.filename:
        raise HTTPException(status_code=422, detail=f"A {kind} file is required.")
    raw = await file.read(max_bytes + 1)
    if not raw:
        raise HTTPException(status_code=422, detail=f"The uploaded {kind} file is empty.")
    if len(raw) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"The {kind} file exceeds the {max_bytes // (1024 * 1024)} MB limit.",
        )
    return raw


def validate_image(raw: bytes, max_pixels: int) -> tuple[int, int, str]:
    try:
        with Image.open(io.BytesIO(raw)) as probe:
            probe.verify()
        with Image.open(io.BytesIO(raw)) as image:
            width, height = image.size
            fmt = (image.format or "unknown").upper()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"The uploaded file is not a readable image: {type(exc).__name__}.",
        ) from exc
    if width <= 0 or height <= 0:
        raise HTTPException(status_code=422, detail="The image has invalid dimensions.")
    if width * height > max_pixels:
        raise HTTPException(
            status_code=413,
            detail=f"The image has {width * height} pixels; the limit is {max_pixels}.",
        )
    return width, height, fmt


async def execute(
    *,
    services: ForensicServices,
    module: str,
    language: str,
    payload: dict[str, Any],
    artifacts: dict[str, Any],
    input_summary: str,
) -> InvestigationReport:
    state = await run_investigation(
        services=services,
        module=module,
        language=language,
        payload=payload,
        artifacts=artifacts,
        input_summary=truncate(input_summary, 1200),
    )
    report = state.get("report")
    if not isinstance(report, InvestigationReport):
        raise HTTPException(
            status_code=500,
            detail=(
                "The investigation did not produce a report"
                + (f": {state.get('error')}" if state.get("error") else ".")
            ),
        )
    return report


def envelope(report: InvestigationReport) -> ReportEnvelope:
    return ReportEnvelope(
        investigation_id=report.id,
        module=report.module,
        report=report,
    )


def safe_language(value: str | None) -> str:
    allowed = {"auto", "en", "hi", "bn", "hinglish"}
    candidate = (value or "auto").strip().lower()
    return candidate if candidate in allowed else "auto"
