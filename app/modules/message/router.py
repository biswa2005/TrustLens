"""Message module HTTP routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_services
from app.modules.common import envelope
from app.modules.message.schemas import MessageAnalysisRequest
from app.modules.message.service import analyze
from app.schemas import ReportEnvelope
from app.services import ForensicServices

router = APIRouter(prefix="/messages", tags=["Message Investigation"])


@router.post(
    "/analyze",
    response_model=ReportEnvelope,
    summary="Investigate a suspicious SMS, WhatsApp or chat message",
)
async def analyze_message(
    request: MessageAnalysisRequest,
    services: ForensicServices = Depends(get_services),
) -> ReportEnvelope:
    report = await analyze(services, request)
    return envelope(report)
