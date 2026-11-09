"""Message / SMS scam-analysis module."""

from __future__ import annotations

from app.engine.utils import truncate
from app.modules.common import execute, safe_language
from app.modules.message.schemas import MessageAnalysisRequest
from app.schemas import InvestigationReport
from app.services import ForensicServices


async def analyze(
    services: ForensicServices, request: MessageAnalysisRequest
) -> InvestigationReport:
    payload = request.model_dump()
    summary = (
        f"{request.channel.upper()} message"
        + (f" from {request.sender}" if request.sender else "")
        + f": {truncate(request.text, 240)}"
    )
    return await execute(
        services=services,
        module="message",
        language=safe_language(request.language),
        payload=payload,
        artifacts={},
        input_summary=summary,
    )
