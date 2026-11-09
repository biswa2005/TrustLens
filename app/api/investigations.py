"""Report retrieval and evidence-verification routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.api.deps import get_services
from app.engine.evidence import verify_evidence_chain
from app.schemas import InvestigationReport, ReportSummary
from app.services import ForensicServices

router = APIRouter(prefix="/investigations", tags=["Investigations"])


@router.get(
    "",
    response_model=list[ReportSummary],
    summary="List recent investigations",
)
async def list_investigations(
    limit: int = Query(default=20, ge=1, le=200),
    module: str | None = Query(default=None),
    services: ForensicServices = Depends(get_services),
) -> list[ReportSummary]:
    if module is not None and module not in {"message", "qr", "visual", "email"}:
        raise HTTPException(status_code=422, detail="Unknown module filter.")
    return services.reports.list(limit=limit, module=module)


@router.get(
    "/{investigation_id}",
    response_model=InvestigationReport,
    summary="Retrieve a complete investigation report",
)
async def get_investigation(
    investigation_id: str,
    services: ForensicServices = Depends(get_services),
) -> InvestigationReport:
    report = services.reports.get(investigation_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return report


@router.get(
    "/{investigation_id}/markdown",
    summary="Download the report as Markdown",
    response_class=Response,
)
async def get_markdown(
    investigation_id: str,
    services: ForensicServices = Depends(get_services),
) -> Response:
    report = services.reports.get(investigation_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return Response(
        content=report.markdown,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'inline; filename="{report.id}.md"',
        },
    )


@router.post(
    "/{investigation_id}/verify",
    summary="Recompute the stored evidence hash chain",
)
async def verify_investigation(
    investigation_id: str,
    services: ForensicServices = Depends(get_services),
) -> dict[str, object]:
    report = services.reports.get(investigation_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    valid, errors = verify_evidence_chain(
        report.evidence, services.settings.signing_key
    )
    return {
        "investigation_id": report.id,
        "valid": valid,
        "errors": errors,
        "evidence_count": len(report.evidence),
        "evidence_fingerprint": report.metadata.get("evidence_fingerprint", ""),
    }
