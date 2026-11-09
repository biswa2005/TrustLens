import os, sys
import uuid
import logging
from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from links.schemas import AnalyseRequest, ScreenRequest
from links.services import db
from links.services.analyser import analyse, screen_url
from links.services.checks.normalise import normalize
from links.services.db import save_report
from links.services.limiter import limiter

router=APIRouter()
log=logging.getLogger(__name__)

async def _live_distrust_hook(report):
    try:
        from links.services.monitor.ca import check_and_emit_distrust_alert
        await check_and_emit_distrust_alert(report)
    except Exception:
        log.exception("Monitoring hook error")

@router.post("/api/v1/analyse/url")
@limiter.limit("20/minute")
async def analyse_url(request:Request,payload: AnalyseRequest,background_tasks:BackgroundTasks):
    try: normalize(payload.url)
    except ValueError: raise HTTPException(status_code=400,detail="Invalid URL")
    try:
        report=await analyse(payload.url, payload.skip_third_party_reputation)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Analysis failed") from exc
    try:
        report_id=await save_report(report)
        if report_id: report=report.model_copy(update={"report_id":report_id})
    except Exception as exc: raise HTTPException(status_code=503,detail="Report storage is unavailable") from exc
    if report.tls_reports:
        background_tasks.add_task(_live_distrust_hook, report)
    return report

@router.post("/api/v1/screen/url")
@limiter.limit("20/minute")
async def screen_url_route(request:Request,payload: ScreenRequest):
    try:
        raw = payload.url if payload.mode == "full" else f"https://{payload.host}/"
        return await screen_url(raw, payload.mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid URL") from exc

@router.get("/api/v1/reports/{report_id}")
async def get_report(report_id:str):
    try: canonical=str(uuid.UUID(report_id))
    except ValueError: raise HTTPException(status_code=400,detail="Invalid report id")
    try: report=await db.get_report(canonical)
    except Exception as exc: raise HTTPException(status_code=503,detail="Report storage is unavailable") from exc
    if report is None: raise HTTPException(status_code=404,detail="Report not found")
    return report

def main() -> None:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from links.services.runtime import run_uvicorn
    run_uvicorn("main:app",host="0.0.0.0",port=int(os.environ.get("PORT","8000")))
