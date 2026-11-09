from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from links.services.limiter import limiter

from links.services import db
from links.services.auth import require_api_key

router = APIRouter()


@router.get("/api/v1/monitor/status")
@limiter.limit("120/minute")
async def monitor_status(request: Request, owner_id: str = Depends(require_api_key)):
    if not db.pool:
        raise HTTPException(status_code=503, detail="Monitoring storage is unavailable")
    async with db.pool.connection() as conn:
        counts = await (await conn.execute(
            "SELECT count(*) FILTER (WHERE enabled), "
            "count(*) FILTER (WHERE enabled AND (lookalike_scanned_at IS NULL OR lookalike_scanned_at < now()-interval '24 hours')) "
            "FROM watch_domains WHERE owner_id=%s", (owner_id,),
        )).fetchone()
        alerts = await (await conn.execute(
            "SELECT count(*) FROM monitoring_alerts WHERE owner_id=%s AND status='new'", (owner_id,),
        )).fetchone()
        state = await (await conn.execute(
            "SELECT state,last_run_at FROM monitor_state WHERE task_name='worker'",
        )).fetchone()
    worker_state = state[0] if state and isinstance(state[0], dict) else {}
    worker_fresh = bool(state and state[1] and (state[1] > datetime.now(timezone.utc) - timedelta(seconds=45)))
    ct_stream = worker_state.get("ct_stream", {"status": "not_started", "stream_gaps_15m": 0, "last_message_at": None})
    if not worker_fresh and ct_stream.get("status") not in {"not_started", "worker_stale"}:
        ct_stream = {**ct_stream, "status": "worker_stale"}
    return {
        "worker_running": bool(worker_state.get("running", False) and worker_fresh),
        "advisory_lock_held": bool(worker_state.get("advisory_lock_held", False) and worker_fresh),
        "ct_stream": ct_stream,
        "tenant_metrics": {"owner_id": owner_id, "active_watches": counts[0], "pending_rescans": counts[1], "unacknowledged_alerts": alerts[0]},
        "system_state": worker_state.get("system_state", {}),
    }
