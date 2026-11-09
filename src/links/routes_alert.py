from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from links.services.limiter import limiter

from links.services import db
from links.services.auth import require_api_key
from links.services.monitor.ct import invalidate_watch_cache

router = APIRouter()


class AlertAction(BaseModel):
    trust_issuer: bool = False
    reason: str | None = Field(default=None, max_length=500)


@router.get("/api/v1/monitor/alerts")
@limiter.limit("120/minute")
async def list_alerts(
    request: Request,
    status: str | None = Query(default=None, pattern="^(new|acknowledged|dismissed)$"),
    severity: str | None = Query(default=None, pattern="^(info|moderate|strong)$"),
    kind: str | None = Query(default=None, pattern="^(lookalike_transition|ca_distrust|ct_issuance)$"),
    watch_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    owner_id: str = Depends(require_api_key),
):
    if not db.pool:
        raise HTTPException(status_code=503, detail="Monitoring storage is unavailable")
    try:
        watch_uuid = uuid.UUID(watch_id) if watch_id else None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid watch id") from exc
    where = ["owner_id=%s"]
    values: list[object] = [owner_id]
    for column, value in (("status", status), ("severity", severity), ("kind", kind), ("watch_id", watch_uuid)):
        if value is not None:
            where.append(f"{column}=%s")
            values.append(value)
    clause = " AND ".join(where)
    async with db.pool.connection() as conn:
        total = (await (await conn.execute(f"SELECT count(*) FROM monitoring_alerts WHERE {clause}", values)).fetchone())[0]
        rows = await (await conn.execute(
            f"SELECT id,watch_id,kind,severity,status,target,evidence,source,dismiss_reason,observed_at,acknowledged_at,limitations "
            f"FROM monitoring_alerts WHERE {clause} ORDER BY observed_at DESC LIMIT %s OFFSET %s",
            [*values, limit, offset],
        )).fetchall()
    keys = ("id", "watch_id", "kind", "severity", "status", "target", "evidence", "source", "dismiss_reason", "observed_at", "acknowledged_at", "limitations")
    return {"alerts": [dict(zip(keys, row)) for row in rows], "total": total, "limit": limit, "offset": offset}


async def _transition(alert_id: str, owner_id: str, action: AlertAction, status: str):
    try:
        alert_uuid = uuid.UUID(alert_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid alert id") from exc
    if not db.pool:
        raise HTTPException(status_code=503, detail="Monitoring storage is unavailable")
    async with db.pool.connection() as conn:
        async with conn.transaction():
            row = await (await conn.execute(
                "SELECT id,watch_id,kind,evidence FROM monitoring_alerts WHERE id=%s AND owner_id=%s FOR UPDATE",
                (alert_uuid, owner_id),
            )).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Alert not found")
            if action.trust_issuer and row[1] and row[2] == "ct_issuance":
                evidence = row[3] or {}
                issuer_org = evidence.get("issuer_org") if isinstance(evidence, dict) else None
                if issuer_org and issuer_org != "unknown" and len(str(issuer_org)) <= 200:
                    await conn.execute(
                        "INSERT INTO domain_issuer_baseline(watch_id,issuer_org) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                        (row[1], issuer_org),
                    )
            updated = await (await conn.execute(
                "UPDATE monitoring_alerts SET status=%s, dismiss_reason=%s, "
                "acknowledged_at=CASE WHEN %s='acknowledged' THEN now() ELSE acknowledged_at END "
                "WHERE id=%s AND owner_id=%s RETURNING id,watch_id,kind,severity,status,target,evidence,source,dismiss_reason,observed_at,acknowledged_at,limitations",
                (status, action.reason if status == "dismissed" else None, status, alert_uuid, owner_id),
            )).fetchone()
    keys = ("id", "watch_id", "kind", "severity", "status", "target", "evidence", "source", "dismiss_reason", "observed_at", "acknowledged_at", "limitations")
    invalidate_watch_cache()
    return dict(zip(keys, updated))


@router.post("/api/v1/monitor/alerts/{alert_id}/ack")
@limiter.limit("120/minute")
async def acknowledge_alert(request: Request, alert_id: str, action: AlertAction = AlertAction(), owner_id: str = Depends(require_api_key)):
    return await _transition(alert_id, owner_id, action, "acknowledged")


@router.post("/api/v1/monitor/alerts/{alert_id}/dismiss")
@limiter.limit("120/minute")
async def dismiss_alert(request: Request, alert_id: str, action: AlertAction = AlertAction(), owner_id: str = Depends(require_api_key)):
    return await _transition(alert_id, owner_id, action, "dismissed")
