from __future__ import annotations

import ipaddress
import uuid

import idna
import tldextract
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from links.services.limiter import limiter

from links.services import db
from links.services.auth import require_api_key
from links.services.monitor.ct import invalidate_watch_cache

router = APIRouter()
_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


class WatchRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    known_own_domains: list[str] = Field(default_factory=list, max_length=50)


def _registered_domain(value: str) -> tuple[str, str]:
    try:
        ascii_domain = idna.encode(value.strip().rstrip(".").lower(), uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise HTTPException(status_code=400, detail="Invalid domain") from exc
    try:
        ipaddress.ip_address(ascii_domain)
    except ValueError:
        pass
    else:
        raise HTTPException(status_code=400, detail="Watch target must be a domain")
    if len(ascii_domain) > 253 or any(len(label) > 63 for label in ascii_domain.split(".")):
        raise HTTPException(status_code=400, detail="Invalid domain")
    ext = _extract(ascii_domain)
    if not ext.suffix or ext.subdomain or ext.top_domain_under_public_suffix != ascii_domain:
        raise HTTPException(status_code=400, detail="Watch target must be a registered domain (eTLD+1), not a subdomain")
    return ascii_domain, value.strip()


@router.post("/api/v1/monitor/watch", status_code=201)
@limiter.limit("120/minute")
async def create_watch(request: Request, payload: WatchRequest, owner_id: str = Depends(require_api_key)):
    if not db.pool:
        raise HTTPException(status_code=503, detail="Monitoring storage is unavailable")
    domain, display = _registered_domain(payload.domain)
    own_domains = [_registered_domain(item)[0] for item in payload.known_own_domains]
    async with db.pool.connection() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (owner_id,))
            count = await (await conn.execute(
                "SELECT count(*) FROM watch_domains WHERE owner_id=%s AND enabled=true", (owner_id,),
            )).fetchone()
            if count[0] >= 20:
                raise HTTPException(status_code=400, detail="Owner watch limit of 20 domains reached")
            row = await (await conn.execute(
                "INSERT INTO watch_domains(owner_id,domain_ascii,domain_display,known_own_domains) "
                "VALUES (%s,%s,%s,%s) ON CONFLICT(owner_id,domain_ascii) DO NOTHING "
                "RETURNING id,domain_ascii,domain_display,known_own_domains,enabled,created_at,wildcard_dns_detected",
                (owner_id, domain, display, own_domains),
            )).fetchone()
            if not row:
                raise HTTPException(status_code=409, detail="Domain is already watched")
    invalidate_watch_cache()
    return dict(zip(("id", "domain", "display", "known_own_domains", "enabled", "created_at", "wildcard_dns_detected"), row))


@router.get("/api/v1/monitor/watch")
@limiter.limit("120/minute")
async def list_watches(request: Request, owner_id: str = Depends(require_api_key)):
    if not db.pool:
        raise HTTPException(status_code=503, detail="Monitoring storage is unavailable")
    async with db.pool.connection() as conn:
        rows = await (await conn.execute(
            "SELECT id,domain_ascii,domain_display,known_own_domains,enabled,baseline_done,lookalike_scanned_at,created_at,wildcard_dns_detected "
            "FROM watch_domains WHERE owner_id=%s AND enabled=true ORDER BY created_at", (owner_id,),
        )).fetchall()
    keys = ("id", "domain", "display", "known_own_domains", "enabled", "baseline_done", "lookalike_scanned_at", "created_at", "wildcard_dns_detected")
    return [dict(zip(keys, row)) for row in rows]


@router.delete("/api/v1/monitor/watch/{watch_id}", status_code=204)
@limiter.limit("120/minute")
async def delete_watch(request: Request, watch_id: str, owner_id: str = Depends(require_api_key)):
    try:
        canonical_id = uuid.UUID(watch_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid watch id") from exc
    if not db.pool:
        raise HTTPException(status_code=503, detail="Monitoring storage is unavailable")
    async with db.pool.connection() as conn:
        result = await conn.execute("DELETE FROM watch_domains WHERE id=%s AND owner_id=%s", (canonical_id, owner_id))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Watch not found")
    invalidate_watch_cache()
    return Response(status_code=204)
