from __future__ import annotations

import hashlib
import time

from fastapi import Header, HTTPException, Request

from links.services import db

_key_windows: dict[str, tuple[int, int]] = {}
_ip_windows: dict[str, tuple[int, int]] = {}


async def _consume_ip_limit(remote_ip: str) -> int:
    """Count all monitor requests from an IP before key lookup, shared by Redis when available."""
    ip_hash = hashlib.sha256(remote_ip.encode("utf-8")).hexdigest()
    bucket = int(time.time() // 60)
    try:
        from links.services.redis_store import client
        redis = client()
        key = f"monitor:ratelimit:ip:v1:{ip_hash}:{bucket}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, 120)
        return int(count)
    except Exception:
        window = int(time.monotonic() // 60)
        previous_window, count = _ip_windows.get(ip_hash, (window, 0))
        count = count + 1 if previous_window == window else 1
        _ip_windows[ip_hash] = (window, count)
        if len(_ip_windows) > 10_000:
            for key, value in tuple(_ip_windows.items()):
                if value[0] != window:
                    _ip_windows.pop(key, None)
        return count


async def _consume_key_limit(key_hash: str) -> int:
    bucket = int(time.time() // 60)
    try:
        from links.services.redis_store import client
        redis = client()
        key = f"monitor:ratelimit:v1:{key_hash}:{bucket}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, 120)
        return int(count)
    except Exception:
        # Keep authenticated monitoring available if Redis is temporarily down.
        window = int(time.monotonic() // 60)
        previous_window, count = _key_windows.get(key_hash, (window, 0))
        count = count + 1 if previous_window == window else 1
        _key_windows[key_hash] = (window, count)
        if len(_key_windows) > 10_000:
            for key, value in tuple(_key_windows.items()):
                if value[0] != window:
                    _key_windows.pop(key, None)
        return count


async def require_api_key(request: Request, x_api_key: str | None = Header(default=None)) -> str:
    remote_ip = request.client.host if request.client else "unknown"
    if await _consume_ip_limit(remote_ip) > 120:
        raise HTTPException(status_code=429, detail="IP rate limit exceeded")
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if not db.pool:
        raise HTTPException(status_code=503, detail="Monitoring storage is unavailable")
    key_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
    async with db.pool.connection() as conn:
        row = await (await conn.execute(
            "SELECT owner_id FROM api_keys WHERE key_hash = %s AND is_active = true",
            (key_hash,),
        )).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    request.state.owner_id = row[0]
    request.state.api_key_hash = key_hash
    # This tier runs only after key validation; Redis shares it across workers.
    count = await _consume_key_limit(key_hash)
    if count > 60:
        raise HTTPException(status_code=429, detail="API key rate limit exceeded")
    return row[0]
