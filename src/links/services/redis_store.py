"""Lifespan-managed async access to the current URLhaus Redis generation."""
import hashlib, inspect, json, os
from urllib.parse import urlsplit

_client = None

def client():
    global _client
    if _client is None:
        from redis.asyncio import Redis
        _client = Redis.from_url(
            os.environ["REDIS_URL"], decode_responses=True,
            socket_connect_timeout=1, socket_timeout=1,
        )
    return _client

async def close():
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None

async def _await(value):
    return await value if inspect.isawaitable(value) else value

async def lookup(url: str) -> list[dict]:
    r=client(); generation=r.get("urlhaus:v1:active_generation")
    generation=await _await(generation)
    if not generation: raise RuntimeError("URLhaus feed generation is unavailable")
    host=urlsplit(url).hostname
    result=[]
    for kind in ("active","historical"):
        for typ,value in (("url",url),("host",host or "")):
            digest=hashlib.sha256(value.encode()).hexdigest()
            values=await _await(r.hvals(f"urlhaus:v1:{generation}:{kind}:{typ}:{digest}"))
            result.extend({**json.loads(v),"matched_value_type":typ,"record_status":kind} for v in values)
    unique={str(x.get("id")):x for x in result}
    return list(unique.values())
