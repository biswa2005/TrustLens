from __future__ import annotations
import os, json, uuid
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from psycopg_pool import AsyncConnectionPool
from psycopg.types.json import Jsonb

pool: AsyncConnectionPool | None=None

async def open_pool():
    global pool
    pool=AsyncConnectionPool(os.environ["DATABASE_URL"],min_size=1,max_size=8,open=False)
    await pool.open()
    migrations=Path(__file__).resolve().parents[1]/"migrations"
    async with pool.connection() as conn:
        await conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT now())")
        for migration in sorted(migrations.glob("*.sql")):
            async with conn.transaction():
                applied=await (await conn.execute("SELECT 1 FROM schema_migrations WHERE name=%s",(migration.name,))).fetchone()
                if applied: continue
                for statement in migration.read_text(encoding="utf8").split(";"):
                    if statement.strip(): await conn.execute(statement)
                await conn.execute("INSERT INTO schema_migrations(name) VALUES (%s) ON CONFLICT DO NOTHING",(migration.name,))

async def close_pool():
    if pool: await pool.close()

async def healthy():
    if not pool: return False
    try:
        async with pool.connection() as conn: await conn.execute("SELECT 1")
        return True
    except Exception: return False

async def save_report(report):
    if not pool: raise RuntimeError("PostgreSQL is not configured")
    retention=int(os.getenv("REPORT_RETENTION_DAYS","7")); rid=uuid.uuid4()
    saved=report.model_copy(update={"report_id":str(rid)})
    async with pool.connection() as conn:
        await conn.execute("DELETE FROM reports WHERE expires_at < now()")
        await conn.execute("INSERT INTO reports(id,submitted_url,report,expires_at) VALUES (%s,%s,%s,%s)",(rid,report.input,Jsonb(saved.model_dump(mode="json")),datetime.now(timezone.utc)+timedelta(days=retention)))
    return str(rid)

async def get_report(report_id:str):
    if not pool: raise RuntimeError("PostgreSQL is not configured")
    async with pool.connection() as conn:
        row=await (await conn.execute("SELECT report FROM reports WHERE id=%s AND expires_at>now()",(uuid.UUID(report_id),))).fetchone()
        return row[0] if row else None

def cache_key(value:str)->str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

async def cache_get(source:str,query:str):
    if not pool: return None
    async with pool.connection() as conn:
        row=await (await conn.execute("SELECT response FROM api_cache WHERE cache_key=%s AND source=%s AND expires_at>now()",(cache_key(query),source))).fetchone()
        return row[0] if row else None

async def cache_put(source:str,query:str,response,ttl:int):
    if not pool: return
    async with pool.connection() as conn:
        await conn.execute("INSERT INTO api_cache(cache_key,source,response,expires_at) VALUES(%s,%s,%s,now()+(%s * interval '1 second')) ON CONFLICT(source,cache_key) DO UPDATE SET response=excluded.response,expires_at=excluded.expires_at",(cache_key(query),source,Jsonb(response),ttl))

async def increment_usage(source:str)->int|None:
    if not pool: return None
    async with pool.connection() as conn:
        row=await (await conn.execute("INSERT INTO api_usage(source,day,count) VALUES(%s,current_date,1) ON CONFLICT(source,day) DO UPDATE SET count=api_usage.count+1 RETURNING count",(source,))).fetchone()
        return row[0]

async def purge_expired()->int:
    if not pool: return 0
    async with pool.connection() as conn:
        a=await conn.execute("DELETE FROM reports WHERE expires_at<now()")
        b=await conn.execute("DELETE FROM api_cache WHERE expires_at<now()")
        return (a.rowcount or 0)+(b.rowcount or 0)
