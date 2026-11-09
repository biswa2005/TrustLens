"""Disposable PostgreSQL integration coverage; runs only with TEST_DATABASE_URL."""
import asyncio
import os
import uuid
from urllib.parse import urlsplit, urlunsplit

import pytest

from links.models import Coverage, Report
from links.services import db

TEST_URL=os.environ.get("TEST_DATABASE_URL")
pytestmark=pytest.mark.skipif(not TEST_URL,reason="TEST_DATABASE_URL is not configured")

@pytest.fixture
def postgres_test_db(monkeypatch):
    parsed=urlsplit(TEST_URL)
    if not parsed.path.rstrip("/").rsplit("/",1)[-1].endswith("_test"):
        pytest.skip("TEST_DATABASE_URL must name a database ending in _test")
    connection_url = TEST_URL
    if os.name == "nt" and parsed.hostname == "localhost":
        userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
        port = f":{parsed.port}" if parsed.port is not None else ""
        connection_url = urlunsplit(parsed._replace(netloc=f"{userinfo}127.0.0.1{port}"))
    monkeypatch.setenv("DATABASE_URL",connection_url)
    loop = asyncio.SelectorEventLoop() if os.name == "nt" else asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def run(coro):
        return loop.run_until_complete(coro)

    run(db.open_pool())
    async def clear():
        async with db.pool.connection() as conn:
            await conn.execute("DELETE FROM reports")
            await conn.execute("DELETE FROM api_cache")
            await conn.execute("DELETE FROM api_usage")
    run(clear())
    try:
        yield run
    finally:
        run(clear())
        run(db.close_pool())
        loop.close()
        asyncio.set_event_loop(None)


def test_postgres_migrations_cache_usage_and_report_retention(postgres_test_db,monkeypatch):
    async def verify():
        async with db.pool.connection() as conn:
            migration=await (await conn.execute("SELECT 1 FROM schema_migrations WHERE name='001_initial.sql'")).fetchone()
        assert migration
        query="https://cache.example/"+uuid.uuid4().hex
        await db.cache_put("integration",query,{"count":1},3600)
        assert await db.cache_get("integration",query)=={"count":1}
        await db.cache_put("integration",query,{"count":2},3600)
        assert await db.cache_get("integration",query)=={"count":2}
        assert await db.increment_usage("integration-"+uuid.uuid4().hex)==1
        report=Report(input="https://example.test",risk_class="inconclusive",coverage=Coverage(completed=0,planned=10,checks=[]))
        monkeypatch.setenv("REPORT_RETENTION_DAYS","1")
        report_id=await db.save_report(report)
        saved=await db.get_report(report_id)
        assert saved["report_id"]==report_id and saved["input"]==report.input
        monkeypatch.setenv("REPORT_RETENTION_DAYS","0")
        expired_id=await db.save_report(report)
        assert await db.get_report(expired_id) is None
    postgres_test_db(verify())
