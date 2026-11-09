"""Disposable PostgreSQL integration coverage; runs only with TEST_DATABASE_URL."""
import asyncio
import hashlib
import os
import secrets
import uuid
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

import pytest
import httpx

from links.models import Coverage, Report
from links.models_tls import TLSReport, CertificateDetails, ChainStatus, HostnameStatus, CADistrustClassification, TrustVerdict
from links import routes
from main import app
from links.services.monitor.alerts import emit_alert
from links.services.monitor import ca, ct, lookalike
from links.services.tls.distrust import DistrustDataset, DistrustRecord
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
            monitor_tables=await (await conn.execute(
                "SELECT to_regclass('api_keys'),to_regclass('watch_domains'),to_regclass('monitoring_alerts')",
            )).fetchone()
            monitor_columns=await (await conn.execute(
                "SELECT count(*) FROM information_schema.columns WHERE table_name='watch_domains' "
                "AND column_name IN ('known_own_domains','baseline_done','lookalike_scanned_at','wildcard_dns_detected')",
            )).fetchone()
        assert migration and all(monitor_tables) and monitor_columns[0] == 4
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


def test_gate0_analysis_post_get_round_trips_tls_reports(postgres_test_db, monkeypatch):
    async def fake_analyse(url, skip_third_party_reputation=False):
        return Report(
            input=url,
            risk_class="inconclusive",
            coverage=Coverage(completed=1, planned=11, checks=[]),
            tls_reports={"example.com:443": TLSReport(
                canonical_authority="example.com:443",
                target_kind="input",
                probe_ok=True,
                chain_status=ChainStatus.VALID_TRUSTED,
                hostname_status=HostnameStatus.MATCHED,
                distrust=CADistrustClassification.TRUSTED,
                trust_verdict=TrustVerdict.VALID,
            )},
        )

    monkeypatch.setattr(routes, "analyse", fake_analyse)

    async def verify():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/v1/analyse/url", json={"url": "https://example.com"})
            assert response.status_code == 200, response.text
            report_id = response.json()["report_id"]
            assert response.json()["tls_reports"]["example.com:443"]["trust_verdict"] == "valid"
            fetched = await client.get(f"/api/v1/reports/{report_id}")
            assert fetched.status_code == 200, fetched.text
            saved = fetched.json()
            assert saved["tls_reports"]["example.com:443"]["canonical_authority"] == "example.com:443"
            assert saved["tls_reports"]["example.com:443"]["trust_verdict"] == "valid"

    postgres_test_db(verify())


def test_monitor_api_auth_tenant_isolation_and_alert_lifecycle(postgres_test_db):
    owner_a, owner_b = f"test-{uuid.uuid4()}", f"test-{uuid.uuid4()}"
    key_a, key_b = secrets.token_urlsafe(32), secrets.token_urlsafe(32)

    async def verify():
        async with db.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO api_keys(key_hash,owner_id,label) VALUES (%s,%s,%s),(%s,%s,%s)",
                (hashlib.sha256(key_a.encode()).hexdigest(), owner_a, "integration-a",
                 hashlib.sha256(key_b.encode()).hexdigest(), owner_b, "integration-b"),
            )
        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                assert (await client.post("/api/v1/monitor/watch", json={"domain": "example.com"})).status_code == 401
                headers_a, headers_b = {"X-API-Key": key_a}, {"X-API-Key": key_b}
                created = await client.post("/api/v1/monitor/watch", headers=headers_a,
                                            json={"domain": "example.com"})
                assert created.status_code == 201, created.text
                watch_id = uuid.UUID(created.json()["id"])
                listed = await client.get("/api/v1/monitor/watch", headers=headers_a)
                assert [item["id"] for item in listed.json()] == [str(watch_id)]
                assert (await client.post("/api/v1/monitor/watch", headers=headers_b,
                                          json={"domain": "app.example.net"})).status_code == 400
                idna_watch = await client.post("/api/v1/monitor/watch", headers=headers_b,
                                               json={"domain": "bücher.de"})
                assert idna_watch.status_code == 201
                assert idna_watch.json()["domain"] == "xn--bcher-kva.de"
                async with db.pool.connection() as conn:
                    inserted = await emit_alert(
                        conn, owner_id=owner_a, watch_id=watch_id, kind="ct_issuance",
                        severity="strong", target="example.com", dedupe_key=f"test:{uuid.uuid4()}",
                        evidence={"issuer_org": "trusted test issuer"}, source="integration_test",
                    )
                assert inserted
                alerts_a = await client.get("/api/v1/monitor/alerts", headers=headers_a)
                alerts_b = await client.get("/api/v1/monitor/alerts", headers=headers_b)
                alert_id = alerts_a.json()["alerts"][0]["id"]
                assert alerts_a.json()["total"] == 1
                assert alerts_b.json()["total"] == 0
                assert (await client.post(f"/api/v1/monitor/alerts/{alert_id}/ack", headers=headers_b)).status_code == 404
                acknowledged = await client.post(
                    f"/api/v1/monitor/alerts/{alert_id}/ack", headers=headers_a,
                    json={"trust_issuer": True},
                )
                assert acknowledged.status_code == 200
                dismissed = await client.post(
                    f"/api/v1/monitor/alerts/{alert_id}/dismiss", headers=headers_a,
                    json={"reason": "Reviewed"},
                )
                assert dismissed.status_code == 200 and dismissed.json()["status"] == "dismissed"
                async with db.pool.connection() as conn:
                    baseline = await (await conn.execute(
                        "SELECT 1 FROM domain_issuer_baseline WHERE watch_id=%s AND issuer_org=%s",
                        (watch_id, "trusted test issuer"),
                    )).fetchone()
                assert baseline
                status_a = await client.get("/api/v1/monitor/status", headers=headers_a)
                status_b = await client.get("/api/v1/monitor/status", headers=headers_b)
                assert status_a.json()["tenant_metrics"]["active_watches"] == 1
                assert status_b.json()["tenant_metrics"]["active_watches"] == 1
                assert (await client.delete(f"/api/v1/monitor/watch/{watch_id}", headers=headers_b)).status_code == 404
                assert (await client.delete(f"/api/v1/monitor/watch/{watch_id}", headers=headers_a)).status_code == 204
                async with db.pool.connection() as conn:
                    await conn.execute(
                        "INSERT INTO watch_domains(owner_id,domain_ascii,domain_display) "
                        "SELECT %s,'quota'||n::text||'.com','quota'||n::text||'.com' FROM generate_series(1,19) AS n",
                        (owner_b,),
                    )
                over_quota = await client.post("/api/v1/monitor/watch", headers=headers_b,
                                               json={"domain": "overflow.com"})
                assert over_quota.status_code == 400
                for _ in range(53):
                    limited = await client.get("/api/v1/monitor/status", headers=headers_a)
                    assert limited.status_code == 200
                assert (await client.get("/api/v1/monitor/status", headers=headers_a)).status_code == 429
        finally:
            async with db.pool.connection() as conn:
                await conn.execute("DELETE FROM monitoring_alerts WHERE owner_id IN (%s,%s)", (owner_a, owner_b))
                await conn.execute("DELETE FROM watch_domains WHERE owner_id IN (%s,%s)", (owner_a, owner_b))
                await conn.execute("DELETE FROM api_keys WHERE owner_id IN (%s,%s)", (owner_a, owner_b))

    postgres_test_db(verify())


def test_lookalike_first_observation_is_silent_then_emits_one_transition(postgres_test_db, monkeypatch):
    owner = f"lookalike-{uuid.uuid4()}"
    async def verify():
        async with db.pool.connection() as conn:
            watch_id = (await (await conn.execute(
                "INSERT INTO watch_domains(owner_id,domain_ascii,domain_display) VALUES (%s,%s,%s) RETURNING id",
                (owner, "example.com", "example.com"),
            )).fetchone())[0]
        monkeypatch.setattr(lookalike, "generate_candidates", lambda *_: ["examp1e.com"])
        monkeypatch.setattr(lookalike, "_wildcard_detected", lambda *_: asyncio.sleep(0, result=False))
        states = iter((lookalike.ProbeState(False), lookalike.ProbeState(True, True, "mx.example.net", 3)))
        async def probe(_): return next(states)
        monkeypatch.setattr(lookalike, "_probe", probe)
        await lookalike.scan_watch({"id": watch_id, "owner_id": owner, "domain_ascii": "example.com",
                                   "known_own_domains": [], "lookalike_scanned_at": None})
        async with db.pool.connection() as conn:
            count = (await (await conn.execute(
                "SELECT count(*) FROM monitoring_alerts WHERE owner_id=%s", (owner,),
            )).fetchone())[0]
            assert count == 0
            scanned_at = (await (await conn.execute(
                "SELECT lookalike_scanned_at FROM watch_domains WHERE id=%s", (watch_id,),
            )).fetchone())[0]
        await lookalike.scan_watch({"id": watch_id, "owner_id": owner, "domain_ascii": "example.com",
                                   "known_own_domains": [], "lookalike_scanned_at": scanned_at})
        async with db.pool.connection() as conn:
            rows = await (await conn.execute(
                "SELECT severity,kind FROM monitoring_alerts WHERE owner_id=%s", (owner,),
            )).fetchall()
            assert rows == [("strong", "lookalike_transition")]
            await conn.execute("DELETE FROM monitoring_alerts WHERE owner_id=%s", (owner,))
            await conn.execute("DELETE FROM watch_domains WHERE id=%s", (watch_id,))
    postgres_test_db(verify())


def test_wildcard_dns_aborts_lookalike_scan(postgres_test_db, monkeypatch):
    owner = f"wildcard-{uuid.uuid4()}"
    async def verify():
        async with db.pool.connection() as conn:
            watch_id = (await (await conn.execute(
                "INSERT INTO watch_domains(owner_id,domain_ascii,domain_display) VALUES (%s,%s,%s) RETURNING id",
                (owner, "example.net", "example.net"),
            )).fetchone())[0]
        monkeypatch.setattr(lookalike, "generate_candidates", lambda *_: ["examp1e.net"])
        monkeypatch.setattr(lookalike, "_wildcard_detected", lambda *_: asyncio.sleep(0, result=True))
        async def unexpected_probe(_):
            raise AssertionError("wildcard DNS must abort probing")
        monkeypatch.setattr(lookalike, "_probe", unexpected_probe)
        await lookalike.scan_watch({"id": watch_id, "owner_id": owner, "domain_ascii": "example.net",
                                   "known_own_domains": [], "lookalike_scanned_at": None})
        async with db.pool.connection() as conn:
            status = await (await conn.execute(
                "SELECT wildcard_dns_detected,lookalike_scanned_at FROM watch_domains WHERE id=%s", (watch_id,),
            )).fetchone()
            alerts = (await (await conn.execute(
                "SELECT count(*) FROM monitoring_alerts WHERE owner_id=%s", (owner,),
            )).fetchone())[0]
            assert status[0] is True and status[1] is not None and alerts == 0
            await conn.execute("DELETE FROM watch_domains WHERE id=%s", (watch_id,))
    postgres_test_db(verify())


def test_ct_baseline_gates_own_domain_and_reports_unknown_issuer(postgres_test_db):
    owner = f"ct-{uuid.uuid4()}"
    async def verify():
        async with db.pool.connection() as conn:
            watch_id = (await (await conn.execute(
                "INSERT INTO watch_domains(owner_id,domain_ascii,domain_display,baseline_done,baseline_empty) "
                "VALUES (%s,%s,%s,false,false) RETURNING id",
                (owner, "example.com", "example.com"),
            )).fetchone())[0]
        message = {"data": {"leaf_cert": {
            "subjectAltName": ["example.com", "www.example.com"],
            "serial_number": "aabbcc", "issuer": {"O": "Unrecognized Issuer Inc"},
        }}}
        ct.invalidate_watch_cache()
        assert await ct.process_certificate(message) == 0
        async with db.pool.connection() as conn:
            await conn.execute("UPDATE watch_domains SET baseline_done=true WHERE id=%s", (watch_id,))
        ct.invalidate_watch_cache()
        assert await ct.process_certificate(message) == 1
        async with db.pool.connection() as conn:
            row = await (await conn.execute(
                "SELECT severity,evidence FROM monitoring_alerts WHERE owner_id=%s", (owner,),
            )).fetchone()
            assert row[0] == "strong"
            assert row[1]["rule"] == "unrecognized_issuer"
            await conn.execute(
                "INSERT INTO domain_issuer_baseline(watch_id,issuer_org) VALUES (%s,%s)",
                (watch_id, "unrecognized issuer"),
            )
        ct.invalidate_watch_cache()
        assert await ct.process_certificate({"data": {"leaf_cert": {
            "subjectAltName": ["example.com"], "serial_number": "aabbcd",
            "issuer": {"O": "Unrecognized Issuer Inc"},
        }}}) == 0
        async with db.pool.connection() as conn:
            await conn.execute("UPDATE watch_domains SET baseline_empty=true WHERE id=%s", (watch_id,))
        ct.invalidate_watch_cache()
        assert await ct.process_certificate({"data": {"leaf_cert": {
            "subjectAltName": ["example.com"], "serial_number": "aabbce",
            "issuer": {"O": "First Issuer Inc"},
        }}}) == 1
        async with db.pool.connection() as conn:
            baseline_alert = await (await conn.execute(
                "SELECT severity,evidence FROM monitoring_alerts WHERE owner_id=%s AND evidence->>'serial_hex'='aabbce'",
                (owner,),
            )).fetchone()
            assert baseline_alert[0] == "info"
            assert baseline_alert[1]["rule"] == "initial_baseline_established"
            await conn.execute("DELETE FROM monitoring_alerts WHERE owner_id=%s", (owner,))
            await conn.execute("DELETE FROM watch_domains WHERE id=%s", (watch_id,))
        ct.invalidate_watch_cache()
    postgres_test_db(verify())


def test_ct_same_certificate_alerts_are_deduped_per_tenant(postgres_test_db):
    owner_a, owner_b = f"ct-a-{uuid.uuid4()}", f"ct-b-{uuid.uuid4()}"
    async def verify():
        async with db.pool.connection() as conn:
            rows = await (await conn.execute(
                "INSERT INTO watch_domains(owner_id,domain_ascii,domain_display,baseline_done,baseline_empty) "
                "VALUES (%s,%s,%s,true,false),(%s,%s,%s,true,false) RETURNING id,owner_id",
                (owner_a, "example.org", "example.org", owner_b, "example.org", "example.org"),
            )).fetchall()
        ct.invalidate_watch_cache()
        message = {"data": {"leaf_cert": {
            "subjectAltName": ["example.org"], "serial_number": "f00d",
            "issuer": {"O": "New Certificate Authority"},
        }}}
        assert await ct.process_certificate(message) == 2
        async with db.pool.connection() as conn:
            counts = await (await conn.execute(
                "SELECT owner_id,count(*) FROM monitoring_alerts WHERE owner_id IN (%s,%s) GROUP BY owner_id ORDER BY owner_id",
                (owner_a, owner_b),
            )).fetchall()
            assert counts == [(owner_a, 1), (owner_b, 1)]
            await conn.execute("DELETE FROM monitoring_alerts WHERE owner_id IN (%s,%s)", (owner_a, owner_b))
            for watch_id, _ in rows:
                await conn.execute("DELETE FROM watch_domains WHERE id=%s", (watch_id,))
        ct.invalidate_watch_cache()
    postgres_test_db(verify())


def test_ca_live_hook_and_retro_scan_keep_report_ids_private(postgres_test_db, monkeypatch):
    owner = f"ca-{uuid.uuid4()}"
    fingerprint, spki_hash = "11" * 32, "22" * 32
    record = DistrustRecord("test-compromised-ca", "compromised", bytes.fromhex(fingerprint),
                            bytes.fromhex(spki_hash), "Test CA", {"type": "all"})
    dataset = DistrustDataset("test-v1+1-verified", (record,))
    monkeypatch.setattr(ca, "load_dataset", lambda: dataset)
    now = datetime.now(timezone.utc)
    cert = CertificateDetails(
        subject="CN=www.retroexample.com", issuer="CN=Test CA", serial_number="1234",
        fingerprint_sha256=fingerprint, spki_sha256=spki_hash,
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=30),
    )

    async def verify():
        async with db.pool.connection() as conn:
            live_watch = (await (await conn.execute(
                "INSERT INTO watch_domains(owner_id,domain_ascii,domain_display) VALUES (%s,%s,%s) RETURNING id",
                (owner, "liveexample.com", "liveexample.com"),
            )).fetchone())[0]
            retro_watch = (await (await conn.execute(
                "INSERT INTO watch_domains(owner_id,domain_ascii,domain_display) VALUES (%s,%s,%s) RETURNING id",
                (owner, "retroexample.com", "retroexample.com"),
            )).fetchone())[0]
            await conn.execute("DELETE FROM monitor_state WHERE task_name='ca_retroscan'")
        live_report = Report(
            input="https://liveexample.com", coverage=Coverage(completed=1, planned=11, checks=[]),
            tls_reports={"liveexample.com:443": TLSReport(
                canonical_authority="liveexample.com:443", target_kind="input", probe_ok=True,
                certificates=(cert,),
            )},
        )
        assert await ca.check_and_emit_distrust_alert(live_report) == 1
        async with db.pool.connection() as conn:
            live_evidence = (await (await conn.execute(
                "SELECT evidence FROM monitoring_alerts WHERE watch_id=%s", (live_watch,),
            )).fetchone())[0]
            assert "report_id" not in live_evidence and "input_url" not in live_evidence

        retro_report = Report(
            input="https://retroexample.com", coverage=Coverage(completed=1, planned=11, checks=[]),
            tls_reports={"retroexample.com:443": TLSReport(
                canonical_authority="retroexample.com:443", target_kind="input", probe_ok=True,
                certificates=(cert,),
            )},
        )
        retro_id = await db.save_report(retro_report)
        null_report = Report(input="http://legacy.example", coverage=Coverage(completed=0, planned=11, checks=[]))
        await db.save_report(null_report)
        async with db.pool.connection() as conn:
            await conn.execute("DELETE FROM monitoring_alerts WHERE watch_id=%s", (retro_watch,))
        assert await ca.ca_retroscan_once(batch_size=1) is True
        async with db.pool.connection() as conn:
            evidence = (await (await conn.execute(
                "SELECT evidence FROM monitoring_alerts WHERE watch_id=%s", (retro_watch,),
            )).fetchone())[0]
            assert evidence["matched_authority"] == "retroexample.com:443"
            assert evidence["fingerprint_sha256"] == fingerprint
            assert evidence["distrust_record_id"] == record.id
            assert retro_id not in json.dumps(evidence)
            await conn.execute("DELETE FROM monitoring_alerts WHERE owner_id=%s", (owner,))
            await conn.execute("DELETE FROM watch_domains WHERE owner_id=%s", (owner,))
            await conn.execute("DELETE FROM monitor_state WHERE task_name='ca_retroscan'")
    postgres_test_db(verify())


def test_ca_reprobe_is_throttled_and_limited_to_two_concurrent_probes(postgres_test_db, monkeypatch):
    owner = f"reprobe-{uuid.uuid4()}"
    async def verify():
        async with db.pool.connection() as conn:
            rows = await (await conn.execute(
                "INSERT INTO watch_domains(owner_id,domain_ascii,domain_display) "
                "SELECT %s,'probe'||n::text||'.com','probe'||n::text||'.com' "
                "FROM generate_series(1,3) AS n RETURNING id,domain_ascii",
                (owner,),
            )).fetchall()
        monkeypatch.setattr(ca, "_reprobe_slots", asyncio.Semaphore(2))
        monkeypatch.setenv("FETCHER_URL", "http://fetcher.test")
        monkeypatch.setenv("FETCHER_TOKEN", "test-token")
        class FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): return False
        monkeypatch.setattr(ca.httpx, "AsyncClient", lambda **_: FakeClient())
        active = peak = 0
        async def failing_probe(*_):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            raise httpx.ConnectError("expected test failure")
        monkeypatch.setattr(ca, "post_probe_tls", failing_probe)
        await asyncio.gather(*(ca._probe_watch({"id": row[0], "domain_ascii": row[1]}) for row in rows))
        assert peak == 2
        async with db.pool.connection() as conn:
            probed = await (await conn.execute(
                "SELECT count(*) FROM watch_domains WHERE owner_id=%s AND last_probed_at IS NOT NULL", (owner,),
            )).fetchone()
            await conn.execute("UPDATE watch_domains SET last_probed_at=now() WHERE owner_id=%s", (owner,))
        assert probed[0] == 3
        selected = []
        async def mark_selected(watch): selected.append(watch["id"])
        monkeypatch.setattr(ca, "_probe_watch", mark_selected)
        await ca.ca_reprobe_once(limit=2)
        assert selected == []
        async with db.pool.connection() as conn:
            await conn.execute("UPDATE watch_domains SET last_probed_at=now()-interval '25 hours' WHERE owner_id=%s", (owner,))
        await ca.ca_reprobe_once(limit=2)
        assert len(selected) == 2
        async with db.pool.connection() as conn:
            await conn.execute("DELETE FROM watch_domains WHERE owner_id=%s", (owner,))
    postgres_test_db(verify())


def test_ct_backfill_failure_uses_retry_backoff(postgres_test_db, monkeypatch):
    owner = f"backfill-{uuid.uuid4()}"
    async def verify():
        async with db.pool.connection() as conn:
            watch_id = (await (await conn.execute(
                "INSERT INTO watch_domains(owner_id,domain_ascii,domain_display) VALUES (%s,%s,%s) RETURNING id",
                (owner, "backfill.example.com", "backfill.example.com"),
            )).fetchone())[0]
        class FailingResponse:
            async def __aenter__(self): raise httpx.ConnectTimeout("expected timeout")
            async def __aexit__(self, *_): return False
        class FakeClient:
            def __init__(self, **_): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *_): return False
            def stream(self, *_args, **_kwargs): return FailingResponse()
        monkeypatch.setattr(ct.httpx, "AsyncClient", FakeClient)
        await ct.crt_backfill_watch({"id": watch_id, "domain_ascii": "backfill.example.com", "backfill_attempts": 0})
        async with db.pool.connection() as conn:
            state = await (await conn.execute(
                "SELECT backfill_attempts,last_backfill_error,EXTRACT(EPOCH FROM next_backfill_at-now()) "
                "FROM watch_domains WHERE id=%s", (watch_id,),
            )).fetchone()
            assert state[0] == 1 and state[1] == "ConnectTimeout"
            assert 295 <= state[2] <= 300
            await conn.execute("DELETE FROM watch_domains WHERE id=%s", (watch_id,))
    postgres_test_db(verify())


def test_crt_fallback_poller_only_alerts_for_watched_domain_issuance(postgres_test_db, monkeypatch):
    owner = f"poller-{uuid.uuid4()}"
    async def verify():
        async with db.pool.connection() as conn:
            watch_id = (await (await conn.execute(
                "INSERT INTO watch_domains(owner_id,domain_ascii,domain_display,baseline_done,baseline_empty) "
                "VALUES (%s,%s,%s,true,false) RETURNING id",
                (owner, "fallbackdomain.com", "fallbackdomain.com"),
            )).fetchone())[0]
        payload = json.dumps([
            {"id": 500, "name_value": "www.fallbackdomain.com", "issuer_name": "O=Novel Certificate Authority",
             "serial_number": "a001"},
            {"id": 501, "name_value": "fallbackdomain-login.evil.net", "issuer_name": "O=Novel Certificate Authority",
             "serial_number": "a002"},
        ]).encode()
        class FakeResponse:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): return False
            def raise_for_status(self): pass
            async def aiter_bytes(self): yield payload
        class FakeClient:
            def __init__(self, **_): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *_): return False
            def stream(self, *_args, **_kwargs): return FakeResponse()
        monkeypatch.setattr(ct.httpx, "AsyncClient", FakeClient)
        assert await ct.crt_rule1_poll_once(limit=1) == (1, 0)
        async with db.pool.connection() as conn:
            rows = await (await conn.execute(
                "SELECT target,evidence FROM monitoring_alerts WHERE owner_id=%s", (owner,),
            )).fetchall()
            assert len(rows) == 1 and rows[0][0] == "fallbackdomain.com"
            assert rows[0][1]["crtsh_record_id"] == 500
            await conn.execute("DELETE FROM monitoring_alerts WHERE owner_id=%s", (owner,))
            await conn.execute("DELETE FROM watch_domains WHERE id=%s", (watch_id,))
    postgres_test_db(verify())


def test_worker_advisory_lock_is_exclusive(postgres_test_db):
    async def verify():
        async with db.pool.connection() as first, db.pool.connection() as second:
            acquired = await (await first.execute("SELECT pg_try_advisory_lock(948201)")).fetchone()
            denied = await (await second.execute("SELECT pg_try_advisory_lock(948201)")).fetchone()
            assert acquired[0] is True
            assert denied[0] is False
            await first.execute("SELECT pg_advisory_unlock(948201)")

    postgres_test_db(verify())
