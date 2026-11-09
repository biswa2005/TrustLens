from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from links.services import db
from links.services.monitor.ca import ca_reprobe_once, ca_retroscan_once
from links.services.monitor.ct import crt_backfill_once, crt_rule1_poll_once, process_certificate
from links.services.monitor.ct_source import WebSocketCTSource
from links.services.monitor.lookalike import lookalike_scan_once
from links.services.runtime import event_loop_factory
from links.services.tls.distrust import load_dataset

log = logging.getLogger("trustlens.worker")
WORKER_LOCK_ID = 948201


async def _state(task_name: str, *, error: str | None = None, state: dict | None = None):
    if not db.pool:
        return
    async with db.pool.connection() as conn:
        await conn.execute(
            "INSERT INTO monitor_state(task_name,last_run_at,last_error,state) VALUES (%s,now(),%s,%s) "
            "ON CONFLICT(task_name) DO UPDATE SET last_run_at=now(),last_error=excluded.last_error,state=excluded.state",
            (task_name, error, Jsonb(state or {})),
        )


async def _worker_state(*, running: bool, advisory_lock_held: bool, ct_state: dict | None = None,
                        system_state: dict | None = None):
    existing = {}
    if db.pool:
        async with db.pool.connection() as conn:
            row = await (await conn.execute("SELECT state FROM monitor_state WHERE task_name='worker'")).fetchone()
            if row and isinstance(row[0], dict):
                existing = row[0]
    if ct_state is None:
        ct_state = existing.get("ct_stream", {"status": "not_started", "stream_gaps_15m": 0, "last_message_at": None})
    existing.update({"running": running, "advisory_lock_held": advisory_lock_held, "ct_stream": ct_state})
    if system_state is not None:
        existing["system_state"] = system_state
    await _state("worker", state=existing)


async def _safe_loop(name: str, callback, period: float):
    while True:
        try:
            await callback()
            await _state(name)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("Monitoring task %s failed", name)
            try:
                await _state(name, error=type(exc).__name__)
            except Exception:
                log.exception("Could not record monitoring task failure: %s", name)
        await asyncio.sleep(period)


async def _maintenance():
    while True:
        now = datetime.now(timezone.utc)
        next_run = now.replace(hour=3, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        await asyncio.sleep((next_run - now).total_seconds())
        try:
            if db.pool:
                async with db.pool.connection() as conn:
                    await conn.execute("DELETE FROM monitoring_alerts WHERE observed_at < now()-interval '90 days'")
                    await conn.execute("DELETE FROM ct_seen_certs WHERE seen_at < now()-interval '30 days'")
            await _state("maintenance")
        except Exception as exc:
            log.exception("Monitoring maintenance purge failed")
            try:
                await _state("maintenance", error=type(exc).__name__)
            except Exception:
                log.exception("Could not persist maintenance failure")


async def _ct_stream_loop():
    stream_failures = 0
    dual_failures = 0
    next_poll_at = 0.0
    last_status_write = 0.0
    gaps: list[datetime] = []
    while True:
        source = WebSocketCTSource()
        try:
            await source.connect()
            stream_failures = 0
            dual_failures = 0
            await _worker_state(running=True, advisory_lock_held=True,
                                ct_state={"status": "connected", "stream_gaps_15m": len(gaps), "last_message_at": None})
            async for message in source.messages():
                await process_certificate(message)
                now = datetime.now(timezone.utc)
                gaps = [stamp for stamp in gaps if (now - stamp).total_seconds() < 900]
                loop_time = asyncio.get_running_loop().time()
                if loop_time - last_status_write >= 5:
                    await _worker_state(running=True, advisory_lock_held=True,
                                        ct_state={"status": "connected", "stream_gaps_15m": len(gaps), "last_message_at": now.isoformat()})
                    last_status_write = loop_time
            raise ConnectionError("CT stream ended")
        except asyncio.CancelledError:
            try:
                await source.close()
            except Exception:
                log.exception("Could not close CT source during worker shutdown")
            raise
        except Exception as exc:
            stream_failures += 1
            gaps.append(datetime.now(timezone.utc))
            log.warning("CT stream or ingestion failed (%s)", type(exc).__name__)
            try:
                await source.close()
            except Exception:
                pass
            status = "reconnecting"
            now_mono = asyncio.get_running_loop().time()
            if now_mono >= next_poll_at:
                next_poll_at = now_mono + 300
                try:
                    poll_ok, poll_failed = await crt_rule1_poll_once()
                    if poll_failed and not poll_ok:
                        dual_failures += 1
                    elif poll_ok or not poll_failed:
                        dual_failures = 0
                    status = "DEGRADED_NO_EGRESS" if dual_failures >= 5 else "polling_fallback"
                except Exception:
                    dual_failures += 1
                    status = "DEGRADED_NO_EGRESS" if dual_failures >= 5 else "reconnecting"
            elif dual_failures >= 5:
                status = "DEGRADED_NO_EGRESS"
            now = datetime.now(timezone.utc)
            gaps = [stamp for stamp in gaps if (now - stamp).total_seconds() < 900]
            await _worker_state(running=True, advisory_lock_held=True,
                                ct_state={"status": status, "stream_gaps_15m": len(gaps), "last_message_at": None,
                                          "last_error": type(exc).__name__})
            await asyncio.sleep(min(60, 5 * stream_failures))


async def _heartbeat(conn):
    while True:
        try:
            await conn.execute("SELECT 1")
            await _worker_state(running=True, advisory_lock_held=True)
        except Exception:
            log.exception("Worker advisory-lock heartbeat failed; stopping worker")
            raise RuntimeError("worker advisory-lock heartbeat failed")
        await asyncio.sleep(15)


async def run_worker_loop():
    await db.open_pool()
    try:
        async with db.pool.connection() as lock_conn:
            row = await (await lock_conn.execute("SELECT pg_try_advisory_lock(%s)", (WORKER_LOCK_ID,))).fetchone()
            if not row or not row[0]:
                log.warning("Another TrustLens worker holds advisory lock %s", WORKER_LOCK_ID)
                return
            dataset = load_dataset()
            await _worker_state(running=True, advisory_lock_held=True,
                                system_state={"ca_distrust_version": dataset.version})
            try:
                async with asyncio.TaskGroup() as tasks:
                    tasks.create_task(_heartbeat(lock_conn), name="worker-heartbeat")
                    tasks.create_task(_safe_loop("lookalike_scanner", lookalike_scan_once, 60), name="lookalike-scanner")
                    tasks.create_task(_safe_loop("crt_backfill", crt_backfill_once, 30), name="crt-backfill")
                    tasks.create_task(_safe_loop("ca_retroscan", ca_retroscan_once, 120), name="ca-retroscan")
                    tasks.create_task(_safe_loop("ca_reprobe", ca_reprobe_once, 300), name="ca-reprobe")
                    tasks.create_task(_ct_stream_loop(), name="ct-stream")
                    tasks.create_task(_maintenance(), name="monitor-maintenance")
            finally:
                await _worker_state(running=False, advisory_lock_held=False)
    finally:
        await db.close_pool()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    factory = event_loop_factory()
    if factory:
        asyncio.run(run_worker_loop(), loop_factory=factory)
    else:
        asyncio.run(run_worker_loop())


if __name__ == "__main__":
    main()
