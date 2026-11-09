from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from uuid import UUID
from datetime import datetime, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from psycopg.types.json import Jsonb

from links.services import db
from links.services.monitor.alerts import emit_alert
from links.services.tls._probe_models import TLSProbeRequest
from links.services.tls.distrust import load_dataset, matching_records
from links.services.tls.fetcher_client import decode_chain, post_probe_tls
from links.services.authority import canonical_authority

_reprobe_slots = asyncio.Semaphore(2)
log = logging.getLogger(__name__)


def _authority_host(authority: str) -> str:
    raw = authority.strip()
    if raw.startswith("["):
        closing = raw.find("]")
        if closing < 0:
            return ""
        host = raw[1:closing]
    else:
        host = raw.rsplit(":", 1)[0] if ":" in raw else raw
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        return host.rstrip(".").lower()


def _is_watched_host(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _record_for_report_certificate(cert_summary: dict, dataset, leaf_not_before=None):
    def digest(field):
        value = str(cert_summary.get(field) or "").replace(":", "").lower()
        try:
            return bytes.fromhex(value) if len(value) == 64 else None
        except ValueError:
            return None
    fingerprint, spki = digest("fingerprint_sha256"), digest("spki_sha256")
    record = next((item for item in dataset.records if item.fingerprint == fingerprint or item.spki_hash == spki), None)
    if not record:
        return None
    scope = record.scope or {"type": "all"}
    if scope.get("type") == "leaf_not_before_gte":
        try:
            date_value = leaf_not_before or datetime.fromisoformat(str(cert_summary["not_before"]).replace("Z", "+00:00"))
            not_before = date_value.date()
            from datetime import date
            if not_before < date.fromisoformat(scope["cutoff"][:10]):
                return None
        except (KeyError, ValueError, TypeError):
            return None
    elif scope.get("type") != "all":
        return None
    return record


async def _emit_for_host(host: str, fingerprint: str, record_id: str, observed_at, source: str) -> int:
    if not db.pool:
        return 0
    async with db.pool.connection() as conn:
        watches = await (await conn.execute(
            "SELECT id,owner_id,domain_ascii FROM watch_domains WHERE enabled=true",
        )).fetchall()
        count = 0
        timestamp = observed_at.isoformat() if hasattr(observed_at, "isoformat") else str(observed_at)
        for watch_id, owner_id, domain in watches:
            if not _is_watched_host(host, domain):
                continue
            authority = canonical_authority(host, 443)
            evidence = {"matched_authority": authority, "distrust_record_id": record_id,
                        "fingerprint_sha256": fingerprint.lower(), "observed_at": timestamp}
            dedupe = f"cadistrust:{owner_id}:{authority}:{record_id}"
            inserted = await emit_alert(conn, owner_id=owner_id, watch_id=watch_id,
                                        kind="ca_distrust", severity="strong", target=host,
                                        dedupe_key=dedupe, evidence=evidence, source=source)
            count += int(inserted)
        return count


async def check_and_emit_distrust_alert(report) -> int:
    """Live analysis hook; alert evidence omits report UUIDs and submitted URLs."""
    dataset = load_dataset()
    count = 0
    tls_reports = getattr(report, "tls_reports", None) or {}
    observed = getattr(report, "timestamp", datetime.now(timezone.utc))
    for report_item in tls_reports.values():
        authority = getattr(report_item, "canonical_authority", "")
        host = _authority_host(authority)
        certificates = getattr(report_item, "certificates", ())
        leaf_not_before = certificates[0].not_before if certificates else None
        for cert in certificates:
            fingerprint = getattr(cert, "fingerprint_sha256", None)
            record = _record_for_report_certificate(cert.model_dump(mode="json"), dataset, leaf_not_before)
            if record:
                count += await _emit_for_host(host, fingerprint, record.id, observed, "live_analysis")
    return count


async def ca_retroscan_once(batch_size: int = 500) -> bool:
    """Scan persisted TLS certificates after a verified distrust dataset changes."""
    if not db.pool:
        return False
    dataset = load_dataset()
    async with db.pool.connection() as conn:
        state = await (await conn.execute("SELECT state FROM monitor_state WHERE task_name='ca_retroscan'")).fetchone()
    last_version = (state[0] or {}).get("last_distrust_version") if state else None
    if last_version == dataset.version:
        return False
    cursor = UUID(int=0)
    while True:
        async with db.pool.connection() as conn:
            rows = await (await conn.execute(
                "SELECT id,report,created_at FROM reports WHERE id>%s AND expires_at>now() AND report ? 'tls_reports' "
                "AND jsonb_typeof(report->'tls_reports')='object' ORDER BY id LIMIT %s",
                (cursor, batch_size),
            )).fetchall()
        if not rows:
            break
        for _, report_json, created_at in rows:
            reports = report_json.get("tls_reports") if isinstance(report_json, dict) else None
            if not isinstance(reports, dict):
                continue
            for tls_report in reports.values():
                if not isinstance(tls_report, dict):
                    continue
                host = _authority_host(str(tls_report.get("canonical_authority", "")))
                certs = tls_report.get("certificates")
                if not isinstance(certs, list):
                    continue
                leaf_not_before = None
                if certs and isinstance(certs[0], dict):
                    try:
                        leaf_not_before = datetime.fromisoformat(str(certs[0]["not_before"]).replace("Z", "+00:00"))
                    except (KeyError, ValueError, TypeError):
                        pass
                for cert in certs:
                    if not isinstance(cert, dict):
                        continue
                    fingerprint = str(cert.get("fingerprint_sha256") or "")
                    record = _record_for_report_certificate(cert, dataset, leaf_not_before)
                    if record:
                        await _emit_for_host(host, fingerprint, record.id, created_at, "distrust_retroscan")
        cursor = rows[-1][0]
        if len(rows) < batch_size:
            break
    async with db.pool.connection() as conn:
        await conn.execute(
            "INSERT INTO monitor_state(task_name,state,last_run_at) VALUES ('ca_retroscan',%s,now()) "
            "ON CONFLICT(task_name) DO UPDATE SET state=excluded.state,last_run_at=now(),last_error=NULL",
            (Jsonb({"last_distrust_version": dataset.version}),),
        )
    return True


async def _probe_watch(watch: dict):
    fetcher = os.environ.get("FETCHER_URL")
    token = os.environ.get("FETCHER_TOKEN")
    async with _reprobe_slots:
        try:
            if not fetcher or not token:
                return
            payload = TLSProbeRequest(host=watch["domain_ascii"], port=443, timeout_budget=8.0).model_dump(mode="json")
            loop = asyncio.get_running_loop()
            async with httpx.AsyncClient(timeout=9.0, follow_redirects=False) as client:
                probe = await post_probe_tls(client, fetcher.rstrip("/") + "/probe/tls", payload,
                                             loop.time() + 8.5, token)
            if probe.ok:
                dataset = load_dataset()
                certs = [x509.load_der_x509_certificate(der) for der in decode_chain(probe)]
                leaf_not_before = certs[0].not_valid_before_utc if certs else None
                for cert in certs:
                    matches = matching_records(cert, dataset, leaf_not_before=leaf_not_before)
                    for record in matches:
                        await _emit_for_host(watch["domain_ascii"], cert.fingerprint(hashes.SHA256()).hex(),
                                             record.id, datetime.now(timezone.utc), "active_reprobe")
        except Exception as exc:
            log.warning("CA re-probe failed (%s)", type(exc).__name__)
        finally:
            if db.pool:
                async with db.pool.connection() as conn:
                    await conn.execute("UPDATE watch_domains SET last_probed_at=now() WHERE id=%s", (watch["id"],))


async def ca_reprobe_once(limit: int = 2):
    if not db.pool:
        return
    async with db.pool.connection() as conn:
        rows = await (await conn.execute(
            "SELECT id,domain_ascii FROM watch_domains WHERE enabled=true AND "
            "(last_probed_at IS NULL OR last_probed_at<now()-interval '24 hours') ORDER BY last_probed_at NULLS FIRST LIMIT %s",
            (limit,),
        )).fetchall()
    await asyncio.gather(*(_probe_watch({"id": row[0], "domain_ascii": row[1]}) for row in rows), return_exceptions=True)
