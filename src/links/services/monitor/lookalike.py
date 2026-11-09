from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import dns.resolver

from links.services import db
from links.services.checks.network import rdap_check
from links.services.monitor.alerts import emit_alert
from links.services.monitor.generator import generate_candidates

_probe_slots = asyncio.Semaphore(20)
_rate_lock = asyncio.Lock()
_last_query = 0.0
_wildcard_cache: dict[str, tuple[float, bool]] = {}
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProbeState:
    resolves: bool
    has_mx: bool = False
    mx_host: str | None = None
    rdap_age_days: int | None = None


async def _throttle():
    global _last_query
    async with _rate_lock:
        wait = 0.1 - (time.monotonic() - _last_query)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_query = time.monotonic()


async def _resolver_has_address(domain: str, nameserver: str) -> bool:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.timeout = 1.0
    resolver.lifetime = 2.0
    for record_type in ("A", "AAAA"):
        await _throttle()
        try:
            answer = await resolver.resolve(domain, record_type, lifetime=2.0, raise_on_no_answer=False)
            if answer.rrset:
                return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except (dns.exception.DNSException, OSError, asyncio.TimeoutError):
            continue
    return False


async def _wildcard_detected(suffix: str) -> bool:
    cached = _wildcard_cache.get(suffix)
    if cached and time.monotonic() - cached[0] < 3600:
        return cached[1]
    probe = f"rand-{uuid.uuid4().hex}.{suffix}"
    values = await asyncio.gather(
        _resolver_has_address(probe, "9.9.9.10"),
        _resolver_has_address(probe, "1.1.1.1"),
    )
    result = any(values)
    _wildcard_cache[suffix] = (time.monotonic(), result)
    return result


async def _resolves(domain: str) -> bool:
    tasks = [asyncio.create_task(_resolver_has_address(domain, server)) for server in ("9.9.9.10", "1.1.1.1")]
    try:
        for completed in asyncio.as_completed(tasks):
            if await completed:
                for task in tasks:
                    if task.done() and not task.cancelled():
                        try:
                            if not task.result():
                                log.info("Public DNS resolvers disagreed for monitored candidate %s", domain)
                        except Exception:
                            pass
                for task in tasks:
                    if not task.done():
                        task.cancel()
                return True
        return False
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _probe(domain: str) -> ProbeState:
    async with _probe_slots:
        resolves = await _resolves(domain)
        if not resolves:
            return ProbeState(False)
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = ["9.9.9.10"]
        resolver.timeout = 1.0
        resolver.lifetime = 2.0
        has_mx, mx_host = False, None
        await _throttle()
        try:
            answer = await resolver.resolve(domain, "MX", lifetime=2.0, raise_on_no_answer=False)
            if answer.rrset:
                first = next(iter(answer))
                has_mx, mx_host = True, str(first.exchange).rstrip(".").lower()[:253]
        except (dns.exception.DNSException, OSError, asyncio.TimeoutError):
            pass
        rdap_age = None
        try:
            status, findings, _ = await rdap_check(domain)
            if status == "ok":
                rdap_age = next((int(item.evidence["age_days"]) for item in findings if item.evidence.get("age_days") is not None), None)
        except Exception:
            pass
        return ProbeState(True, has_mx, mx_host, rdap_age)


def _transition(previous: dict, current: ProbeState):
    if not current.resolves:
        return None
    if current.has_mx and not previous.get("has_mx"):
        if not previous.get("resolves"):
            return "strong", "lookalike_resolving_with_signals"
        return "moderate", "lookalike_new_mx_record"
    if current.resolves and not previous.get("resolves"):
        if current.rdap_age_days is not None and current.rdap_age_days < 30:
            return "strong", "lookalike_recent_registration_confirmed"
        return "info", "lookalike_now_resolving"
    if previous.get("has_mx") and current.has_mx and previous.get("mx_host") != current.mx_host:
        return "moderate", "lookalike_mx_provider_changed"
    if (current.rdap_age_days is not None and current.rdap_age_days < 30
            and previous.get("rdap_age_days") != current.rdap_age_days):
        return "strong", "lookalike_recent_registration_confirmed"
    return None


async def scan_watch(watch: dict):
    watch_id, owner_id, domain = watch["id"], watch["owner_id"], watch["domain_ascii"]
    candidates = generate_candidates(domain, watch.get("known_own_domains") or ())
    existing: dict[str, dict] = {}
    if not db.pool:
        return
    async with db.pool.connection() as conn:
        rows = await (await conn.execute(
            "SELECT candidate_ascii,resolves,has_mx,mx_host,rdap_age_days FROM lookalike_state WHERE watch_id=%s",
            (watch_id,),
        )).fetchall()
        existing = {row[0]: {"resolves": row[1], "has_mx": row[2], "mx_host": row[3], "rdap_age_days": row[4]} for row in rows}
        await conn.execute("UPDATE watch_domains SET wildcard_dns_detected=false WHERE id=%s", (watch_id,))
    suffix = domain.split(".", 1)[-1]
    if await _wildcard_detected(suffix):
        async with db.pool.connection() as conn:
            async with conn.transaction():
                await conn.execute(
                    "UPDATE watch_domains SET wildcard_dns_detected=true WHERE id=%s", (watch_id,),
                )
                await conn.execute("UPDATE watch_domains SET lookalike_scanned_at=now() WHERE id=%s", (watch_id,))
        return
    semaphore = asyncio.Semaphore(20)

    async def limited(candidate):
        async with semaphore:
            return candidate, await _probe(candidate)

    results = await asyncio.gather(*(limited(candidate) for candidate in candidates), return_exceptions=True)
    async with db.pool.connection() as conn:
        async with conn.transaction():
            for item in results:
                if isinstance(item, BaseException):
                    continue
                candidate, state = item
                previous = existing.get(candidate)
                await conn.execute(
                    "INSERT INTO lookalike_state(watch_id,candidate_ascii,resolves,has_mx,mx_host,rdap_age_days) "
                    "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT(watch_id,candidate_ascii) DO UPDATE SET "
                    "resolves=excluded.resolves,has_mx=excluded.has_mx,mx_host=excluded.mx_host,rdap_age_days=excluded.rdap_age_days,last_checked=now()",
                    (watch_id, candidate, state.resolves, state.has_mx, state.mx_host, state.rdap_age_days),
                )
                # First observations, including candidates introduced by a later generator update, are silent.
                if previous is None or watch.get("lookalike_scanned_at") is None:
                    continue
                transition = _transition(previous, state)
                if not transition:
                    continue
                severity, event = transition
                evidence = {"event": event, "resolves": state.resolves, "has_mx": state.has_mx,
                            "mx_host": state.mx_host, "rdap_age_days": state.rdap_age_days}
                dedupe = f"lookalike:{owner_id}:{watch_id}:{candidate}:{event}"
                await emit_alert(conn, owner_id=owner_id, watch_id=watch_id, kind="lookalike_transition",
                                 severity=severity, target=candidate, dedupe_key=dedupe,
                                 evidence=evidence, source="dns_observation")
            # This timestamp moves only in the transaction that commits all state changes.
            await conn.execute("UPDATE watch_domains SET lookalike_scanned_at=now() WHERE id=%s", (watch_id,))


async def lookalike_scan_once(limit: int = 2):
    if not db.pool:
        return
    async with db.pool.connection() as conn:
        watches = await (await conn.execute(
            "SELECT id,owner_id,domain_ascii,known_own_domains,lookalike_scanned_at FROM watch_domains "
            "WHERE enabled=true AND (lookalike_scanned_at IS NULL OR lookalike_scanned_at < now()-interval '24 hours') "
            "ORDER BY lookalike_scanned_at NULLS FIRST LIMIT %s", (limit,),
        )).fetchall()
    for row in watches:
        try:
            await scan_watch(dict(zip(("id", "owner_id", "domain_ascii", "known_own_domains", "lookalike_scanned_at"), row)))
        except Exception as exc:
            log.warning("Lookalike scan failed (%s)", type(exc).__name__)
            continue
