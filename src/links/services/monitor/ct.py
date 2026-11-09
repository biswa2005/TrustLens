from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import unicodedata
from datetime import datetime, timezone

import httpx
import idna
import tldextract
from rapidfuzz.distance import DamerauLevenshtein

from links.services import db
from links.services.monitor.alerts import emit_alert

_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_CT_LIMIT = 10 * 1024 * 1024
_MAX_SANS = 50
_MAX_SAN_LENGTH = 253
_COMBOS = ("login", "verify", "account", "secure", "portal")
_SUFFIXES = ("inc", "llc", "bv", "ltd", "limited", "corporation", "corp")
_watch_cache: tuple[float, list[dict]] = (0.0, [])


def invalidate_watch_cache():
    global _watch_cache
    _watch_cache = (0.0, [])


def clean_org(value: str | None) -> str:
    value = unicodedata.normalize("NFKC", value or "")[:2000]
    value = "".join(ch for ch in value if ch.isprintable() and not unicodedata.category(ch).startswith("C"))
    value = re.sub(r"\s+", " ", value).strip(" .,-")
    while value:
        words = value.split()
        tail = re.sub(r"[^a-z]", "", words[-1].lower())
        if tail not in _SUFFIXES:
            break
        value = " ".join(words[:-1]).strip(" .,-")
    return value.casefold()[:200] or "unknown"


def _issuer_org(item: dict) -> str:
    if isinstance(item, str):
        issuer = item
    else:
        issuer = item.get("issuer") or item.get("issuer_name") or item.get("issuerOrganization")
        if issuer is None:
            # Streaming certificate payloads and chain subjects may pass the
            # distinguished-name object directly instead of the full record.
            issuer = item
    if isinstance(issuer, dict):
        for key in ("O", "organization", "organizationName", "CN", "commonName"):
            if issuer.get(key):
                return clean_org(str(issuer[key]))
    if isinstance(issuer, list):
        attrs = {}
        for part in issuer:
            if isinstance(part, dict):
                key = part.get("name") or part.get("oid")
                val = part.get("value")
                if key and val:
                    attrs[str(key).split(".")[-1].upper()] = str(val)
        return clean_org(attrs.get("O") or attrs.get("CN"))
    if isinstance(issuer, str):
        attrs = {}
        for key, val in re.findall(r"(?:^|[,/])\s*(O|CN)\s*=\s*([^,/]+)", issuer, re.I):
            attrs[key.upper()] = val.strip()
        if attrs:
            return clean_org(attrs.get("O") or attrs.get("CN"))
    return "unknown"


def _sanitize_sans(values) -> list[str]:
    if isinstance(values, str):
        values = re.split(r"[,\n]", values, maxsplit=_MAX_SANS - 1)
    if not isinstance(values, (tuple, list)):
        return []
    result = []
    for raw in values[:_MAX_SANS]:
        if not isinstance(raw, str):
            continue
        value = "".join(ch for ch in raw.strip() if ch.isprintable() and not unicodedata.category(ch).startswith("C"))
        if value.lower().startswith("dns:"):
            value = value[4:]
        value = value.strip().rstrip(".").lower()
        if value.startswith("*."):
            value = value[2:]
        if not value or len(value) > _MAX_SAN_LENGTH or "*" in value:
            continue
        try:
            value = idna.encode(value, uts46=True).decode("ascii")
        except (idna.IDNAError, UnicodeError):
            continue
        if len(value) > _MAX_SAN_LENGTH:
            continue
        result.append(value)
    return list(dict.fromkeys(result))


def _decode_label(label: str) -> str:
    if label.lower().startswith("xn--"):
        try:
            return idna.decode(label.encode("ascii"), uts46=True).lower()
        except (idna.IDNAError, UnicodeError):
            return ""
    return label.lower()


def _registered_domain(host: str) -> str:
    ext = _extract(host)
    return ext.top_domain_under_public_suffix.lower() if ext.top_domain_under_public_suffix else host.lower()


def _brand_label(domain: str) -> str:
    return _extract(domain).domain.lower() or domain.split(".")[0].lower()


def _san_prefilter(san: str, watch: dict, candidates: set[str]) -> bool:
    apex = watch["domain_ascii"]
    if san == apex or san.endswith("." + apex):
        return True
    labels = [_decode_label(label) for label in san.split(".")]
    brand = _brand_label(apex)
    if any(brand in label for label in labels):
        return True
    registered = _registered_domain(san)
    candidate_labels = watch.get("candidate_labels", set())
    if registered in candidates or _decode_label(_extract(registered).domain) in candidate_labels:
        return True
    brand_label = _decode_label(brand)
    if len(brand_label) >= 6:
        for label in labels:
            if abs(len(label) - len(brand_label)) <= 2 and DamerauLevenshtein.distance(label, brand_label) <= 2:
                return True
    return False


def _match_rule(san: str, watch: dict, candidates: set[str]) -> str | None:
    domain = watch["domain_ascii"]
    own = set(watch.get("known_own_domains") or ())
    registered = _registered_domain(san)
    if registered in own:
        return None
    brand = _brand_label(domain)
    labels = [_decode_label(label) for label in san.split(".")]
    if san == domain or san.endswith("." + domain):
        return "own_domain"
    if registered in candidates:
        return "lookalike_cert_issued"
    label = _decode_label(_extract(registered).domain)
    if brand in label and any(word in label for word in _COMBOS):
        return "combosquat_cert"
    if registered != domain and any(brand in label for label in labels[:-1]):
        return "brand_in_subdomain_cert"
    distance_cap = 0 if len(brand) < 6 else 1 if len(brand) < 10 else 2
    if distance_cap and abs(len(label) - len(brand)) <= distance_cap and DamerauLevenshtein.distance(label, brand) <= distance_cap:
        return "similar_name_cert"
    return None


def _certificate_parts(message: dict) -> tuple[list[str], str, str, str]:
    data = message.get("data", message)
    if not isinstance(data, dict):
        return [], "unknown", "", ""
    leaf = data.get("leaf_cert") or data.get("certificate") or data
    if not isinstance(leaf, dict):
        leaf = {}
    extension = leaf.get("extensions") if isinstance(leaf.get("extensions"), dict) else {}
    sans = _sanitize_sans(leaf.get("subjectAltName") or leaf.get("san_dns") or leaf.get("all_domains") or extension.get("subjectAltName") or data.get("sans"))
    issuer_source = data.get("issuer") if isinstance(data.get("issuer"), (dict, list, str)) else leaf.get("issuer") or leaf
    if issuer_source == leaf and isinstance(data.get("chain"), list) and data["chain"]:
        issuer_source = data["chain"][0].get("subject", data["chain"][0]) if isinstance(data["chain"][0], dict) else leaf
    issuer = _issuer_org(issuer_source)
    if issuer == "unknown" and isinstance(data.get("chain"), list) and data["chain"] and isinstance(data["chain"][0], dict):
        issuer = _issuer_org(data["chain"][0].get("subject", data["chain"][0]))
    serial = re.sub(r"[^0-9a-f]", "", str(leaf.get("serial_number") or leaf.get("serialNumber") or leaf.get("serial") or data.get("serial") or "")[:1024].lower())[:256]
    cert_hash = str(leaf.get("fingerprint") or leaf.get("sha256") or data.get("fingerprint") or "")[:128]
    cert_hash = re.sub(r"[^0-9a-fA-F]", "", cert_hash).lower()[:64]
    if len(cert_hash) != 64:
        cert_hash = ""
    return sans, issuer, serial, cert_hash


def _dedupe_hash(watch_id, issuer: str, serial: str, san: str) -> str:
    material = f"{watch_id}:{issuer}:{serial}:{san}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


async def _watches():
    global _watch_cache
    if _watch_cache[0] > asyncio.get_running_loop().time():
        return _watch_cache[1]
    if not db.pool:
        return []
    async with db.pool.connection() as conn:
        rows = await (await conn.execute(
            "SELECT w.id,w.owner_id,w.domain_ascii,w.known_own_domains,w.baseline_done,w.baseline_empty "
            "FROM watch_domains w WHERE w.enabled=true"
        )).fetchall()
        watches = [dict(zip(("id", "owner_id", "domain_ascii", "known_own_domains", "baseline_done", "baseline_empty"), row)) for row in rows]
        for watch in watches:
            candidates = await (await conn.execute("SELECT candidate_ascii FROM lookalike_state WHERE watch_id=%s", (watch["id"],))).fetchall()
            watch["candidates"] = {item[0] for item in candidates}
            watch["candidate_labels"] = {_decode_label(_extract(item[0]).domain) for item in candidates}
    _watch_cache = (asyncio.get_running_loop().time() + 30, watches)
    return watches


async def process_certificate(message: dict) -> int:
    if not db.pool or not isinstance(message, dict):
        return 0
    sans, issuer, serial, cert_hash = _certificate_parts(message)
    if not sans or not serial:
        return 0
    watches = await _watches()
    emitted = 0
    for watch in watches:
        known_own = set(watch["known_own_domains"] or ())
        candidates = watch.get("candidates", set())
        matching_sans = [san for san in sans if _registered_domain(san) not in known_own and _san_prefilter(san, watch, candidates)]
        if not matching_sans:
            continue
        async with db.pool.connection() as conn:
            current = await (await conn.execute(
                "SELECT enabled,baseline_done,baseline_empty,known_own_domains FROM watch_domains WHERE id=%s AND owner_id=%s",
                (watch["id"], watch["owner_id"]),
            )).fetchone()
            if not current or not current[0]:
                invalidate_watch_cache()
                continue
            watch["baseline_done"], watch["baseline_empty"] = current[1], current[2]
            current_own = set(current[3] or ())
            for san in matching_sans:
                if _registered_domain(san) in current_own:
                    continue
                rule = _match_rule(san, watch, candidates)
                if not rule:
                    continue
                if rule == "own_domain" and not watch["baseline_done"]:
                    continue
                if rule == "own_domain" and watch["baseline_empty"]:
                    rule, severity = "initial_baseline_established", "info"
                elif rule == "own_domain":
                    baseline = await (await conn.execute(
                        "SELECT 1 FROM domain_issuer_baseline WHERE watch_id=%s AND issuer_org=%s",
                        (watch["id"], issuer),
                    )).fetchone()
                    if baseline:
                        continue
                    rule, severity = "unrecognized_issuer", "strong"
                else:
                    severity = "strong" if rule in {"lookalike_cert_issued", "brand_in_subdomain_cert"} else "moderate"
                apex = _registered_domain(san)
                dedupe_hash = _dedupe_hash(watch["id"], issuer, serial, apex)
                seen = await (await conn.execute("SELECT 1 FROM ct_seen_certs WHERE cert_dedupe_hash=%s", (dedupe_hash,))).fetchone()
                if seen:
                    break
                dedupe = (f"ct:{watch['owner_id']}:{watch['id']}:initial_baseline_established"
                          if rule == "initial_baseline_established"
                          else f"ct:{watch['owner_id']}:{watch['id']}:{rule}:{dedupe_hash}")
                evidence = {"rule": rule, "issuer_org": issuer, "serial_hex": serial[:256],
                            "certificate_sha256": cert_hash or None, "san_apex": apex}
                inserted = await emit_alert(conn, owner_id=watch["owner_id"], watch_id=watch["id"],
                                            kind="ct_issuance", severity=severity, target=san,
                                            dedupe_key=dedupe, evidence=evidence, source="certificate_transparency")
                if inserted:
                    await conn.execute("INSERT INTO ct_seen_certs(cert_dedupe_hash) VALUES (%s) ON CONFLICT DO NOTHING", (dedupe_hash,))
                    if rule == "initial_baseline_established":
                        await conn.execute("UPDATE watch_domains SET baseline_empty=false WHERE id=%s", (watch["id"],))
                        watch["baseline_empty"] = False
                    emitted += 1
                break  # strict priority and one alert per watch/certificate
    return emitted


async def crt_backfill_watch(watch: dict):
    domain, watch_id = watch["domain_ascii"], watch["id"]
    timeout = httpx.Timeout(15.0)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            async with client.stream("GET", "https://crt.sh/", params={"q": domain, "output": "json"}) as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > _CT_LIMIT:
                        raise ValueError("crt.sh response exceeded 10 MB")
        records = json.loads(body)
        if not isinstance(records, list):
            raise ValueError("invalid crt.sh response")
    except Exception as exc:
        attempts = int(watch.get("backfill_attempts") or 0) + 1
        delays = (300, 900, 3600, 21600)
        delay = delays[min(attempts - 1, len(delays) - 1)]
        async with db.pool.connection() as conn:
            await conn.execute(
                "UPDATE watch_domains SET backfill_attempts=%s,next_backfill_at=now()+(%s * interval '1 second'),last_backfill_error=%s WHERE id=%s",
                (attempts, delay, type(exc).__name__[:80], watch_id),
            )
        return
    issuers = set()
    max_id = 0
    for item in records:
        if not isinstance(item, dict):
            continue
        issuers.add(_issuer_org(item))
        try:
            max_id = max(max_id, int(item.get("id") or 0))
        except (ValueError, TypeError):
            pass
    async with db.pool.connection() as conn:
        async with conn.transaction():
            for issuer in issuers:
                if issuer != "unknown":
                    await conn.execute("INSERT INTO domain_issuer_baseline(watch_id,issuer_org) VALUES (%s,%s) ON CONFLICT DO NOTHING", (watch_id, issuer))
            await conn.execute(
                "UPDATE watch_domains SET baseline_done=true,baseline_empty=%s,backfill_attempts=0,next_backfill_at=now(),last_backfill_error=NULL,last_ct_log_id=GREATEST(last_ct_log_id,%s) WHERE id=%s",
                (not records, max_id, watch_id),
            )


async def crt_backfill_once(limit: int = 5):
    if not db.pool:
        return
    async with db.pool.connection() as conn:
        rows = await (await conn.execute(
            "SELECT id,domain_ascii,backfill_attempts FROM watch_domains WHERE enabled=true AND baseline_done=false AND next_backfill_at<=now() ORDER BY next_backfill_at LIMIT %s",
            (limit,),
        )).fetchall()
    for row in rows:
        await crt_backfill_watch(dict(zip(("id", "domain_ascii", "backfill_attempts"), row)))


async def crt_rule1_poll_once(limit: int = 5):
    """Fallback polling covers own-domain issuer changes only; no fuzzy rules."""
    if not db.pool:
        return 0, 0
    async with db.pool.connection() as conn:
        rows = await (await conn.execute(
            "SELECT id,owner_id,domain_ascii,known_own_domains,baseline_done,baseline_empty,last_ct_log_id "
            "FROM watch_domains WHERE enabled=true AND baseline_done=true ORDER BY last_ct_polled_at NULLS FIRST,last_ct_polled_at LIMIT %s", (limit,),
        )).fetchall()
    succeeded = failed = 0
    for row in rows:
        watch = dict(zip(("id", "owner_id", "domain_ascii", "known_own_domains", "baseline_done", "baseline_empty", "last_ct_log_id"), row))
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
                async with client.stream("GET", "https://crt.sh/", params={"q": watch["domain_ascii"], "output": "json"}) as response:
                    response.raise_for_status(); body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > _CT_LIMIT:
                            raise ValueError("crt.sh response exceeded 10 MB")
            entries = json.loads(body)
            if not isinstance(entries, list):
                continue
        except Exception:
            failed += 1
            continue
        succeeded += 1
        max_id = watch["last_ct_log_id"]
        for item in entries:
            if not isinstance(item, dict):
                continue
            try:
                cert_id = int(item.get("id") or 0)
            except (ValueError, TypeError):
                continue
            max_id = max(max_id, cert_id)
            if cert_id <= watch["last_ct_log_id"]:
                continue
            names = _sanitize_sans(item.get("name_value"))
            known_own = set(watch.get("known_own_domains") or ())
            if not any((name == watch["domain_ascii"] or name.endswith("." + watch["domain_ascii"]))
                       and _registered_domain(name) not in known_own for name in names):
                continue
            issuer = _issuer_org(item)
            async with db.pool.connection() as conn:
                allowed = await (await conn.execute(
                    "SELECT 1 FROM domain_issuer_baseline WHERE watch_id=%s AND issuer_org=%s",
                    (watch["id"], issuer),
                )).fetchone()
                if allowed:
                    continue
                rule = "initial_baseline_established" if watch["baseline_empty"] else "unrecognized_issuer"
                severity = "info" if watch["baseline_empty"] else "strong"
                sha = re.sub(r"[^0-9a-f]", "", str(item.get("sha256") or "").lower())[:64]
                if len(sha) != 64:
                    sha = ""
                serial = re.sub(r"[^0-9a-f]", "", str(item.get("serial_number") or "").lower())[:256]
                keyhash = _dedupe_hash(watch["id"], issuer, serial or str(cert_id), watch["domain_ascii"])
                inserted = await emit_alert(conn, owner_id=watch["owner_id"], watch_id=watch["id"], kind="ct_issuance",
                                 severity=severity, target=watch["domain_ascii"],
                                 dedupe_key=(f"ct:{watch['owner_id']}:{watch['id']}:initial_baseline_established" if rule == "initial_baseline_established" else f"ct:{watch['owner_id']}:{watch['id']}:{rule}:{keyhash}"),
                                 evidence={"rule": rule, "issuer_org": issuer, "certificate_sha256": sha[:64] or None,
                                           "san_apex": watch["domain_ascii"], "crtsh_record_id": cert_id},
                                 source="crt_sh_poll")
                if inserted:
                    async with db.pool.connection() as conn:
                        await conn.execute("INSERT INTO ct_seen_certs(cert_dedupe_hash) VALUES (%s) ON CONFLICT DO NOTHING", (keyhash,))
                        if rule == "initial_baseline_established":
                            await conn.execute("UPDATE watch_domains SET baseline_empty=false WHERE id=%s", (watch["id"],))
        async with db.pool.connection() as conn:
            await conn.execute("UPDATE watch_domains SET last_ct_log_id=%s,last_ct_polled_at=now() WHERE id=%s", (max_id, watch["id"]))
    return succeeded, failed
