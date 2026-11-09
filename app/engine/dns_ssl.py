"""Passive DNS, RDAP and TLS certificate inspection."""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from app.config import Settings
from app.engine.cache import TTLCache
from app.engine.net import NetworkDisabled, SafeHttpClient
from app.engine.utils import truncate
from app.schemas import DNSInfo, SSLInfo

logger = logging.getLogger(__name__)


def _flatten_name(value: Any) -> str:
    if isinstance(value, tuple):
        return " ".join(_flatten_name(item) for item in value if item)
    if isinstance(value, list):
        return ", ".join(_flatten_name(item) for item in value if item)
    return str(value)


class DNSAnalyzer:
    def __init__(self, settings: Settings, cache: TTLCache | None = None) -> None:
        self.settings = settings
        self.cache = cache or TTLCache(default_ttl=1800)

    async def lookup(self, domain: str) -> DNSInfo:
        domain = (domain or "").strip(".").lower()
        cached = self.cache.get(f"dns:{domain}")
        if isinstance(cached, DNSInfo):
            return cached
        if not self.settings.allow_network or not domain:
            return DNSInfo(errors=["Network access disabled; DNS not queried."])

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self.settings.network_timeout_seconds
        resolver.timeout = min(4.0, self.settings.network_timeout_seconds)

        async def query(record_type: str) -> list[str]:
            try:
                answer = await resolver.resolve(domain, record_type, raise_on_no_answer=False)
                if answer.rrset is None:
                    return []
                if record_type == "TXT":
                    values = []
                    for item in answer:
                        chunks = getattr(item, "strings", None)
                        if chunks:
                            values.append(b"".join(chunks).decode("utf-8", errors="replace"))
                        else:
                            values.append(str(item).strip('"'))
                    return values
                return [str(item).rstrip(".") for item in answer]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                return []
            except (dns.exception.Timeout, dns.exception.DNSException) as exc:
                logger.debug("DNS %s lookup for %s failed: %s", record_type, domain, exc)
                return []

        a, aaaa, mx, ns, txt, cname = await asyncio.gather(
            query("A"), query("AAAA"), query("MX"), query("NS"), query("TXT"), query("CNAME")
        )
        spf = next((value for value in txt if value.lower().startswith("v=spf1")), None)
        dmarc: str | None = None
        dmarc_policy: str | None = None
        if domain:
            try:
                dmarc_answer = await resolver.resolve(f"_dmarc.{domain}", "TXT", raise_on_no_answer=False)
                if dmarc_answer.rrset is not None:
                    for item in dmarc_answer:
                        chunks = getattr(item, "strings", None)
                        value = (
                            b"".join(chunks).decode("utf-8", errors="replace")
                            if chunks
                            else str(item).strip('"')
                        )
                        if value.lower().startswith("v=dmarc1"):
                            dmarc = value
                            for part in value.split(";"):
                                if part.strip().lower().startswith("p="):
                                    dmarc_policy = part.split("=", 1)[1].strip().lower()
                            break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except (dns.exception.Timeout, dns.exception.DNSException):
                pass

        info = DNSInfo(
            a=sorted(set(a)),
            aaaa=sorted(set(aaaa)),
            mx=sorted(set(mx)),
            ns=sorted(set(ns)),
            txt=[truncate(value, 500) for value in txt][:15],
            cname=sorted(set(cname)),
            spf=spf,
            dmarc=truncate(dmarc, 500) if dmarc else None,
            dmarc_policy=dmarc_policy,
        )
        if not (info.a or info.aaaa or info.cname or info.mx):
            info.errors.append("No A/AAAA/CNAME/MX records were returned.")
        self.cache.set(f"dns:{domain}", info, ttl=1800)
        return info

    async def source_ips(self, domain: str) -> list[str]:
        info = await self.lookup(domain)
        return info.a + info.aaaa


def inspect_tls(host: str, timeout: float = 6.0, port: int = 443) -> SSLInfo:
    """Blocking TLS inspection, intended to be run in a worker thread.

    ``SSLInfo.inspected`` separates "the certificate failed validation" (a real
    security observation) from "we never reached a TLS endpoint" (which proves
    nothing about the certificate and must not raise the reputation score).
    """

    if not host:
        return SSLInfo(valid=False, inspected=False, error="Empty hostname")

    def connect(verify: bool) -> tuple[ssl.SSLSocket, dict[str, Any]]:
        if verify:
            context = ssl.create_default_context()
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        wrapped = context.wrap_socket(raw, server_hostname=host)
        return wrapped, wrapped.getpeercert() or {}

    info = SSLInfo()
    cert: dict[str, Any] = {}
    try:
        with_verify: ssl.SSLSocket | None = None
        try:
            with_verify, cert = connect(verify=True)
            info.valid = True
        except (ssl.SSLCertVerificationError, ssl.SSLError) as exc:
            info.valid = False
            info.error = truncate(str(exc), 300)
            try:
                unverified, cert = connect(verify=False)
                try:
                    unverified.close()
                except OSError:
                    pass
            except (OSError, ssl.SSLError) as inner:
                info.error = truncate(f"{info.error}; {inner}", 400)
                return info
        finally:
            if with_verify is not None:
                try:
                    with_verify.close()
                except OSError:
                    pass

        if cert:
            info.subject = _flatten_name(cert.get("subject"))
            info.issuer = _flatten_name(cert.get("issuer"))
            info.not_before = cert.get("notBefore")
            info.not_after = cert.get("notAfter")
            san = cert.get("subjectAltName") or ()
            info.san = [value for kind, value in san if kind in {"DNS", "IP Address"}][:40]
            if info.not_after:
                try:
                    expires = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(info.not_after), tz=UTC
                    )
                    info.days_remaining = (expires - datetime.now(UTC)).days
                except (ValueError, OverflowError):
                    pass
        if not cert and info.valid:
            info.valid = False
            info.error = info.error or "TLS handshake succeeded but no certificate was returned."
    except TimeoutError:
        info.valid = False
        info.inspected = False
        info.error = "TLS connection timed out."
    except socket.gaierror as exc:
        # DNS never resolved: no TLS endpoint was reached, so the certificate
        # itself was never presented and cannot be judged either way.
        info.valid = False
        info.inspected = False
        info.error = truncate(f"DNS resolution failed: {exc}", 300)
    except (ConnectionRefusedError, ConnectionResetError) as exc:
        info.valid = False
        info.inspected = False
        info.error = truncate(f"{type(exc).__name__}: {exc}", 300)
    except (OSError, ssl.SSLError) as exc:
        # An endpoint answered.  For ssl.SSLError the peer did speak TLS and the
        # handshake failed -> that IS an invalid/untrusted certificate outcome.
        info.valid = False
        info.inspected = isinstance(exc, ssl.SSLError)
        info.error = truncate(f"{type(exc).__name__}: {exc}", 300)
    return info


class TLSAnalyzer:
    def __init__(self, settings: Settings, cache: TTLCache | None = None) -> None:
        self.settings = settings
        self.cache = cache or TTLCache(default_ttl=3600)

    async def inspect(self, host: str, port: int = 443) -> SSLInfo:
        key = f"tls:{host}:{port}"
        cached = self.cache.get(key)
        if isinstance(cached, SSLInfo):
            return cached
        if not self.settings.allow_network:
            return SSLInfo(
                valid=False,
                inspected=False,
                error="Network access disabled; TLS not inspected.",
            )
        info = await asyncio.to_thread(
            inspect_tls, host, self.settings.network_timeout_seconds, port
        )
        self.cache.set(key, info, ttl=3600)
        return info


class RDAPAnalyzer:
    BASE = "https://rdap.org/domain/"

    def __init__(self, settings: Settings, http: SafeHttpClient, cache: TTLCache | None = None) -> None:
        self.settings = settings
        self.http = http
        self.cache = cache or TTLCache(default_ttl=86400)

    async def lookup(self, domain: str) -> dict[str, Any]:
        domain = (domain or "").lower().strip(".")
        if not domain:
            return {"available": False, "error": "Empty domain"}
        cached = self.cache.get(f"rdap:{domain}")
        if isinstance(cached, dict):
            return cached
        if not self.settings.allow_network:
            return {"available": False, "error": "Network access disabled."}
        try:
            status, data = await self.http.api_get_json(
                f"{self.BASE}{domain}",
                headers={"Accept": "application/rdap+json"},
                follow_redirects=True,
            )
        except NetworkDisabled as exc:
            return {"available": False, "error": str(exc)}
        except Exception as exc:  # pragma: no cover - network variability
            return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
        if status >= 400 or not isinstance(data, dict):
            return {"available": False, "error": f"RDAP HTTP {status}"}

        events: dict[str, str] = {}
        for event in data.get("events", []) or []:
            action = (event.get("eventAction") or "").lower()
            date = event.get("eventDate")
            if action and date:
                events[action] = date

        registrar = None
        for entity in data.get("entities", []) or []:
            roles = [role.lower() for role in entity.get("roles", []) or []]
            if "registrar" in roles:
                vcard = entity.get("vcardArray") or []
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                            registrar = str(item[3])
                            break
                if registrar:
                    break

        age_days = None
        registered = events.get("registration")
        if registered:
            try:
                registered_dt = datetime.fromisoformat(registered.replace("Z", "+00:00"))
                age_days = (datetime.now(UTC) - registered_dt).days
            except ValueError:
                pass

        result = {
            "available": True,
            "domain": data.get("ldhName") or domain,
            "status": data.get("status", []),
            "registrar": registrar,
            "registered": registered,
            "expires": events.get("expiration"),
            "updated": events.get("last changed"),
            "age_days": age_days,
            "nameservers": [
                item.get("ldhName") for item in data.get("nameservers", []) or [] if item.get("ldhName")
            ][:10],
        }
        self.cache.set(f"rdap:{domain}", result, ttl=86400)
        return result
