"""Live SPF, DKIM and DMARC verification.

The receiving mail server's ``Authentication-Results`` header is treated as a
claim.  When network access is available we independently fetch DNS records,
evaluate SPF against the originating IP, verify DKIM with dkimpy and evaluate
DMARC alignment.  If a check cannot be performed we say so explicitly.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from app.config import Settings
from app.engine.dns_ssl import DNSAnalyzer
from app.engine.urls import registrable_domain
from app.engine.utils import truncate

logger = logging.getLogger(__name__)


class SPFEvaluator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.lookups = 0
        self.max_lookups = 10
        self.cache: dict[tuple[str, str], list[str]] = {}

    async def _query(self, name: str, record_type: str) -> list[str]:
        key = (name, record_type)
        if key in self.cache:
            return self.cache[key]
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = min(4.0, self.settings.network_timeout_seconds)
        resolver.timeout = min(3.0, self.settings.network_timeout_seconds)
        try:
            answer = await resolver.resolve(name, record_type, raise_on_no_answer=False)
            if answer.rrset is None:
                values: list[str] = []
            elif record_type == "TXT":
                values = []
                for item in answer:
                    chunks = getattr(item, "strings", None)
                    values.append(
                        b"".join(chunks).decode("utf-8", errors="replace")
                        if chunks
                        else str(item).strip('"')
                    )
            elif record_type == "MX":
                values = [str(item.exchange).rstrip(".") for item in answer]
            else:
                values = [str(item).rstrip(".") for item in answer]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            values = []
        except (dns.exception.Timeout, dns.exception.DNSException):
            values = []
        self.cache[key] = values
        return values

    async def evaluate(self, domain: str, ip: str, record: str, depth: int = 0) -> dict[str, Any]:
        domain = (domain or "").lower().strip(".")
        result = {
            "domain": domain,
            "ip": ip,
            "record": truncate(record, 1000),
            "result": "none",
            "matched": None,
            "explanation": "",
            "lookups": 0,
            "source": "live_dns",
        }
        if not record:
            result["explanation"] = f"No SPF record was found for {domain}."
            return result
        if not record.lower().startswith("v=spf1"):
            result["result"] = "permerror"
            result["explanation"] = "The SPF TXT record does not begin with v=spf1."
            return result
        if depth > 5:
            result["result"] = "permerror"
            result["explanation"] = "SPF include recursion exceeded the safe depth."
            return result
        try:
            source_ip = ipaddress.ip_address(ip)
        except ValueError:
            result["explanation"] = "No valid originating IP was available, so SPF could not be evaluated."
            return result

        terms = record.split()[1:]
        redirect_domain = None
        for term in terms:
            if self.lookups >= self.max_lookups:
                result["result"] = "permerror"
                result["explanation"] = "SPF DNS lookup limit (10) exceeded."
                return result
            if term.lower().startswith("redirect="):
                redirect_domain = term.split("=", 1)[1]
                continue
            qualifier = "+"
            body = term
            if term[:1] in {"+", "-", "~", "?"}:
                qualifier = term[0]
                body = term[1:]
            mechanism, _, value = body.partition(":")
            mechanism = mechanism.lower()
            matched = False
            detail = ""
            if mechanism == "all":
                matched = True
                detail = "matched 'all'"
            elif mechanism in {"ip4", "ip6"}:
                try:
                    network = ipaddress.ip_network(value, strict=False)
                    matched = source_ip in network
                    detail = f"source IP {ip} {'is' if matched else 'is not'} in {network}"
                except ValueError:
                    detail = f"invalid {mechanism} value '{value}'"
            elif mechanism in {"a", "mx"}:
                self.lookups += 1
                target = value.split("/", 1)[0] or domain
                hosts = [target] if mechanism == "a" else await self._query(target, "MX")
                addresses: list[str] = []
                for host in hosts[:10]:
                    addresses.extend(await self._query(host, "A"))
                    addresses.extend(await self._query(host, "AAAA"))
                for address in addresses:
                    try:
                        if ipaddress.ip_address(address) == source_ip:
                            matched = True
                            break
                    except ValueError:
                        continue
                detail = f"{mechanism} target {target} resolved to {len(addresses)} address(es)"
            elif mechanism == "include":
                self.lookups += 1
                included_record = ""
                txt_values = await self._query(value, "TXT")
                for candidate in txt_values:
                    if candidate.lower().startswith("v=spf1"):
                        included_record = candidate
                        break
                if included_record:
                    nested = await self.evaluate(value, ip, included_record, depth + 1)
                    self.lookups += nested.get("lookups", 0)
                    if nested["result"] == "pass":
                        matched = True
                        qualifier = "+"
                        detail = f"include:{value} returned pass"
                    elif nested["result"] in {"fail", "softfail"}:
                        detail = f"include:{value} returned {nested['result']}"
                    else:
                        detail = f"include:{value} returned {nested['result']}"
                else:
                    detail = f"include:{value} has no SPF record"
            elif mechanism == "exists":
                self.lookups += 1
                matched = bool(await self._query(value or domain, "A"))
                detail = f"exists:{value or domain} {'resolved' if matched else 'did not resolve'}"
            elif mechanism == "ptr":
                # ptr is deprecated and intentionally not used for a decisive result
                detail = "ptr mechanism is deprecated and was not evaluated"
            else:
                detail = f"unsupported mechanism '{mechanism}'"
                continue

            if matched:
                mapping = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
                result.update(
                    {
                        "result": mapping.get(qualifier, "neutral"),
                        "matched": term,
                        "explanation": f"SPF {mapping.get(qualifier, 'neutral')}: {detail}.",
                        "lookups": self.lookups,
                    }
                )
                return result

        if redirect_domain:
            self.lookups += 1
            txt_values = await self._query(redirect_domain, "TXT")
            redirect_record = next(
                (value for value in txt_values if value.lower().startswith("v=spf1")), None
            )
            if redirect_record:
                nested = await self.evaluate(redirect_domain, ip, redirect_record, depth + 1)
                result.update(nested)
                result["lookups"] = self.lookups + nested.get("lookups", 0)
                return result

        result["result"] = "neutral"
        result["explanation"] = "No SPF mechanism matched the source IP; the record has no decisive 'all'."
        result["lookups"] = self.lookups
        return result


def _sync_txt(name: str, timeout: float = 5.0) -> bytes:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answer = resolver.resolve(name, "TXT", raise_on_no_answer=False)
        if answer.rrset is None:
            return b""
        chunks = []
        for item in answer:
            strings = getattr(item, "strings", None)
            if strings:
                chunks.append(b"".join(strings))
        return b"".join(chunks)
    except Exception:
        return b""


async def _verify_dkim(raw: bytes, settings: Settings) -> dict[str, Any]:
    if not raw:
        return {"result": "none", "verified": False, "method": "none", "errors": ["No raw message"]}
    try:
        import dkim  # type: ignore

        timeout = max(3.0, settings.network_timeout_seconds)
        try:
            verified = await asyncio.wait_for(
                asyncio.to_thread(dkim.verify, raw, dnsfunc=_sync_txt, timeout=timeout),
                timeout=timeout + 2,
            )
            return {
                "result": "pass" if verified else "fail",
                "verified": bool(verified),
                "method": "dkimpy_live_dns",
                "errors": [],
            }
        except TimeoutError:
            return {
                "result": "not_verified",
                "verified": False,
                "method": "dkimpy_live_dns",
                "errors": ["DKIM verification timed out."],
            }
        except Exception as exc:
            message = truncate(f"{type(exc).__name__}: {exc}", 300)
            state = "fail" if any(word in message.lower() for word in ("body", "signature", "verify", "key")) else "not_verified"
            return {"result": state, "verified": False, "method": "dkimpy_live_dns", "errors": [message]}
    except ImportError:
        return {
            "result": "not_verified",
            "verified": False,
            "method": "unavailable",
            "errors": ["dkimpy is not installed."],
        }


def _align(left: str, right: str, mode: str) -> bool:
    if not left or not right:
        return False
    left = left.lower().strip(".")
    right = right.lower().strip(".")
    if mode == "s":
        return left == right
    return registrable_domain(left) == registrable_domain(right) and bool(registrable_domain(left))


def _parse_dmarc(record: str | None) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in (record or "").split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


async def verify_email_auth(
    raw_message: bytes,
    parsed: dict[str, Any],
    settings: Settings,
    dns: DNSAnalyzer,
) -> dict[str, Any]:
    from_domain = parsed.get("from_domain") or ""
    return_domain = parsed.get("return_domain") or from_domain
    header_auth = parsed.get("auth_results") or {}

    received = parsed.get("received") or []
    public_ips = [hop.get("ip") for hop in received if hop.get("ip") and not hop.get("private_ip")]
    source_ip = public_ips[-1] if public_ips else ""
    if not source_ip:
        x_origin = (parsed.get("headers") or {}).get("X-Originating-IP") or []
        if x_origin:
            import re

            match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", x_origin[0])
            if match:
                source_ip = match.group(0)

    if not settings.allow_network:
        return {
            "enabled": False,
            "spf": {
                "result": header_auth.get("spf") or "not_verified",
                "source": "receiving_server_header" if header_auth.get("spf") else "not_verified",
                "explanation": "Network disabled; SPF was not independently evaluated.",
            },
            "dkim": {
                "result": (header_auth.get("dkim") or ["not_verified"])[0],
                "verified": False,
                "method": "receiving_server_header",
                "errors": ["Network disabled; DKIM signature was not verified."],
            },
            "dmarc": {
                "result": header_auth.get("dmarc") or "not_verified",
                "source": "receiving_server_header" if header_auth.get("dmarc") else "not_verified",
                "explanation": "Network disabled; DMARC was not independently evaluated.",
            },
            "summary": "Live authentication checks skipped (network disabled); header claims used where present.",
        }

    dns_info = await dns.lookup(from_domain) if from_domain else None
    spf_record = dns_info.spf if dns_info else None
    if not spf_record and return_domain and return_domain != from_domain:
        return_info = await dns.lookup(return_domain)
        spf_record = return_info.spf
    evaluator = SPFEvaluator(settings)
    if spf_record and source_ip:
        spf_result = await evaluator.evaluate(return_domain or from_domain, source_ip, spf_record)
    else:
        spf_result = {
            "domain": return_domain or from_domain,
            "ip": source_ip,
            "record": spf_record,
            "result": "none" if not spf_record else "not_verified",
            "explanation": (
                "No SPF record found."
                if not spf_record
                else "No originating IP was available for SPF evaluation."
            ),
            "source": "live_dns",
        }

    signatures = parsed.get("dkim_signatures") or []
    if signatures:
        dkim_result = await _verify_dkim(raw_message, settings)
    else:
        dkim_result = {
            "result": "none",
            "verified": False,
            "method": "none",
            "errors": ["The message has no DKIM-Signature header."],
        }
    header_dkim = (header_auth.get("dkim") or [])
    if dkim_result["verified"]:
        dkim_result["result"] = "pass"
    elif dkim_result["result"] in {"not_verified", "none"} and "pass" in header_dkim:
        dkim_result.update(
            {
                "result": "pass",
                "verified": False,
                "method": "receiving_server_header",
            }
        )
    dkim_result["signature_domains"] = [item.get("domain") for item in signatures if item.get("domain")]

    dmarc_info = dns_info if dns_info else None
    dmarc_record = dmarc_info.dmarc if dmarc_info else None
    tags = _parse_dmarc(dmarc_record)
    policy = tags.get("p")
    adkim = "s" if tags.get("adkim", "r").lower() == "s" else "r"
    aspf = "s" if tags.get("aspf", "r").lower() == "s" else "r"
    aligned_spf = bool(spf_result.get("result") == "pass" and _align(spf_result.get("domain", ""), from_domain, aspf))
    dkim_domains = dkim_result.get("signature_domains") or []
    dkim_pass = dkim_result.get("result") == "pass"
    aligned_dkim = bool(dkim_pass and any(_align(domain, from_domain, adkim) for domain in dkim_domains))
    if not dmarc_record:
        dmarc_result = {
            "result": "none",
            "record": None,
            "policy": None,
            "aligned_spf": aligned_spf,
            "aligned_dkim": aligned_dkim,
            "explanation": f"No DMARC record was found at _dmarc.{from_domain}.",
            "source": "live_dns",
        }
    else:
        passed = aligned_spf or aligned_dkim
        dmarc_result = {
            "result": "pass" if passed else "fail",
            "record": truncate(dmarc_record, 1000),
            "policy": policy,
            "subdomain_policy": tags.get("sp"),
            "pct": tags.get("pct"),
            "aligned_spf": aligned_spf,
            "aligned_dkim": aligned_dkim,
            "explanation": (
                f"DMARC {'passed' if passed else 'failed'} for policy p={policy}. "
                f"Aligned SPF: {aligned_spf}; aligned DKIM: {aligned_dkim}."
            ),
            "source": "live_dns",
        }

    summary_parts = [
        f"SPF {spf_result.get('result', 'unknown')}",
        f"DKIM {dkim_result.get('result', 'unknown')}",
        f"DMARC {dmarc_result.get('result', 'unknown')}",
    ]
    return {
        "enabled": True,
        "source_ip": source_ip,
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
        "header_claims": header_auth,
        "dns": dns_info.model_dump(mode="json") if dns_info else None,
        "summary": "; ".join(summary_parts) + ".",
    }
