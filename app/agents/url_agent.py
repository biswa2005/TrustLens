"""URL Intelligence Agent.

Investigates every URL/domain queued by the specialist agents using static
structure, brand-registry matching, DNS, TLS, RDAP, threat intelligence and a
safe page fetch.  The agent deliberately does not decide whether a message is a
scam; it reports infrastructure evidence and residual uncertainty.
"""

from __future__ import annotations

from typing import Any

from app.agents.base import BaseAgent
from app.agents.runtime import AgentRuntime
from app.agents.state import InvestigationState
from app.agents.types import ToolResult
from app.engine.urls import registrable_domain
from app.engine.utils import dedupe
from app.schemas import Finding, Severity, Verdict


class URLIntelligenceAgent(BaseAgent):
    name = "url"
    display_name = "URL Intelligence Agent"
    llm_tools: list[str] = []

    def plan_tools(
        self, state: InvestigationState, runtime: AgentRuntime
    ) -> list[tuple[str, dict[str, Any]]]:
        settings = runtime.settings
        urls = dedupe(list(state.get("pending_urls") or []))[
            : settings.max_urls_per_investigation
        ]
        domains = dedupe(
            [str(item).lower().strip(".") for item in (state.get("pending_domains") or [])]
        )
        investigated_urls, investigated_domains = self._already_investigated(runtime)

        tools: list[tuple[str, dict[str, Any]]] = []
        for url in urls:
            if url in investigated_urls:
                continue
            tools.append(
                (
                    "investigate_url",
                    {"url": url, "fetch_page": bool(settings.enable_page_fetch)},
                )
            )

        # Domains are only investigated directly when no full URL already covers
        # them; this avoids duplicate DNS/TLS/RDAP work.
        covered = {
            registrable_domain(str((payload or {}).get("url") or ""))
            for _, payload in tools
        }
        for domain in domains:
            if domain in investigated_domains or domain in covered:
                continue
            tools.append(("investigate_domain", {"domain": domain}))
        return tools

    @staticmethod
    def _already_investigated(runtime: AgentRuntime) -> tuple[set[str], set[str]]:
        urls: set[str] = set()
        domains: set[str] = set()
        for item in runtime.store.items:
            if item.kind.value not in {"url_static", "url_fetch"}:
                continue
            data = item.data or {}
            for key in ("url", "normalized_url", "final_url"):
                value = str(data.get(key) or "")
                if value:
                    urls.add(value)
            host = str(data.get("host") or data.get("registered_domain") or "")
            if host:
                domains.add(host.lower().strip("."))
                registered = registrable_domain(host)
                if registered:
                    domains.add(registered)
        return urls, domains

    def deterministic_findings(
        self,
        state: InvestigationState,
        results: list[ToolResult],
        analysis: dict[str, Any] | None,
        runtime: AgentRuntime,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for result in results:
            if result.name not in {"investigate_url", "investigate_domain"}:
                continue
            data = result.data
            host = str(data.get("host") or data.get("registered_domain") or "the destination")
            verdict = str(data.get("verdict") or Verdict.INCONCLUSIVE.value)
            score = int(data.get("reputation_score") or 0)
            signals = [item for item in (data.get("signals") or []) if isinstance(item, dict)]
            refs = [item.id for item in result.evidence]
            if not refs:
                continue

            top_signals = signals[:6]
            signal_text = "; ".join(
                f"{item.get('label')}: {item.get('detail')}" for item in top_signals
            )
            intel = data.get("threat_intel") or []
            intel_text = ", ".join(
                f"{item.get('source')}={item.get('status')}" for item in intel[:6]
            )
            rdap = data.get("rdap") or {}
            ssl_info = data.get("ssl") or {}
            infrastructure_note = []
            if isinstance(rdap.get("age_days"), int):
                infrastructure_note.append(f"domain age {rdap['age_days']} days")
            if ssl_info.get("valid") is False:
                infrastructure_note.append(
                    "TLS certificate invalid"
                    if ssl_info.get("inspected", True)
                    else "TLS not inspected (host unreachable)"
                )
            if signal_text:
                infrastructure_note.append("signals: " + signal_text)
            if intel_text:
                infrastructure_note.append("threat intelligence: " + intel_text)

            if verdict in {Verdict.MALICIOUS.value, Verdict.LIKELY_MALICIOUS.value}:
                severity = (
                    Severity.CRITICAL if verdict == Verdict.MALICIOUS.value else Severity.HIGH
                )
                findings.append(
                    self.finding(
                        f"{'Malicious' if severity == Severity.CRITICAL else 'High-risk'} infrastructure: {host}",
                        f"URL investigation of `{data.get('normalized_url') or host}` produced a "
                        f"reputation score of {score}/100 and verdict **{verdict.replace('_', ' ')}**. "
                        + ("; ".join(infrastructure_note) + ". " if infrastructure_note else "")
                        + "The score is an additive, category-capped summary of the listed signals; "
                        "each signal is linked to its own evidence item. A match is actionable, but a "
                        "missing match would not have proved safety.",
                        severity,
                        0.9 if severity == Severity.CRITICAL else 0.84,
                        refs,
                        tags=["url", "infrastructure", "high_risk"]
                        + ([verdict] if verdict else []),
                        techniques=["T1583 Acquire Infrastructure", "T1566 Phishing"],
                    )
                )
            elif verdict == Verdict.SUSPICIOUS.value:
                findings.append(
                    self.finding(
                        f"Suspicious infrastructure: {host}",
                        f"URL investigation of `{data.get('normalized_url') or host}` produced a "
                        f"reputation score of {score}/100 (suspicious). "
                        + ("; ".join(infrastructure_note) + ". " if infrastructure_note else "")
                        + "The observations are consistent with phishing infrastructure but do not "
                        "prove malicious intent on their own.",
                        Severity.MEDIUM,
                        0.76,
                        refs,
                        tags=["url", "infrastructure", "suspicious"],
                    )
                )
            else:
                findings.append(
                    self.finding(
                        f"No adverse infrastructure indicators: {host}",
                        f"URL investigation of `{data.get('normalized_url') or host}` produced a "
                        f"reputation score of {score}/100. "
                        + (
                            "Checks completed: " + "; ".join(infrastructure_note) + ". "
                            if infrastructure_note
                            else "No structural, DNS, TLS or threat-intelligence red flags were observed. "
                        )
                        + "Absence of a blocklist match is not proof of safety; newly created phishing "
                        "domains are frequently unlisted.",
                        Severity.INFO,
                        0.7,
                        refs,
                        tags=["url", "infrastructure", "no_adverse_indicators"],
                    )
                )

            # Dedicated brand-impersonation finding: identity evidence is materially
            # different from generic URL reputation and deserves its own headline.
            brand_signals = [
                item
                for item in signals
                if "brand" in str(item.get("label", "")).lower()
                or "brand" in str(item.get("detail", "")).lower()
            ]
            if brand_signals:
                findings.append(
                    self.finding(
                        f"Lookalike domain targets a brand: {host}",
                        "The hostname structurally imitates a known brand: "
                        + "; ".join(str(item.get("detail")) for item in brand_signals[:3])
                        + ". Brand-lookalike hostnames are used to make phishing links look "
                        "plausible in a message or address bar.",
                        Severity.HIGH,
                        0.87,
                        refs,
                        tags=["url", "brand_impersonation", "lookalike"],
                        techniques=["T1656 Impersonation"],
                    )
                )

            malicious_intel = [
                item for item in intel if item.get("status") == "malicious"
            ]
            if malicious_intel:
                findings.append(
                    self.finding(
                        f"Threat-intelligence match for {host}",
                        "Independent providers classify this destination as malicious: "
                        + "; ".join(
                            f"{item.get('source')}: {item.get('detail')}"
                            for item in malicious_intel[:4]
                        )
                        + ". Do not open the link or enter credentials.",
                        Severity.CRITICAL,
                        0.93,
                        refs,
                        tags=["url", "threat_intel", "malicious"],
                    )
                )

            upload = [
                item
                for item in signals
                if "download" in str(item.get("label", "")).lower()
                or "executable" in str(item.get("detail", "")).lower()
            ]
            if upload:
                findings.append(
                    self.finding(
                        "The link offers a direct file download",
                        "The URL path points directly at an executable or archive. "
                        + "; ".join(str(item.get("detail")) for item in upload[:3])
                        + " A downloaded file should be treated as untrusted and detonated only in a "
                        "sandbox.",
                        Severity.HIGH,
                        0.85,
                        refs,
                        tags=["url", "download", "malware_risk"],
                        techniques=["T1204 User Execution"],
                    )
                )
        return findings
