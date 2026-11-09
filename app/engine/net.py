"""Safe HTTP plumbing.

Two distinct paths exist:

* ``SafeHttpClient.api_*`` – requests to a fixed set of threat-intelligence
  endpoints (URLs are built by the server, never by user input).
* ``SafeHttpClient.fetch_untrusted`` – fetches a URL extracted from a suspect
  message/screenshot.  Every host is resolved and rejected if it points at a
  private, loopback, link-local or otherwise non-global address.  Redirects are
  followed manually so each hop is re-validated (SSRF protection).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.config import Settings
from app.engine.utils import is_public_ip, truncate

logger = logging.getLogger(__name__)

_UNSAFE_PORTS = {0, 21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 6379, 9200, 11211}


class NetworkDisabled(RuntimeError):
    pass


class UnsafeTarget(ValueError):
    pass


class SafeHttpClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._api: httpx.AsyncClient | None = None
        self._web: httpx.AsyncClient | None = None

    def _api_client(self) -> httpx.AsyncClient:
        if self._api is None or self._api.is_closed:
            self._api = httpx.AsyncClient(
                timeout=httpx.Timeout(self.settings.threat_intel_timeout_seconds, connect=5.0),
                headers={"User-Agent": self.settings.user_agent, "Accept": "application/json"},
                follow_redirects=True,
            )
        return self._api

    def _web_client(self) -> httpx.AsyncClient:
        if self._web is None or self._web.is_closed:
            self._web = httpx.AsyncClient(
                timeout=httpx.Timeout(self.settings.network_timeout_seconds, connect=5.0),
                headers={
                    "User-Agent": self.settings.user_agent,
                    "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
                    "Accept-Language": "en-US,en;q=0.8",
                },
                follow_redirects=False,
            )
        return self._web

    async def close(self) -> None:
        for client in (self._api, self._web):
            if client and not client.is_closed:
                await client.aclose()

    # ---------------------------------------------------------------- APIs
    async def api_get_json(self, url: str, **kwargs: Any) -> tuple[int, Any]:
        if not self.settings.allow_network:
            raise NetworkDisabled("Network access is disabled (ALLOW_NETWORK=false)")
        response = await self._api_client().get(url, **kwargs)
        try:
            data = response.json()
        except ValueError:
            data = {"raw": truncate(response.text, 1000)}
        return response.status_code, data

    async def api_post_json(self, url: str, **kwargs: Any) -> tuple[int, Any]:
        if not self.settings.allow_network:
            raise NetworkDisabled("Network access is disabled (ALLOW_NETWORK=false)")
        response = await self._api_client().post(url, **kwargs)
        try:
            data = response.json()
        except ValueError:
            data = {"raw": truncate(response.text, 1000)}
        return response.status_code, data

    async def api_head(self, url: str, **kwargs: Any) -> httpx.Response:
        if not self.settings.allow_network:
            raise NetworkDisabled("Network access is disabled (ALLOW_NETWORK=false)")
        return await self._api_client().head(url, **kwargs)

    # ----------------------------------------------------------- untrusted
    async def fetch_untrusted(
        self, url: str, *, max_bytes: int = 512_000, max_redirects: int | None = None
    ) -> dict[str, Any]:
        """Fetch a suspect page with manual, re-validated redirects."""

        if not self.settings.allow_network or not self.settings.enable_page_fetch:
            raise NetworkDisabled("Untrusted page fetching is disabled")

        chain: list[dict[str, Any]] = []
        current = url
        limit = self.settings.max_redirects if max_redirects is None else max_redirects
        for _hop in range(limit + 1):
            await self._validate_target(current)
            client = self._web_client()
            async with client.stream("GET", current) as response:
                location = response.headers.get("location")
                chain.append(
                    {
                        "url": current,
                        "status": response.status_code,
                        "location": location,
                        "content_type": response.headers.get("content-type", ""),
                    }
                )
                if response.status_code in {301, 302, 303, 307, 308} and location:
                    current = urljoin(current, location)
                    continue

                content_type = response.headers.get("content-type", "")
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        break
                    chunks.append(chunk)
                body = b"".join(chunks)
                encoding = response.encoding or "utf-8"
                try:
                    text = body.decode(encoding, errors="replace")
                except LookupError:
                    text = body.decode("utf-8", errors="replace")
                return {
                    "requested_url": url,
                    "final_url": current,
                    "status": response.status_code,
                    "content_type": content_type,
                    "chain": chain,
                    "body": text[:max_bytes],
                    "bytes": total,
                    "truncated": total > max_bytes,
                    "headers": {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower()
                        in {
                            "server",
                            "content-type",
                            "location",
                            "set-cookie",
                            "x-powered-by",
                            "strict-transport-security",
                            "content-security-policy",
                        }
                    },
                }
        raise UnsafeTarget(f"Too many redirects (>{limit})")

    async def _validate_target(self, url: str) -> None:
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            raise UnsafeTarget("Malformed URL") from exc
        if parts.scheme not in {"http", "https"}:
            raise UnsafeTarget(f"Scheme {parts.scheme!r} is not allowed")
        host = parts.hostname
        if not host:
            raise UnsafeTarget("URL has no host")
        if parts.username or parts.password:
            raise UnsafeTarget("URLs containing credentials are not fetched")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if port in _UNSAFE_PORTS:
            raise UnsafeTarget(f"Port {port} is not allowed")
        if port not in {80, 443, 8080, 8443}:
            raise UnsafeTarget(f"Non-standard port {port} is not fetched")

        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if not is_public_ip(str(literal)):
                raise UnsafeTarget("Private or reserved IP address")
            return

        addresses = await asyncio.to_thread(_resolve_host, host)
        if not addresses:
            raise UnsafeTarget("Host did not resolve")
        if any(not is_public_ip(address) for address in addresses):
            raise UnsafeTarget("Host resolves to a private or reserved address")


def _resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    values = []
    for info in infos:
        address = info[4][0]
        try:
            values.append(str(ipaddress.ip_address(address)))
        except ValueError:
            continue
    return sorted(set(values))
