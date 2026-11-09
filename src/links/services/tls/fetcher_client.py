from __future__ import annotations

import asyncio
import base64
import binascii

from links.services.tls._probe_models import TLSProbeResponse

MAX_BODY = 256 * 1024
MAX_CERTS, MAX_CERT_B64, MAX_CHAIN_DER, MAX_OCSP_B64 = 10, 22_000, 64 * 1024, 22_000


class BoundsError(ValueError):
    pass


class ProbeResponseTooLarge(BoundsError):
    pass


def decode_chain(resp: TLSProbeResponse) -> list[bytes]:
    if len(resp.der_chain_base64) > MAX_CERTS:
        raise BoundsError("too_many_certs")
    out, total = [], 0
    for encoded in resp.der_chain_base64:
        if len(encoded) > MAX_CERT_B64:
            raise BoundsError("cert_b64_too_long")
        der = base64.b64decode(encoded, validate=True)
        total += len(der)
        if len(der) > 16 * 1024 or total > MAX_CHAIN_DER:
            raise BoundsError("chain_too_large")
        out.append(der)
    return out


def decode_ocsp_staple(resp: TLSProbeResponse) -> bytes | None:
    encoded = resp.ocsp_staple_base64
    if encoded is None:
        return None
    if len(encoded) > MAX_OCSP_B64:
        raise BoundsError("ocsp_b64_too_long")
    return base64.b64decode(encoded, validate=True)


async def post_probe_tls(client, url: str, payload: dict, deadline_loop_time: float,
                         token: str) -> TLSProbeResponse:
    loop = asyncio.get_running_loop()
    async with asyncio.timeout_at(deadline_loop_time):
        body = bytearray()
        async with client.stream("POST", url, json=payload,
                                 headers={"X-Fetcher-Token": token}) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_BODY:
                    raise ProbeResponseTooLarge("probe_response_too_large")
    return TLSProbeResponse.model_validate_json(bytes(body))
