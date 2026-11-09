from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import socket

from OpenSSL import SSL
from cryptography.hazmat.primitives import hashes, serialization

from fetcher.models import TLSProbeRequest, TLSProbeResponse
from fetcher.guard import Blocked, validate_and_resolve_async
from fetcher.authority import canonical_authority

log = logging.getLogger(__name__)
HANDSHAKE_BYTE_CAP = 128 * 1024
MAX_CERTS, MAX_CERT_DER, MAX_CHAIN_DER = 10, 16 * 1024, 64 * 1024


class _Limit(Exception):
    pass


def _make_client_context(ocsp_holder):
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)
    ctx.set_options(SSL.OP_NO_COMPRESSION)
    callback = getattr(ctx, "set_ocsp_client_callback", None)
    if callback:
        callback(lambda conn, data, _: (ocsp_holder.append(bytes(data)) if data else None) or True)
    return ctx


async def _flush(loop, sock, conn):
    while True:
        try: out = conn.bio_read(16384)
        except SSL.WantReadError: return
        await loop.sock_sendall(sock, out)


async def perform_handshake(sock, conn, cap: int = HANDSHAKE_BYTE_CAP) -> int:
    loop = asyncio.get_running_loop(); received = 0
    while True:
        try:
            conn.do_handshake(); await _flush(loop, sock, conn); return received
        except SSL.WantReadError:
            await _flush(loop, sock, conn)
            chunk = await loop.sock_recv(sock, 16384)
            if not chunk: raise ConnectionResetError("eof_in_handshake")
            received += len(chunk)
            if received > cap: raise _Limit(f"handshake_bytes>{cap}")
            conn.bio_write(chunk)


def _error(req, kind, detail):
    return TLSProbeResponse(host=req.host, port=req.port, ok=False, error_kind=kind,
                            error_detail=str(detail)[:100])


async def _resolve_target(target_host: str, port: int, timeout: float):
    return await validate_and_resolve_async(f"https://{target_host}/", timeout=timeout)


async def _connect(sock, address, loop):
    await loop.sock_connect(sock, address)


def _make_socket(family):
    return socket.socket(family, socket.SOCK_STREAM)


def _new_connection(ocsp_holder):
    return SSL.Connection(_make_client_context(ocsp_holder), None)


def _export_peer_chain(conn):
    leaf = conn.get_peer_certificate()
    peer = conn.get_peer_cert_chain() or []
    leaf_fp = leaf.to_cryptography().fingerprint(hashes.SHA256()) if leaf else None
    certs = [leaf] + [cert for cert in peer
                      if leaf_fp is None or cert.to_cryptography().fingerprint(hashes.SHA256()) != leaf_fp]
    der_chain = []
    seen = set()
    for cert in certs:
        if cert is None:
            continue
        der = cert.to_cryptography().public_bytes(serialization.Encoding.DER)
        if der in seen:
            continue
        seen.add(der)
        der_chain.append(der)
    return der_chain


def _build_success_response(req, der_chain, holder, conn):
    if len(der_chain) > MAX_CERTS or any(len(der) > MAX_CERT_DER for der in der_chain) or sum(map(len, der_chain)) > MAX_CHAIN_DER:
        return _error(req, "resource_limit", "certificate_chain_bounds")
    staple = holder[0] if holder and len(holder[0]) <= 16 * 1024 else None
    limits = [] if staple else ["ocsp_staple_unavailable"]
    return TLSProbeResponse(host=req.host, port=req.port, ok=True,
                            der_chain_base64=[base64.b64encode(der).decode("ascii") for der in der_chain],
                            ocsp_staple_base64=base64.b64encode(staple).decode("ascii") if staple else None,
                            limitations=limits, negotiated_protocol=conn.get_protocol_version_name(),
                            negotiated_cipher=conn.get_cipher_name())


async def run_tls_probe(req: TLSProbeRequest) -> TLSProbeResponse:
    loop = asyncio.get_running_loop(); sock = None; started = loop.time()
    try:
        async with asyncio.timeout_at(started + req.timeout_budget):
            authority = canonical_authority(req.host, req.port)
            target_host = authority.split("]:", 1)[0][1:] if authority.startswith("[") else authority.rsplit(":", 1)[0]
            remaining = started + req.timeout_budget - loop.time()
            if remaining <= 0: raise TimeoutError("deadline")
            parsed, port, ip = await _resolve_target(target_host, req.port, remaining)
            ip_obj = ipaddress.ip_address(ip)
            family = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
            sock = _make_socket(family); sock.setblocking(False)
            address = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
            await _connect(sock, address, loop)
            holder = []; conn = _new_connection(holder)
            try: ipaddress.ip_address(target_host.strip("[]")); is_ip = True
            except ValueError: is_ip = False
            if not is_ip: conn.set_tlsext_host_name(target_host.encode("ascii"))
            conn.set_alpn_protos([protocol.encode() for protocol in req.alpn_protocols])
            try: conn.request_ocsp()
            except AttributeError: pass
            conn.set_connect_state(); await perform_handshake(sock, conn)
            der_chain = _export_peer_chain(conn)
            return _build_success_response(req, der_chain, holder, conn)
    except TimeoutError: return _error(req, "timeout", "deadline")
    except Blocked as exc: return _error(req, "blocked", exc.reason)
    except PermissionError as exc: return _error(req, "blocked", str(exc))
    except _Limit as exc: return _error(req, "resource_limit", str(exc))
    except ConnectionRefusedError: return _error(req, "connection_refused", "refused")
    except SSL.Error: return _error(req, "handshake_failed", "tls_error")
    except OSError as exc: return _error(req, "connection_refused", type(exc).__name__)
    except Exception as exc:
        log.exception("TLS probe internal error")
        return _error(req, "internal_error", type(exc).__name__)
    finally:
        if sock is not None: sock.close()
