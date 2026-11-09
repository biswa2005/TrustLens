import asyncio
import time

import pytest

from fetcher import tls_probe
from fetcher.models import TLSProbeRequest


class RecordingSocket:
    def __init__(self, family, kind):
        self.family = family
        self.kind = kind
        self.closed = False
        self.blocking = None

    def setblocking(self, value):
        self.blocking = value

    def close(self):
        self.closed = True


class FakeConnection:
    def set_tlsext_host_name(self, _value):
        pass

    def set_alpn_protos(self, _value):
        pass

    def request_ocsp(self):
        pass

    def set_connect_state(self):
        pass


@pytest.mark.parametrize("failing_stage", ["resolve", "connect", "handshake", "chain_export", "response_build"])
def test_probe_contains_runtime_errors_and_closes_socket(monkeypatch, failing_stage):
    sockets = []

    def socket_factory(family):
        sock = RecordingSocket(family, "SOCK_STREAM")
        sockets.append(sock)
        return sock

    async def resolve(_host, _port, _timeout):
        if failing_stage == "resolve":
            raise RuntimeError("injected resolve failure")
        return None, 443, "93.184.216.34"

    async def connect(_sock, _address, _loop):
        if failing_stage == "connect":
            raise RuntimeError("injected connect failure")

    async def handshake(_sock, _conn):
        if failing_stage == "handshake":
            raise RuntimeError("injected handshake failure")
        return 0

    def export_chain(_conn):
        if failing_stage == "chain_export":
            raise RuntimeError("injected chain export failure")
        return [b"der-certificate"]

    def build_response(_req, _chain, _holder, _conn):
        if failing_stage == "response_build":
            raise RuntimeError("injected response build failure")
        raise AssertionError("the successful response builder should be the injected failure")

    monkeypatch.setattr(tls_probe, "_make_socket", socket_factory)
    monkeypatch.setattr(tls_probe, "_resolve_target", resolve)
    monkeypatch.setattr(tls_probe, "_connect", connect)
    monkeypatch.setattr(tls_probe, "perform_handshake", handshake)
    monkeypatch.setattr(tls_probe, "_new_connection", lambda _holder: FakeConnection())
    monkeypatch.setattr(tls_probe, "_export_peer_chain", export_chain)
    monkeypatch.setattr(tls_probe, "_build_success_response", build_response)

    response = asyncio.run(tls_probe.run_tls_probe(TLSProbeRequest(host="example.test", timeout_budget=2)))

    assert not response.ok
    assert response.error_kind == "internal_error"
    if failing_stage == "resolve":
        assert sockets == []
    else:
        assert len(sockets) == 1
        assert sockets[0].closed


def test_run_tls_probe_connects_only_to_validated_ip_and_resolves_once(monkeypatch):
    calls = []
    sockets = []

    def socket_factory(family):
        sock = RecordingSocket(family, "SOCK_STREAM")
        sockets.append(sock)
        return sock

    async def resolve(host, port, _timeout):
        calls.append(("resolve", host, port))
        return None, port, "93.184.216.34"

    async def connect(_sock, address, _loop):
        calls.append(("connect", address))
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(tls_probe, "_make_socket", socket_factory)
    monkeypatch.setattr(tls_probe, "_resolve_target", resolve)
    monkeypatch.setattr(tls_probe, "_connect", connect)

    response = asyncio.run(tls_probe.run_tls_probe(
        TLSProbeRequest(host="example.test", timeout_budget=2)))

    assert not response.ok and response.error_kind == "connection_refused"
    assert calls == [("resolve", "example.test", 443),
                     ("connect", ("93.184.216.34", 443))]
    assert len(sockets) == 1 and sockets[0].closed


def test_run_tls_probe_honours_absolute_deadline_without_minimum_floor(monkeypatch):
    async def stalled_resolve(_host, _port, _timeout):
        await asyncio.sleep(5)

    monkeypatch.setattr(tls_probe, "_resolve_target", stalled_resolve)

    started = time.perf_counter()
    response = asyncio.run(tls_probe.run_tls_probe(
        TLSProbeRequest(host="example.test", timeout_budget=0.6)))
    elapsed = time.perf_counter() - started

    assert not response.ok and response.error_kind == "timeout"
    assert elapsed < 1.2
