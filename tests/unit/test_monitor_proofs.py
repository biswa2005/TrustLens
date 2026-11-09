import asyncio
import hashlib
import json
import secrets
from types import SimpleNamespace

import pytest
import fakeredis
import dns.exception
from fastapi.testclient import TestClient

from main import app
from links.services import analyser, redis_store
from links.services.monitor import ct
from links.services.monitor.ca import _authority_host
from links.services.monitor.generator import generate_candidates
from links.services.monitor import lookalike
from links.services.tls.distrust import validate_manifest
from scripts.import_urlhaus import import_file
from scripts import create_api_key


def test_candidate_generation_is_deterministic_capped_and_excludes_owned_domains():
    domain = "yourbank.com"
    own = ["yourbank.net", "brand-owned.example"]
    first = generate_candidates(domain, own, cap=40)
    second = generate_candidates(domain, own, cap=40)
    assert first == second
    assert len(first) <= 40
    assert domain not in first
    assert "yourbank.net" not in first
    assert all(candidate.isascii() and candidate == candidate.lower() for candidate in first)


def test_candidate_generator_enforces_hard_500_limit():
    label = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvxyz"
    candidates = generate_candidates(f"{label}.com", cap=10_000)
    assert len(candidates) == 500


@pytest.mark.parametrize(
    ("previous", "current", "expected"),
    [
        ({"resolves": False, "has_mx": False}, lookalike.ProbeState(True, True, "mx.test", 10),
         ("strong", "lookalike_resolving_with_signals")),
        ({"resolves": False, "has_mx": False}, lookalike.ProbeState(True, False, None, None),
         ("info", "lookalike_now_resolving")),
        ({"resolves": True, "has_mx": False}, lookalike.ProbeState(True, True, "mx.test", 90),
         ("moderate", "lookalike_new_mx_record")),
    ],
)
def test_lookalike_transition_severity(previous, current, expected):
    assert lookalike._transition(previous, current) == expected


@pytest.mark.parametrize("resolving_server", ["9.9.9.10", "1.1.1.1"])
def test_dual_dns_resolver_accepts_a_positive_answer_from_either_server(monkeypatch, resolving_server):
    async def fake_resolve(_domain, nameserver):
        await asyncio.sleep(0.001 if nameserver == resolving_server else 0.01)
        return nameserver == resolving_server

    monkeypatch.setattr(lookalike, "_resolver_has_address", fake_resolve)
    assert asyncio.run(lookalike._resolves("candidate.example")) is True


def test_dns_timeout_on_one_resolver_falls_back_to_the_other(monkeypatch):
    queried = []

    class FakeResolver:
        def __init__(self, **_): self.nameservers = []
        async def resolve(self, *_args, **_kwargs):
            nameserver = self.nameservers[0]
            queried.append(nameserver)
            if nameserver == "9.9.9.10":
                raise dns.exception.Timeout
            return SimpleNamespace(rrset=["203.0.113.7"])

    monkeypatch.setattr(lookalike.dns.asyncresolver, "Resolver", FakeResolver)
    assert asyncio.run(lookalike._resolves("fallback.example")) is True
    assert "9.9.9.10" in queried and "1.1.1.1" in queried


def test_ct_known_own_domains_are_excluded_and_apex_matches():
    watch = {
        "domain_ascii": "yourbank.com",
        "known_own_domains": ["yourbank.net"],
        "candidate_labels": set(),
    }
    assert ct._match_rule("www.yourbank.com", watch, set()) == "own_domain"
    assert ct._match_rule("www.yourbank.net", watch, set()) is None


@pytest.mark.parametrize(
    ("san", "expected"),
    [
        ("yourbank.com.evil.net", "brand_in_subdomain_cert"),
        ("yourbank-login.com", "combosquat_cert"),
    ],
)
def test_ct_matches_brand_in_subdomain_and_combosquat(san, expected):
    watch = {"domain_ascii": "yourbank.com", "known_own_domains": [], "candidate_labels": set()}
    assert ct._match_rule(san, watch, set()) == expected


def test_ct_short_brand_does_not_use_edit_distance_flooding():
    watch = {"domain_ascii": "sbi.com", "known_own_domains": [], "candidate_labels": set()}
    assert ct._match_rule("sbl.com", watch, set()) is None


def test_ct_stream_normalizes_direct_issuer_distinguished_name():
    payload = {"data": {"leaf_cert": {
        "subjectAltName": ["example.com"], "serial_number": "ab12",
        "issuer": {"O": "Example Certificate Authority Inc"},
    }}}
    assert ct._certificate_parts(payload)[1] == "example certificate authority"


def test_fast_screen_blocks_exact_active_urlhaus_match(monkeypatch, tmp_path):
    feed = tmp_path / "urlhaus.csv"
    feed.write_text(
        "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        "ioc-1,2026-01-01,https://mal.test/login,online,,malware,test,https://urlhaus.abuse.ch/,test\n",
        encoding="utf-8",
    )
    store = fakeredis.FakeRedis(decode_responses=True)
    import_file(feed, store)
    monkeypatch.setattr(redis_store, "client", lambda: store)
    result = asyncio.run(analyser.screen_url("https://mal.test/login", "full"))
    assert result["verdict"] == "block" and result["confidence"] == "high"


@pytest.mark.parametrize(
    ("url", "expected_verdict", "expected_confidence"),
    [
        ("https://paypa1-security-update.com/login", "warn", "medium"),
        ("https://login.example.com/verify", "no_local_signals", "low"),
        ("https://clean.example/", "no_local_signals", "low"),
    ],
)
def test_fast_screen_local_verdict_mapping(monkeypatch, url, expected_verdict, expected_confidence):
    store = fakeredis.FakeRedis(decode_responses=True)
    store.set("urlhaus:v1:active_generation", "empty")
    monkeypatch.setattr(redis_store, "client", lambda: store)
    result = asyncio.run(analyser.screen_url(url, "full"))
    assert result["verdict"] == expected_verdict
    assert result["confidence"] == expected_confidence


def test_fast_screen_redis_down_and_coverage_metadata(monkeypatch):
    def unavailable():
        raise ConnectionError("redis down")

    monkeypatch.setattr(redis_store, "client", unavailable)
    result = asyncio.run(analyser.screen_url("https://clean.example/", "full"))
    assert result["verdict"] == "no_local_signals"
    assert result["coverage"]["completed"] == 3
    assert result["coverage"]["planned"] == 10
    assert result["coverage"]["scope"] == "local_pre_screen"


def test_chrome_extension_origin_cors_preflight():
    origin = "chrome-extension://" + "a" * 32
    with TestClient(app) as client:
        response = client.options(
            "/api/v1/monitor/status",
            headers={"Origin": origin, "Access-Control-Request-Method": "GET",
                     "Access-Control-Request-Headers": "x-api-key"},
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin
    assert "x-api-key" in response.headers["access-control-allow-headers"].lower()


def test_monitoring_ip_limiter_runs_before_api_key_auth():
    client_ip = f"198.51.100.{secrets.randbelow(254) + 1}"
    with TestClient(app, client=(client_ip, 51000)) as client:
        for _ in range(120):
            assert client.get("/api/v1/monitor/status").status_code == 401
        assert client.get("/api/v1/monitor/status").status_code == 429


def test_api_key_creator_persists_only_hash(monkeypatch):
    captured = {}

    class FakeConnection:
        async def execute(self, query, params):
            captured["query"], captured["params"] = query, params

    class FakePool:
        class ConnectionContext:
            async def __aenter__(self): return FakeConnection()
            async def __aexit__(self, *_): return False
        def connection(self): return self.ConnectionContext()

    async def open_pool(): create_api_key.db.pool = FakePool()
    async def close_pool(): create_api_key.db.pool = None
    monkeypatch.setattr(create_api_key.db, "open_pool", open_pool)
    monkeypatch.setattr(create_api_key.db, "close_pool", close_pool)
    raw_key = asyncio.run(create_api_key.create("owner-test", "proof"))
    assert raw_key.startswith("tl_live_")
    assert captured["params"] == (hashlib.sha256(raw_key.encode()).hexdigest(), "owner-test", "proof")
    assert raw_key not in captured["query"] and raw_key not in repr(captured["params"])


def test_ct_prefilter_accepts_registered_punycode_candidate():
    candidate = "xn--yourbnk-9za.com"
    watch = {"domain_ascii": "yourbank.com", "candidate_labels": set()}
    assert ct._san_prefilter(candidate, watch, {candidate})


def test_ct_san_sanitization_caps_length_count_and_control_chars():
    values = ["safe.example\n", "x" * 254 + ".com", "bad\x00.example"] + [f"host{i}.example" for i in range(60)]
    cleaned = ct._sanitize_sans(values)
    assert len(cleaned) <= 50
    assert "safe.example" in cleaned
    assert "x" * 254 + ".com" not in cleaned
    assert all("\x00" not in name and len(name) <= 253 for name in cleaned)


def test_ca_authority_parser_handles_ipv6_and_domain_authorities():
    assert _authority_host("[2001:db8::1]:443") == "2001:db8::1"
    assert _authority_host("Example.COM:443") == "example.com"


def test_manifest_build_gate_rejects_placeholder_fingerprints(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({
        "version": "test",
        "records": [{
            "id": "placeholder", "classification": "compromised",
            "expected_cert_sha256": "<ENTER_FINGERPRINT>", "cert_file": "certs/placeholder.pem",
        }],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="placeholder"):
        validate_manifest(tmp_path)
