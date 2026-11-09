from datetime import datetime, timedelta, timezone
from pathlib import Path
import asyncio
import base64
import socket
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from links.models_tls import (CADistrustClassification as D, CertificateDetails,
                              ChainStatus as C, HostnameStatus as H,
                              RevocationStatus as R, TLSReport, TrustVerdict as V)
from links.services.authority import canonical_authority
from links.services.checks.normalise import normalize
from links.services.tls._probe_models import TLSProbeRequest, TLSProbeResponse
from links.services.tls.findings import EVIDENCE_GROUPS, RULES
from links.services.tls.fetcher_client import BoundsError, decode_chain, decode_ocsp_staple
from links.services.tls.hostname_verifier import verify_hostname
from links.services.tls.validity import excessive_lifetime, maximum_public_lifetime
from links.services.tls.verdict import compute_trust_verdict
from links.services.risk import GATING_CHECKS


def test_authority_canonical_cases():
    assert canonical_authority("Example.COM") == "example.com:443"
    assert canonical_authority("Example.COM", 8443) == "example.com:8443"
    assert canonical_authority("2001:db8::1") == "[2001:db8::1]:443"
    assert canonical_authority("bücher.example") == "xn--bcher-kva.example:443"
    assert canonical_authority("EXAMPLE.COM.") == "example.com:443"
    assert Path(__file__).parents[2].joinpath("src/links/services/authority.py").read_bytes() == Path(__file__).parents[2].joinpath("fetcher/authority.py").read_bytes()
    assert Path(__file__).parents[2].joinpath("src/links/services/tls/_probe_models.py").read_bytes() == Path(__file__).parents[2].joinpath("fetcher/models.py").read_bytes()


def test_probe_request_constraints():
    assert TLSProbeRequest(host="example.com", timeout_budget=7).port == 443
    with pytest.raises(Exception): TLSProbeRequest(host="example.com", port=8443, timeout_budget=7)
    with pytest.raises(Exception): TLSProbeRequest(host="example.com", timeout_budget=8.1)


def test_tls_is_11th_check_but_not_gating():
    from links.services.analyser import CHECK_IDS
    assert len(CHECK_IDS) == 11 and CHECK_IDS[-1] == "tls_certificate"
    assert len(GATING_CHECKS) == 10 and "tls_certificate" not in GATING_CHECKS


def test_finding_rules_have_exactly_one_evidence_group():
    for rule in RULES:
        assert sum(rule in group["rules"] for group in EVIDENCE_GROUPS.values()) == 1


@pytest.mark.parametrize("chain", list(C))
@pytest.mark.parametrize("hostname", list(H))
@pytest.mark.parametrize("distrust", list(D))
def test_valid_verdict_requires_positive_evidence(chain, hostname, distrust):
    verdict = compute_trust_verdict(chain=chain, hostname=hostname, revocation=R.NOT_EVALUATED,
                                    distrust=distrust, fired=set())
    assert (verdict == V.VALID) == (chain == C.VALID_TRUSTED and hostname == H.MATCHED and distrust == D.TRUSTED)


@pytest.mark.parametrize("fired,expected", [
    ({"broken_key_size"}, V.INVALID),
    ({"broken_hash"}, V.INVALID),
    ({"unsupported_algorithm"}, V.INCONCLUSIVE),
    ({"weak_key_size"}, V.CONFIGURATION_ISSUES),
    ({"legacy_hash"}, V.CONFIGURATION_ISSUES),
    ({"excessive_validity_period"}, V.CONFIGURATION_ISSUES),
])
def test_positive_chain_fired_rules_follow_truth_table(fired, expected):
    verdict = compute_trust_verdict(chain=C.VALID_TRUSTED, hostname=H.MATCHED,
                                    revocation=R.NOT_EVALUATED, distrust=D.TRUSTED, fired=fired)
    assert verdict == expected


def _leaf(sans, *, lifetime_days=200):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1))
        .not_valid_after(now+timedelta(days=lifetime_days)))
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(value) for value in sans]), critical=False)
    return builder.sign(key, hashes.SHA256())


def _ocsp_pair():
    from cryptography.x509.oid import ExtendedKeyUsageOID
    from cryptography.x509 import ocsp
    from cryptography.x509.ocsp import OCSPResponderEncoding
    issuer_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    issuer_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Test Issuer")])
    now=datetime.now(timezone.utc)
    issuer=(x509.CertificateBuilder().subject_name(issuer_name).issuer_name(issuer_name)
        .public_key(issuer_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(days=2)).not_valid_after(now+timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
        .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,None,None),critical=True)
        .sign(issuer_key,hashes.SHA256()))
    leaf_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leaf_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"example.com")])
    leaf=(x509.CertificateBuilder().subject_name(leaf_name).issuer_name(issuer_name)
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=20))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]),critical=False)
        .sign(issuer_key,hashes.SHA256()))
    return leaf,issuer,issuer_key,now


def _ocsp_response(leaf,issuer,issuer_key,now,status,signer_key=None,algorithm=None,next_update=True):
    from cryptography.x509 import ocsp
    from cryptography.x509.ocsp import OCSPResponderEncoding
    builder=(ocsp.OCSPResponseBuilder().add_response(cert=leaf,issuer=issuer,
        algorithm=algorithm or hashes.SHA256(),cert_status=status,this_update=now-timedelta(minutes=1),
        next_update=now+timedelta(hours=1) if next_update else None,
        revocation_time=now-timedelta(days=1) if status==ocsp.OCSPCertStatus.REVOKED else None,
        revocation_reason=x509.ReasonFlags.key_compromise if status==ocsp.OCSPCertStatus.REVOKED else None)
        .responder_id(OCSPResponderEncoding.NAME,issuer))
    return builder.sign(signer_key or issuer_key,hashes.SHA256()).public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER)


def test_wildcard_public_suffix_does_not_prevent_later_san_match():
    cert = _leaf(["*.co.uk", "example.com"])
    assert verify_hostname(cert, "example.com")[0] == H.MATCHED
    assert verify_hostname(_leaf(["*.co.uk"]), "foo.co.uk")[0] == H.PUBLIC_SUFFIX_WILDCARD_REJECTED


def test_public_lifetime_schedule_and_six_hour_overage():
    assert maximum_public_lifetime(datetime(2026, 11, 9, tzinfo=timezone.utc)) == 200
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(start+timedelta(days=200, hours=6))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
        .sign(key, hashes.SHA256()))
    assert excessive_lifetime(cert, chain_trusted=True)["limit_days"] == 200
    assert excessive_lifetime(cert, chain_trusted=False) is None


def test_tls_report_uses_frozen_tuple_collections():
    report = TLSReport(canonical_authority="example.com:443", target_kind="input", probe_ok=True,
                       limitations=("x",), certificates=(CertificateDetails(subject="a", issuer="b", serial_number="1", not_before=datetime.now(timezone.utc), not_after=datetime.now(timezone.utc)),))
    with pytest.raises(Exception): report.limitations += ("y",)
    with pytest.raises(Exception): report.certificates += ()


def test_failed_probe_report_retains_error_kind_reason_and_roundtrips():
    from links.models import Coverage, Report
    from links.models_tls import inconclusive_report
    failure=inconclusive_report("Example.COM.",443,"timeout","deadline", "input")
    assert failure.canonical_authority=="example.com:443"
    assert failure.probe_error_kind=="timeout" and failure.probe_error_detail=="deadline"
    parent=Report(input="https://example.com",coverage=Coverage(completed=0,planned=11,checks=[]),tls_reports={failure.canonical_authority:failure})
    decoded=Report.model_validate_json(parent.model_dump_json())
    assert decoded.tls_reports["example.com:443"].probe_error_kind=="timeout"


def test_distrust_loader_rejects_unverified_fingerprint(tmp_path):
    import json
    from cryptography.hazmat.primitives import serialization
    from links.services.tls.distrust import load_dataset
    _,issuer,_,_=_ocsp_pair()
    cert_dir=tmp_path/"certs"; cert_dir.mkdir()
    (cert_dir/"root.pem").write_bytes(issuer.public_bytes(serialization.Encoding.PEM))
    manifest={"version":"test-v1","records":[{"id":"wrong","entity":"example","classification":"compromised","source_url":"https://example.invalid","source_record":"test","retrieved_on":"2026-11-09","cert_file":"certs/root.pem","expected_cert_sha256":"00"*32,"scope":{"type":"all"}}]}
    (tmp_path/"manifest.json").write_text(json.dumps(manifest),encoding="utf-8")
    loaded=load_dataset(tmp_path)
    assert loaded.version=="test-v1+0-verified" and loaded.records==()


def test_shipped_distrust_record_matches_source_fingerprint():
    import json
    from links.services.tls.distrust import DATA, load_dataset
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    loaded = load_dataset()
    assert len(loaded.records) == 1
    assert loaded.version == f"{manifest['version']}+1-verified"
    assert loaded.records[0].entity == "eMudhra BV"
    assert loaded.records[0].fingerprint.hex() == manifest["records"][0]["expected_cert_sha256"].lower()


def test_decode_chain_rejects_bad_base64_and_per_certificate_size():
    from links.services.tls._probe_models import TLSProbeResponse
    with pytest.raises((BoundsError, ValueError)):
        decode_chain(TLSProbeResponse(host="x", port=443, ok=True, der_chain_base64=["%%%"] ))
    with pytest.raises(BoundsError):
        decode_chain(TLSProbeResponse(host="x", port=443, ok=True,
                                      der_chain_base64=[base64.b64encode(b"x"*16_385).decode()]))
    with pytest.raises(Exception):
        decode_chain(TLSProbeResponse(host="x", port=443, ok=True,
                                      der_chain_base64=[base64.b64encode(b"x").decode()]*11))


def test_decode_ocsp_rejects_invalid_and_oversized_values():
    from links.services.tls._probe_models import TLSProbeResponse
    with pytest.raises(ValueError):
        decode_ocsp_staple(TLSProbeResponse(host="x", port=443, ok=True, ocsp_staple_base64="!"))
    with pytest.raises(BoundsError):
        decode_ocsp_staple(TLSProbeResponse(host="x", port=443, ok=True,
                                            ocsp_staple_base64="A"*22_001))


def test_non_default_https_port_is_skipped_with_scope_limitation():
    from links.services.analyser import check_tls_certificate
    from links.services.registry import Context
    ctx=Context(raw_input="https://example.com:8443/",nurl=normalize("https://example.com:8443/"))
    result, findings=asyncio.run(check_tls_certificate(ctx))
    assert result.status=="skipped" and not findings
    assert "tls_non_default_port_not_analysed:8443" in ctx.values["limitations"]


def test_check_tls_certificate_http_input_is_skipped():
    from links.services.analyser import check_tls_certificate
    from links.services.registry import Context
    ctx=Context(raw_input="http://example.com/",nurl=normalize("http://example.com/"))
    result, findings=asyncio.run(check_tls_certificate(ctx))
    assert result.status=="skipped" and not findings and ctx.values["tls_reports"]=={}


def test_check_tls_certificate_all_probes_failed_is_unavailable(monkeypatch):
    import httpx
    from links.services.analyser import check_tls_certificate
    from links.services.registry import Context
    from links.services.tls import fetcher_client
    monkeypatch.setenv("FETCHER_URL","http://fetcher.test")
    monkeypatch.setenv("FETCHER_TOKEN","token")
    async def fail(*args, **kwargs):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(fetcher_client, "post_probe_tls", fail)
    ctx=Context(raw_input="https://example.com/",nurl=normalize("https://example.com/"))
    result, findings=asyncio.run(check_tls_certificate(ctx))
    assert result.status=="unavailable" and not any(f.severity!="info" for f in findings)
    report=ctx.values["tls_reports"]["example.com:443"]
    assert not report.probe_ok and report.probe_error_kind=="connection_refused"


def test_check_tls_certificate_one_success_is_ok(monkeypatch):
    import httpx
    from cryptography.hazmat.primitives import serialization
    from links.services.analyser import check_tls_certificate
    from links.services.registry import Context
    from links.services.tls import fetcher_client, trust_store
    from scripts.make_tls_fixtures import ec_key, issue_ca, issue_leaf, make_store
    root_key=ec_key(401)
    root=issue_ca("Check Root", root_key, serial=401)
    leaf=issue_leaf(root, root_key, serial=402)
    ok=TLSProbeResponse(host="example.test", port=443, ok=True,
        der_chain_base64=[base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
                          for c in (leaf, root)])
    async def mixed(client, url, payload, deadline, token):
        if payload["host"]=="example.test": return ok
        raise httpx.ConnectError("down")
    monkeypatch.setenv("FETCHER_URL","http://fetcher.test")
    monkeypatch.setenv("FETCHER_TOKEN","token")
    monkeypatch.setattr(fetcher_client, "post_probe_tls", mixed)
    monkeypatch.setattr(trust_store, "get_trust_store", lambda: make_store([root]))
    ctx=Context(raw_input="https://example.test/",nurl=normalize("https://example.test/"),
                fetch_result={"final_url":"https://two.test/"})
    result, findings=asyncio.run(check_tls_certificate(ctx))
    assert result.status=="ok"
    assert ctx.values["tls_reports"]["example.test:443"].trust_verdict==V.VALID
    assert not ctx.values["tls_reports"]["two.test:443"].probe_ok
    assert any("ConnectError" in text for text in ctx.values["limitations"])


@pytest.mark.parametrize("ocsp_status,expected",[("GOOD",R.GOOD),("REVOKED",R.REVOKED),("UNKNOWN",R.UNKNOWN)])
def test_authenticated_direct_issuer_ocsp_statuses(ocsp_status,expected):
    from cryptography.x509 import ocsp
    from links.services.tls.ocsp import evaluate_ocsp
    leaf,issuer,key,now=_ocsp_pair()
    der=_ocsp_response(leaf,issuer,key,now,getattr(ocsp.OCSPCertStatus,ocsp_status))
    status,rule,_=evaluate_ocsp(der,leaf,[issuer],now)
    assert status==expected
    assert rule==("ocsp_revoked" if expected==R.REVOKED else None)


def test_ocsp_requires_matching_issuer_and_authenticated_signature():
    from cryptography.x509 import ocsp
    from links.services.tls.ocsp import evaluate_ocsp
    leaf,issuer,key,now=_ocsp_pair()
    der=_ocsp_response(leaf,issuer,key,now,ocsp.OCSPCertStatus.REVOKED)
    parsed=ocsp.load_der_ocsp_response(der)
    tampered=bytearray(der); signature_offset=tampered.find(parsed.signature)
    assert signature_offset>=0
    tampered[signature_offset]^=1
    der=bytes(tampered)
    status,rule,evidence=evaluate_ocsp(der,leaf,[issuer],now)
    assert status==R.UNAVAILABLE and rule=="ocsp_unauthenticated" and evidence["reason"]=="signature_bad"
    _,wrong_issuer,_,_=_ocsp_pair()
    status,rule,_=evaluate_ocsp(_ocsp_response(leaf,issuer,key,now,ocsp.OCSPCertStatus.GOOD),leaf,[wrong_issuer],now)
    assert status==R.UNAVAILABLE and rule=="ocsp_malformed"


def test_ocsp_uses_cert_id_selected_sha256_and_rejects_stale_response():
    from cryptography.x509 import ocsp
    from links.services.tls.ocsp import evaluate_ocsp
    leaf,issuer,key,now=_ocsp_pair()
    status,_,_=evaluate_ocsp(_ocsp_response(leaf,issuer,key,now,ocsp.OCSPCertStatus.GOOD,algorithm=hashes.SHA256()),leaf,[issuer],now)
    assert status==R.GOOD
    stale=_ocsp_response(leaf,issuer,key,now-timedelta(days=8),ocsp.OCSPCertStatus.GOOD,next_update=False)
    status,rule,_=evaluate_ocsp(stale,leaf,[issuer],now)
    assert status==R.UNAVAILABLE and rule=="ocsp_stale"


@pytest.mark.parametrize("count,expected",[(0,"embedded_present_malformed"),(1,"embedded_present_parsed"),(2,"embedded_present_parsed")])
def test_embedded_sct_structure_states(count,expected):
    from types import SimpleNamespace
    from links.services.tls.ct import inspect_embedded_scts
    class FakeExtensions:
        def get_extension_for_class(self,_):
            return SimpleNamespace(value=[SimpleNamespace(version=SimpleNamespace(name="v1"),log_id=b"x",timestamp=datetime.now(timezone.utc)) for _ in range(count)])
    result,_=inspect_embedded_scts(SimpleNamespace(extensions=FakeExtensions()))
    assert result==expected


def test_embedded_sct_absence_and_malformed_fields():
    from types import SimpleNamespace
    from links.services.tls.ct import inspect_embedded_scts
    class NoSCT:
        def get_extension_for_class(self,_): raise x509.ExtensionNotFound("missing",x509.ObjectIdentifier("1.2.3"))
    assert inspect_embedded_scts(SimpleNamespace(extensions=NoSCT()))[0]=="not_present"
    class BadSCT:
        def get_extension_for_class(self,_):
            return SimpleNamespace(value=[SimpleNamespace(version=SimpleNamespace(name="v2"),log_id=b"x",timestamp=None)])
    assert inspect_embedded_scts(SimpleNamespace(extensions=BadSCT()))[0]=="embedded_present_malformed"


def test_memory_bio_handshake_enforces_received_byte_cap():
    from OpenSSL import SSL
    from fetcher.tls_probe import HANDSHAKE_BYTE_CAP, _Limit, perform_handshake

    class Reader:
        received = 0
        def do_handshake(self): raise SSL.WantReadError()
        def bio_read(self, _): raise SSL.WantReadError()
        def bio_write(self, data): self.received += len(data)

    async def run():
        client, peer = socket.socketpair()
        client.setblocking(False)
        conn = Reader()
        sender = asyncio.create_task(asyncio.to_thread(peer.sendall, b"x"*(HANDSHAKE_BYTE_CAP+50_000)))
        try:
            with pytest.raises(_Limit): await perform_handshake(client,conn)
            assert conn.received <= HANDSHAKE_BYTE_CAP + 16_384
        finally:
            client.close(); peer.close()
            await asyncio.gather(sender,return_exceptions=True)
    asyncio.run(run())


def test_memory_bio_handshake_with_local_tls_server(tmp_path):
    from OpenSSL import SSL
    from fetcher.tls_probe import _make_client_context, perform_handshake
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"localhost")])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1))
        .not_valid_after(now+timedelta(days=10))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),critical=False)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(key,hashes.SHA256()))
    cert_path=tmp_path/"server.pem"; key_path=tmp_path/"server.key"
    cert_path.write_bytes(cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
        __import__("cryptography").hazmat.primitives.serialization.PrivateFormat.PKCS8,
        __import__("cryptography").hazmat.primitives.serialization.NoEncryption()))

    async def run():
        server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(cert_path),str(key_path))
        async def handle(reader,writer):
            await reader.read(1); writer.close()
        server=await asyncio.start_server(handle,"127.0.0.1",0,ssl=server_context)
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM); sock.setblocking(False)
        conn=SSL.Connection(_make_client_context([]),None)
        conn.set_tlsext_host_name(b"localhost"); conn.set_connect_state()
        try:
            await asyncio.get_running_loop().sock_connect(sock,("127.0.0.1",server.sockets[0].getsockname()[1]))
            received=await perform_handshake(sock,conn)
            assert received>0 and conn.get_peer_certificate() is not None
        finally:
            sock.close(); server.close(); await server.wait_closed()
    asyncio.run(run())
