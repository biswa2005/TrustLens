"""Print chain-building and trust-anchor diagnostics for live TLS probes."""
from __future__ import annotations

import base64
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import certifi
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from fetcher.models import TLSProbeRequest, TLSProbeResponse
from links.models_tls import ChainStatus
from links.services.tls.path_validator import validate_chain
from links.services.tls.trust_store import get_trust_store


def _hex_extension(cert: x509.Certificate, extension_type: type) -> str:
    try:
        value = cert.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return "<absent>"
    return value.key_identifier.hex()


def _order_path(leaf: x509.Certificate, supplied: list[x509.Certificate]):
    """Mirror validate_chain's issuer-subject walk for diagnostic display."""
    path = [leaf]
    used = {leaf.fingerprint(hashes.SHA256())}
    while True:
        child = path[-1]
        parent = next((cert for cert in supplied
                       if cert.subject == child.issuer
                       and cert.fingerprint(hashes.SHA256()) not in used), None)
        if parent is None:
            return path
        path.append(parent)
        used.add(parent.fingerprint(hashes.SHA256()))


def _print_cert(index: int, cert: x509.Certificate) -> None:
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    print(f"  received[{index}]")
    print(f"    subject: {cert.subject.rfc4514_string()}")
    print(f"    issuer: {cert.issuer.rfc4514_string()}")
    print(f"    sha256: {cert.fingerprint(hashes.SHA256()).hex()}")
    print(f"    AKI: {_hex_extension(cert, x509.AuthorityKeyIdentifier)}")
    print(f"    SKI: {_hex_extension(cert, x509.SubjectKeyIdentifier)}")
    print(f"    is_ca: {is_ca}")
    print(f"    not_before: {cert.not_valid_before_utc.isoformat()}")
    print(f"    not_after: {cert.not_valid_after_utc.isoformat()}")


def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def diagnose(host: str, client: httpx.Client, token: str, base_url: str) -> None:
    print(f"\n=== {host} ===")
    response = client.post(
        f"{base_url.rstrip('/')}/probe/tls",
        json=TLSProbeRequest(host=host, timeout_budget=8.0).model_dump(mode="json"),
        headers={"X-Fetcher-Token": token},
    )
    response.raise_for_status()
    probe = TLSProbeResponse.model_validate(response.json())
    print(f"probe_ok: {probe.ok}; error_kind: {probe.error_kind}; detail: {probe.error_detail}")
    if not probe.ok or not probe.der_chain_base64:
        print(f"certifi_version: {certifi.__version__}")
        return

    certs = [x509.load_der_x509_certificate(base64.b64decode(item, validate=True))
             for item in probe.der_chain_base64]
    for index, cert in enumerate(certs):
        _print_cert(index, cert)

    path = _order_path(certs[0], certs[1:])
    store = get_trust_store()
    print("  _order_path:")
    for index, cert in enumerate(path):
        print(f"    path[{index}]: {cert.subject.rfc4514_string()} "
              f"[{cert.fingerprint(hashes.SHA256()).hex()}]")
    top = path[-1]
    top_fp = top.fingerprint(hashes.SHA256())
    print(f"  top_subject: {top.subject.rfc4514_string()}")
    print(f"  top_issuer: {top.issuer.rfc4514_string()}")
    print(f"  top_self_issued: {top.subject == top.issuer}")
    print(f"  top_fingerprint_in_trust_store: {top_fp in store.fingerprints}")
    print(f"  top_issuer_der_in_by_subject: {top.issuer.public_bytes() in store.by_subject}")
    top_spki = _spki(top)
    same_key_roots = [root.subject.rfc4514_string() for root in store.certs
                      if _spki(root) == top_spki]
    print(f"  top_same_spki_trust_store_subjects: {same_key_roots}")
    status, evidence = validate_chain(certs[0], certs[1:], host, datetime.now(timezone.utc), store)
    print(f"  chain_status: {status.value}; evidence: {evidence}")
    print(f"  certifi_version: {certifi.__version__}")


def main() -> None:
    load_dotenv()
    token = os.environ.get("FETCHER_TOKEN", "")
    if not token:
        raise SystemExit("FETCHER_TOKEN is missing from the environment and repository .env")
    base_url = os.environ.get("FETCHER_URL", "http://127.0.0.1:8001")
    with httpx.Client(timeout=15.0) as client:
        for host in ("example.com", "google.com", "github.com", "wikipedia.org"):
            try:
                diagnose(host, client, token, base_url)
            except Exception as exc:
                print(f"\n=== {host} ===\nprobe_failure: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
