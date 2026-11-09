"""Deterministic certificate builders shared by offline path-validation tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

FIXED_NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


def ec_key(number: int):
    return ec.derive_private_key(number, ec.SECP256R1())


def ed448_key():
    return ed448.Ed448PrivateKey.from_private_bytes(bytes(range(57)))


def name(common_name: str, *, string_type=None) -> x509.Name:
    attribute = x509.NameAttribute(NameOID.COMMON_NAME, common_name, _type=string_type)
    return x509.Name([attribute])


def _sign(builder, key):
    algorithm = None if isinstance(key, ed448.Ed448PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm)


def issue_ca(
    common_name: str,
    key,
    *,
    serial: int,
    issuer: x509.Name | None = None,
    issuer_key=None,
    path_length: int | None = None,
    now: datetime = FIXED_NOW,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    subject: x509.Name | None = None,
) -> x509.Certificate:
    signer = issuer_key or key
    issuer_name = issuer or name(common_name)
    subject_name = subject or name(common_name)
    builder = (x509.CertificateBuilder().subject_name(subject_name).issuer_name(issuer_name)
        .public_key(key.public_key()).serial_number(serial)
        .not_valid_before(not_before or now - timedelta(days=30))
        .not_valid_after(not_after or now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False))
    return _sign(builder, signer)


def issue_leaf(
    issuer: x509.Certificate,
    issuer_key,
    *,
    serial: int,
    common_name: str = "example.test",
    now: datetime = FIXED_NOW,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    subject: x509.Name | None = None,
    signing_key=None,
) -> x509.Certificate:
    key = signing_key or ec_key(serial + 10_000)
    builder = (x509.CertificateBuilder().subject_name(subject or name(common_name))
        .issuer_name(issuer.subject).public_key(key.public_key()).serial_number(serial)
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
    return _sign(builder, issuer_key)


def issue_self_signed_leaf(
    *, serial: int, key=None, signer_key=None, now: datetime = FIXED_NOW,
) -> x509.Certificate:
    key = key or ec_key(serial + 20_000)
    signer = signer_key or key
    subject = name("example.test")
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(serial)
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    return _sign(builder, signer)


def make_store(roots: list[x509.Certificate]):
    """Build the public TrustStore interface around fixture certificates."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.verification import Store

    from links.services.tls.trust_store import TrustStore

    store = TrustStore.__new__(TrustStore)
    store.certs = tuple(roots)
    store.fingerprints = frozenset(cert.fingerprint(hashes.SHA256()) for cert in roots)
    store.by_subject = {}
    for cert in roots:
        store.by_subject.setdefault(cert.subject.public_bytes(), []).append(cert)
    store.store = Store(roots)
    store.version = "test-fixed"
    return store
