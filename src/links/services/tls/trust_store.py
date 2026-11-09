from __future__ import annotations

import functools
import hashlib

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.verification import Store


class TrustStore:
    def __init__(self):
        pem = certifi.contents().encode()
        self.certs = tuple(x509.load_pem_x509_certificates(pem))
        self.fingerprints = frozenset(c.fingerprint(hashes.SHA256()) for c in self.certs)
        self.by_subject = {}
        for cert in self.certs:
            self.by_subject.setdefault(cert.subject.public_bytes(), []).append(cert)
        self.store = Store(list(self.certs))
        self.version = f"certifi-{certifi.__version__}-{hashlib.sha256(pem).hexdigest()[:16]}"


@functools.lru_cache(maxsize=1)
def get_trust_store() -> TrustStore:
    return TrustStore()
