from app.hashing import canonicalize, compute_nonce, fingerprint


def test_canonical_is_deterministic():
    payload = {"b": 2, "a": 1}
    assert canonicalize(payload) == '{"a":1,"b":2}'


def test_fingerprint_length():
    payload = {"indicator": "example.com"}
    fp = fingerprint(payload, "abc123")
    assert len(fp) == 64


def test_nonce_changes_commitment():
    payload = {"indicator": "example.com"}
    n1 = compute_nonce()
    n2 = compute_nonce()
    # nonces differ with overwhelming probability
    assert n1 != n2
