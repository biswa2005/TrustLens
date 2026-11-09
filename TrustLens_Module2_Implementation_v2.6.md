# TrustLens Module 2: Implementation Guide v2.6

**Scope:** TLS Certificate and Web Trust Analysis (Module 2 only)
**Supersedes:** v2.5. The architecture is unchanged. This pass only corrects the items that could produce a wrong verdict or a safety hole, and adds coding-time instructions for everything else.
**Prerequisite:** Module 1 as described in `context.md` and `IMPLEMENTATION_CHECKLIST.md` (host-run FastAPI; Compose-managed fetcher, PostgreSQL, Redis).

> Code here is skeleton-level. Items marked **VERIFY** depend on library behaviour you must confirm against the *pinned* versions before relying on them. Nothing in this document has been run against your repository.

---

## 0. How this document ends the review loop

### 0.1 Gap admission rule (use this for every future review)

A finding is only admitted to the must-fix list if it meets at least one of these:

1. It can produce a wrong `VALID` verdict or a wrong Low Risk result.
2. It is an SSRF, resource-exhaustion or secret-leak hole.
3. It is a **failing test** or a failed real run.

Everything else goes into one of two places: section 15 (fix while coding, each item has a test) or section 17 (documented limitation). No new architecture.

### 0.2 Triage of the v2.5 gap review

| Gap-review item | Disposition | Where |
|---|---|---|
| P0.1 Module 1 integration | **Must fix** | §1, §2 |
| P0.2 Socket byte cap unproven | **Must fix** | §5 |
| P0.3 OCSP authentication wrong | **Must fix** | §10 |
| P0.4 Path validation classification | **Must fix** | §7 |
| P0.5 Wildcard early return | **Must fix** | §9 |
| P0.6 Absolute deadline | **Must fix** | §5, §12 |
| P0.7 Verdict falls through to VALID | **Must fix** | §11 |
| P0.8 Handler "never raises" claim | **Must fix** | §5 |
| P0.9 Decode boundary bounds | **Must fix** | §6 |
| 2.4 Distrust data unverified | **Must fix** | §13 |
| 3.1 Authority key contract | **Must fix** | §3 |
| 2.7 Failure info not preserved | **Must fix** | §4 |
| 2.1 SCT parsing | Fix while coding | F2 |
| 2.2 Lifetime `.days` truncation and scope | Fix while coding | F1 |
| 2.3 Weak crypto matrix | Fix while coding | F3 |
| 2.6 Custom HTTPS ports | Decide now, implement in code | F4 |
| 3.2 / 3.3 Request constraints, fetcher access control | Folded into §5 (small) | §5 |
| 3.4 Docker isolation | Fix while coding | F6 |
| Test corrections (IP pinning etc.) | Fix while coding | F7 |
| Immutable nested models, evidence-group registration | Fix while coding | F5, F8 |
| Delegated OCSP, active OCSP/CRL, CT log search, legacy protocol probing | Documented limitation | §17 |

---

## 1. Fixed decisions

| Decision | Status |
|---|---|
| `tls_certificate` is registered as an 11th check | Fixed |
| The **gating baseline stays at the original ten checks**. `Coverage.planned` displays 11, but confidence and Low-Risk gates count only `GATING_CHECKS` (§2) | Fixed |
| Check contract is `async def fn(ctx) -> tuple[CheckResult, list[Finding]]`. **No `CheckUnavailable` exception.** Unavailable and skipped outcomes are returned as `CheckResult(status=...)` | Fixed |
| Evidence groups are named to match the Module 1 hand-off: `tls_trust` (infrastructure) and `reputation_ca` (reputation) | Fixed |
| Only the fetcher makes outbound TLS connections for this check | Fixed |
| `/probe/tls` uses `VERIFY_NONE` with the SSRF guard as the compensating control. `/fetch` keeps `VERIFY_PEER` | Fixed |
| TLS bytes are read by **our own async code** and fed to OpenSSL through memory BIOs, so the cap counts what OpenSSL actually consumes | Fixed (§5) |
| One **absolute deadline** per check run. No minimum timeout may extend it | Fixed |
| A verdict is `VALID` only when positive evidence says so. Missing or unprocessable evidence is `INCONCLUSIVE`, never `VALID` | Fixed |
| Only **authenticated** OCSP staples affect trust. Direct-issuer signatures only for the MVP | Fixed |
| HTTPS on port 443 only for the MVP. Other ports are reported as a scope limitation, not as a certificate problem | Fixed (F4) |
| CT: embedded SCT presence and structural parse only | Fixed |
| Legacy protocol probing, active OCSP, CRL, CT log search are out of scope | Fixed |

**Decision for you (D-T1):** under Module 1's independence rules, a lone `compromised_ca` finding is one Strong group in one class, so the Module 1 `risk_class` is Suspicious, not High. The TLS report itself still shows verdict `compromised`. My lean: keep that, and show the TLS verdict prominently in the UI. Revisit only if testing shows it under-calls.

---

## 2. Module 1 reconciliation (do this first)

### 2.1 Verify, then record the answer

Open the real files and answer each line in a comment on the PR. If an answer disagrees with this document, the fix goes into Module 1, not into Module 2 code.

| # | Question | File |
|---|---|---|
| V1 | Does the runner expect `(CheckResult, list[Finding])` from checks? | `registry.py`, `analyser.py` |
| V2 | What kind of class is `Context` (dataclass, Pydantic, plain)? Add `values: dict` using that class's own idiom | `registry.py` |
| V3 | Is `ctx.fetch_result` a `FetchResult` model or a dict? | `models.py`, `redirect.py` |
| V4 | Required `Finding` fields (`source`, `timestamp`, `evidence_group`, `target`, `dampenable`) | `models.py` |
| V5 | Does `Finding` have `evidence_class`? If not, never pass it | `models.py` |
| V6 | What does the runner do with an exception from a check? (Expected: `status="error"`.) Module 2 never relies on this | `registry.py` |
| V7 | How does `EvidenceGroup` get built from findings, and where is the group-to-class map? | `risk.py` |
| V8 | Where are confidence and Low-Risk gates computed, and what literals do they use? | `risk.py` |
| V9 | Which tests assert exactly ten checks? | `tests/` |
| V10 | Fetcher routes, config, Dockerfile deps | `fetcher/`, `Dockerfile.fetcher` |

### 2.2 Changes to Module 1

```python
# src/links/services/analyser.py
CHECK_IDS = [..., "intel_urlhaus", "tls_certificate"]   # Coverage.planned = 11 (display only)
```

```python
# src/links/services/risk.py
GATING_CHECKS: frozenset[str] = frozenset({
    "normalise", "lexical", "brand_impersonation", "redirect_chain",
    "password_form", "dns", "rdap",
    "intel_safebrowsing", "intel_virustotal", "intel_urlhaus",
})  # exactly the original ten; tls_certificate is deliberately absent

def _ok_gating(coverage) -> set[str]:
    return {c.check_id for c in coverage.checks
            if c.check_id in GATING_CHECKS and c.status == "ok"}
```

Rewrite the existing `confidence()` and Low-Risk gate to call `_ok_gating()` and keep every existing threshold literal unchanged (`>= 8`, `>= 7`, and so on). `tls_certificate` can add findings and evidence groups, but it never moves a gate.

### 2.3 Evidence groups (register as full `EvidenceGroup` contracts, not just names)

| Group | Class | Member rules |
|---|---|---|
| `tls_trust` | infrastructure | `hostname_mismatch`, `cert_expired`, `cert_not_yet_valid`, `chain_incomplete`, `untrusted_root`, `self_signed`, `signature_invalid`, `path_constraint_violated`, `weak_key_size`, `broken_key_size`, `legacy_hash`, `broken_hash`, `excessive_validity_period`, `unsupported_algorithm`, `ocsp_revoked`, `ocsp_unauthenticated`, `ocsp_stale`, `ocsp_malformed`, `probe_error`, `resource_limit` |
| `reputation_ca` | reputation | `compromised_ca`, `distrusted_ca` |

Add a unit test that every rule ID emitted by `findings.py` appears in exactly one group's member list.

### 2.4 Tests to update

```python
def test_eleven_checks_registered_ten_gating():
    assert len(CHECKS) == 11
    assert "tls_certificate" not in GATING_CHECKS and len(GATING_CHECKS) == 10
```

All existing Module 1 risk tests must stay green without edits to their expected values.

---

## 3. One canonical authority format (Modules 1, 2 and 5)

Define it once, in `src/links/services/authority.py`, and import it everywhere (including the fetcher copy, see §4.1).

```python
import ipaddress, idna

def canonical_authority(host: str, port: int = 443) -> str:
    """lowercase IDNA/punycode host (or IP literal), IPv6 in brackets, ALWAYS with port."""
    h = host.strip().rstrip(".")
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
        return f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
    except ValueError:
        return f"{idna.encode(h.lower(), uts46=True).decode('ascii')}:{port}"
```

Module 5 looks up `ctx.values["tls_reports"][canonical_authority(final_host, final_port)]`. Tests: default port, explicit port, IPv6, IDN to punycode, uppercase, trailing dot.

---

## 4. Models

### 4.1 `src/links/models_tls.py`

Keep the v2.5 enums with these changes:

- `HostnameStatus` unchanged (keeps `INVALID_TARGET`).
- `CADistrustClassification.TRUSTED` now means **"no match in dataset vX"**. Document that in the docstring. `NOT_EVALUATED` means the dataset failed to load.
- `TLSProbeErrorKind` gains `INTERNAL_ERROR` and `UNSUPPORTED_SCOPE`.
- `CertificateDetails` and `TLSReport` use **tuples**, not lists, for nested collections (F5).

Additions to `TLSReport` (all required for reproducibility):

```python
class TLSReport(BaseModel):
    model_config = ConfigDict(frozen=True)
    canonical_authority: str
    target_kind: Literal["input", "final_destination"]
    probe_ok: bool                                   # False => an inconclusive placeholder
    probe_error_kind: str | None = None
    probe_error_detail: str | None = None            # sanitised, short
    limitations: tuple[str, ...] = ()
    trust_store_version: str | None = None           # sha256 of certifi bundle + certifi version
    distrust_dataset_version: str | None = None      # manifest version + record count
    # ... all v2.5 fields otherwise unchanged
```

`inconclusive_report(host, port, kind, reason, target_kind)` **must store** `reason` and `kind` (v2.5 dropped them). Every attempted authority produces a saved report, including failures.

The fetcher and host share the probe request/response models. Keep one copy in `fetcher/models.py`, a byte-identical copy at `src/links/services/tls/_probe_models.py`, and a test comparing SHA-256 of both files. Do the same for `authority.py`.

### 4.2 Report persistence

Add one **optional** field to Module 1's `Report`: `tls_reports: dict[str, TLSReport] | None = None`. Additive only. The orchestrator copies `ctx.values["tls_reports"]` into it so it is stored in the JSONB report and returned by `GET /api/v1/reports/{id}`.

---

## 5. Fetcher `/probe/tls`

### 5.1 Request model with constraints

```python
from typing import Annotated, Literal
from pydantic import BaseModel, Field, StringConstraints

Host = Annotated[str, StringConstraints(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9\.\-:\[\]]+$")]

class TLSProbeRequest(BaseModel):
    host: Host
    port: Literal[443] = 443
    timeout_budget: float = Field(gt=0.5, le=8.0)
    alpn_protocols: list[Literal["h2", "http/1.1"]] = Field(default=["h2", "http/1.1"], max_length=2)
```

The 8 s ceiling guarantees the probe fits inside the 10 s check timeout (§12). Reject, don't clamp.

### 5.2 Access control and concurrency (small, do it now)

- Host and fetcher share `FETCHER_TOKEN` (new env var). Host sends `X-Fetcher-Token`; the fetcher compares with `hmac.compare_digest` and returns 401 otherwise. This is the one secret the fetcher holds; note it in the README, because "fetcher has no secrets" is no longer literally true.
- `asyncio.Semaphore(4)` around `run_tls_probe`. If a slot is not free within 0.5 s, return 429.

### 5.3 Guard (reuse Module 1's, add reject-if-any)

Keep the v2.5 `resolve_and_verify_endpoint`. It already rejects the host if **any** resolved IP is non-global, and keeps the port-443 rule. Keep the docstring explaining why "first good IP" is forbidden. It must call the shared `canonical_authority()`.

### 5.4 Why the v2.5 socket cap does not work, and the fix

OpenSSL reads from a file descriptor in C, so a Python `socket.recv` override is never called. Instead, use **memory BIOs**: our code does all network I/O with asyncio and hands bytes to OpenSSL. The cap then counts exactly what OpenSSL sees. This also removes the blocking `connect()` and `select()` from the event loop.

```python
# fetcher/tls_probe.py
import asyncio, base64, socket, time
from OpenSSL import SSL
from cryptography.hazmat.primitives import serialization

HANDSHAKE_BYTE_CAP = 128 * 1024
MAX_CERTS, MAX_CERT_DER, MAX_CHAIN_DER = 10, 16 * 1024, 64 * 1024

class _Limit(Exception): ...

def _make_client_context(ocsp_holder: list) -> SSL.Context:
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)   # scoped to /probe/tls; SSRF guard is the control
    ctx.set_options(SSL.OP_NO_COMPRESSION)
    def _ocsp_cb(conn, data, _):                        # VERIFY: set_ocsp_client_callback in pinned pyOpenSSL
        if data:
            ocsp_holder.append(bytes(data))
        return True
    ctx.set_ocsp_client_callback(_ocsp_cb)
    return ctx

async def _flush(loop, sock, conn):
    while True:
        try:
            out = conn.bio_read(16384)
        except SSL.WantReadError:
            return
        await loop.sock_sendall(sock, out)

async def perform_handshake(sock, conn, cap: int = HANDSHAKE_BYTE_CAP) -> int:
    """Drive the handshake over an already-connected NON-BLOCKING socket. Returns bytes received.
    Separate from the guard so it can be tested directly against local servers."""
    loop = asyncio.get_running_loop()
    received = 0
    while True:
        try:
            conn.do_handshake()
            await _flush(loop, sock, conn)
            return received
        except SSL.WantReadError:
            await _flush(loop, sock, conn)
            chunk = await loop.sock_recv(sock, 16384)
            if not chunk:
                raise ConnectionResetError("eof_in_handshake")
            received += len(chunk)
            if received > cap:
                raise _Limit(f"handshake_bytes>{cap}")
            conn.bio_write(chunk)
```

### 5.5 Probe lifecycle with one absolute deadline and guaranteed cleanup

```python
async def run_tls_probe(req, *, resolve=resolve_and_verify_endpoint) -> TLSProbeResponse:
    loop = asyncio.get_running_loop()
    started = loop.time()
    sock = None
    try:
        async with asyncio.timeout_at(started + req.timeout_budget):    # ONE deadline: DNS, connect, handshake
            ep = await resolve(req.host, req.port)                      # guard (injectable for tests only via parameter)
            sock = socket.socket(socket.AF_INET6 if ep.is_ipv6 else socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            await loop.sock_connect(sock, (ep.ip_address, ep.port))     # pinned IP, never re-resolved
            holder: list[bytes] = []
            conn = SSL.Connection(_make_client_context(holder), None)   # None => memory BIOs
            if not ep.is_ip_literal:
                conn.set_tlsext_host_name(ep.target_host.encode("ascii"))
            conn.set_alpn_protos([p.encode() for p in req.alpn_protocols])
            try:
                conn.request_ocsp()                                     # VERIFY availability
            except AttributeError:
                pass
            conn.set_connect_state()
            await perform_handshake(sock, conn)
            return _build_ok_response(req, ep, conn, holder, started, loop)
    except TimeoutError:
        return _err(req, "timeout", "deadline")
    except PermissionError as e:
        return _err(req, "blocked", str(e)[:80])
    except _Limit as e:
        return _err(req, "resource_limit", str(e))
    except ConnectionRefusedError:
        return _err(req, "connection_refused", "refused")
    except SSL.Error:
        return _err(req, "handshake_failed", "tls_error")
    except (OSError, ValueError):
        return _err(req, "dns_failure" if _is_dns(req) else "connection_refused", "network")
    except Exception as e:                                              # unexpected: sanitise, never leak
        logger.exception("probe internal error")
        return _err(req, "internal_error", type(e).__name__)
    finally:
        if sock is not None:
            sock.close()
```

`_build_ok_response` extracts the chain and enforces the size bounds **before** returning:

- Leaf from `conn.get_peer_certificate(as_cryptography=True)`; remaining from `conn.get_peer_cert_chain(as_cryptography=True)`, de-duplicated by DER (**VERIFY** the `as_cryptography` argument in the pinned pyOpenSSL; otherwise call `.to_cryptography()`).
- Reject with `resource_limit` if more than `MAX_CERTS`, any DER over `MAX_CERT_DER`, or total over `MAX_CHAIN_DER`.
- Staple: `holder[0]` if present and at most 16 KiB, otherwise `None` plus `limitations.append("ocsp_staple_unavailable")`.

The route:

```python
@app.post("/probe/tls", response_model=TLSProbeResponse)
async def probe_tls(req: TLSProbeRequest, x_fetcher_token: str = Header(...)):
    if not hmac.compare_digest(x_fetcher_token, settings.FETCHER_TOKEN):
        raise HTTPException(401)
    try:
        await asyncio.wait_for(_sem.acquire(), 0.5)
    except TimeoutError:
        raise HTTPException(429)
    try:
        return await run_tls_probe(req)
    finally:
        _sem.release()
```

`run_tls_probe` itself never raises (the final `except Exception` guarantees it). The only exceptions that leave the route are the intentional 401 and 429.

---

## 6. Host-side client and decode boundary

```python
# src/links/services/tls/fetcher_client.py
MAX_BODY = 256 * 1024
async def post_probe_tls(client, url, payload, deadline_loop_time) -> TLSProbeResponse:
    loop = asyncio.get_running_loop()
    async with asyncio.timeout_at(deadline_loop_time):
        body = bytearray()
        async with client.stream("POST", url, json=payload, headers={"X-Fetcher-Token": settings.FETCHER_TOKEN}) as r:
            r.raise_for_status()
            async for chunk in r.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_BODY:
                    raise ProbeResponseTooLarge()
    return TLSProbeResponse.model_validate_json(bytes(body))
```

The decoder treats the fetcher response as untrusted data crossing a service boundary:

```python
MAX_CERTS, MAX_CERT_B64, MAX_CHAIN_DER, MAX_OCSP_B64 = 10, 22_000, 64 * 1024, 22_000

def decode_chain(resp) -> list[bytes]:
    if len(resp.der_chain_base64) > MAX_CERTS:
        raise BoundsError("too_many_certs")
    out, total = [], 0
    for s in resp.der_chain_base64:
        if len(s) > MAX_CERT_B64:
            raise BoundsError("cert_b64_too_long")
        der = base64.b64decode(s, validate=True)
        total += len(der)
        if total > MAX_CHAIN_DER:
            raise BoundsError("chain_too_large")
        out.append(der)
    return out
```

Apply the same pattern to `ocsp_staple_base64` (`MAX_OCSP_B64`, `validate=True`). Any `BoundsError`, `binascii.Error` or `ValueError` becomes an inconclusive report with `chain_status=RESOURCE_LIMIT_EXCEEDED` or `INCONCLUSIVE`, plus a `resource_limit` or `probe_error` finding.

---

## 7. Path validation (rewritten)

Principles: use **one `now`** everywhere, classify deterministically from checked facts, never map an unclassified failure to `UNTRUSTED_ROOT`, and never touch private `Store` internals.

### 7.1 Trust store wrapper

```python
# src/links/services/tls/trust_store.py
import functools, hashlib, certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.verification import Store

class TrustStore:
    def __init__(self):
        pem = certifi.contents().encode()
        self.certs = x509.load_pem_x509_certificates(pem)                  # VERIFY: exists in cryptography>=39
        self.by_subject: dict[bytes, list[x509.Certificate]] = {}
        self.fingerprints: set[bytes] = set()
        for c in self.certs:
            self.by_subject.setdefault(c.subject.public_bytes(), []).append(c)
            self.fingerprints.add(c.fingerprint(hashes.SHA256()))
        self.store = Store(self.certs)
        self.version = f"certifi-{certifi.__version__}-{hashlib.sha256(pem).hexdigest()[:16]}"

@functools.lru_cache(maxsize=1)
def get_trust_store() -> TrustStore:
    return TrustStore()
```

### 7.2 Algorithm

```python
def validate_chain(leaf, supplied, host, now, ts: TrustStore):
    path = _order_path(leaf, supplied)          # follow issuer->subject links among supplied certs; extras ignored
    # 1. validity of EVERY certificate, with the single `now`
    for i, c in enumerate(path):
        if now < c.not_valid_before_utc: return NOT_YET_VALID, {"index": i}
        if now > c.not_valid_after_utc:  return EXPIRED,       {"index": i}
    # 2. adjacent signatures
    for i, (child, parent) in enumerate(zip(path, path[1:])):
        r = verify_certificate_signature(child, parent)
        if r == "invalid":     return SIGNATURE_INVALID, {"index": i}
        if r == "unsupported": return INCONCLUSIVE, {"reason": "unsupported_algorithm", "index": i}
    # 3. top-of-path self-issuance (a name match is NOT proof of self-signing)
    top = path[-1]
    self_issued = top.subject == top.issuer
    if self_issued:
        r = verify_certificate_signature(top, top)
        if r == "invalid":     return SIGNATURE_INVALID, {"reason": "self_issued_not_self_signed"}
        if r == "unsupported": return INCONCLUSIVE, {"reason": "unsupported_algorithm"}
    # 4. CA constraints. cas[k] has exactly k CA certificates below it in the path
    cas = path[1:]
    for k, ca in enumerate(cas):
        try:
            bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            return PATH_CONSTRAINT_VIOLATED, {"index": k + 1, "reason": "no_basic_constraints"}
        if not bc.ca:
            return PATH_CONSTRAINT_VIOLATED, {"index": k + 1, "reason": "not_a_ca"}
        if bc.path_length is not None and bc.path_length < k:
            return PATH_CONSTRAINT_VIOLATED, {"index": k + 1, "reason": "path_length_exceeded"}
        # if KeyUsage present it must allow keyCertSign
        try:
            ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
            if not ku.key_cert_sign:
                return PATH_CONSTRAINT_VIOLATED, {"index": k + 1, "reason": "no_key_cert_sign"}
        except x509.ExtensionNotFound:
            pass
    # 5. anchor determination
    top_fp = top.fingerprint(hashes.SHA256())
    anchored = top_fp in ts.fingerprints or (not self_issued and top.issuer.public_bytes() in ts.by_subject)
    if not anchored:
        if self_issued:
            return (SELF_SIGNED if len(path) == 1 else UNTRUSTED_ROOT), {"top": top.subject.rfc4514_string()}
        return INCOMPLETE_CHAIN, {"missing_issuer": top.issuer.rfc4514_string()}
    # 6. full policy verification with the SAME `now`
    try:
        v = (PolicyBuilder().store(ts.store).time(now)                 # VERIFY: time() accepts an aware datetime
             .build_server_verifier(_service_identity(host)))
        v.verify(leaf, [c for c in path[1:] if c.fingerprint(hashes.SHA256()) not in ts.fingerprints])
    except VerificationError as e:
        return INCONCLUSIVE, {"reason": "policy_verification_failed", "class": type(e).__name__}
    return VALID_TRUSTED, {"reason": "ok"}
```

Notes for implementation:

- `INCONCLUSIVE` is the honest answer when the anchor exists, every deterministic check passed, and the library's policy still rejects. The detail goes into evidence for you to investigate.
- `_order_path` is about 15 lines: start at the leaf, repeatedly pick a supplied cert whose subject equals the current cert's issuer, stop when none is found or on a repeat. Certificates not used are recorded in `limitations`.
- `verify_certificate_signature` returns a tri-state string (`"valid"`, `"invalid"`, `"unsupported"`, §7.3).

### 7.3 Signature verifier (tri-state)

Keep the v2.5 RSA (PKCS#1 v1.5 and PSS via `signature_algorithm_parameters`), ECDSA and Ed25519 paths. Change the return type: `"valid"` on success, `"invalid"` on `InvalidSignature`, and `"unsupported"` for DSA, Ed448, any `UnsupportedAlgorithm`, or an unknown key type. `unsupported` must never be treated as valid or silently skipped. It becomes an `unsupported_algorithm` finding and verdict `INCONCLUSIVE`.

---

## 8. Probe orchestration (`probe_and_analyze`)

Keep the v2.5 flow, with these corrections:

1. `now = datetime.now(timezone.utc)` once, passed to every function.
2. Decode with `decode_chain()` (§6). On `BoundsError`, return an inconclusive report with the stored reason.
3. Every failure path returns a saved `TLSReport` with `probe_ok=False`, `probe_error_kind`, and `limitations`.
4. Fill `trust_store_version` and `distrust_dataset_version` on every report, including failures where known.
5. `transport_eligibility` is computed before constructing the frozen report, exactly as in v2.5, and is `False` for any `probe_ok=False` report.

---

## 9. Hostname verification (wildcard fix)

Collect, don't return early:

```python
rejected: list[str] = []
for raw in dns_sans:
    san = raw.strip().lower()
    if san.startswith("*."):
        base = san[2:]
        if not base or "*" in base:
            continue
        reg = _EXTRACTOR(base)
        if reg.domain == "" and reg.suffix:          # *.co.uk style
            rejected.append(san)
            continue                                  # keep checking the remaining SANs
        ...                                           # single-label match as in v2.5; return MATCHED on hit
    elif "*" in san:
        continue
    else:
        ...                                           # exact IDNA match; return MATCHED on hit
# after the loop, no SAN matched:
if rejected:
    return HostnameStatus.PUBLIC_SUFFIX_WILDCARD_REJECTED, {**evidence, "rejected": rejected}
return HostnameStatus.MISMATCHED, {**evidence, "sans": dns_sans}
```

Required test: a certificate with SANs `*.co.uk` then `example.com` must return `MATCHED` for `example.com`, and `PUBLIC_SUFFIX_WILDCARD_REJECTED` for `foo.co.uk` when nothing else matches. Also drop the `publicsuffixlist` dependency (v2.5 already said to, since `tldextract` carries the snapshot).

---

## 10. OCSP (authenticated staples, rewritten)

`cryptography`'s OCSP response object has **no `verify()`**. Verify the signature manually. Only direct-issuer responses count as authenticated. Anything else is "unauthenticated" and informational.

```python
# src/links/services/tls/ocsp.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519
from cryptography.x509 import ocsp

SKEW = timedelta(minutes=5)
MAX_AGE_NO_NEXT_UPDATE = timedelta(days=7)

def _key_bits(pub) -> bytes | None:
    """Contents of the subjectPublicKey BIT STRING (what OCSP issuerKeyHash covers), NOT the full SPKI."""
    if isinstance(pub, rsa.RSAPublicKey):
        return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return None

def _digest(alg, data: bytes) -> bytes:
    h = hashes.Hash(alg); h.update(data); return h.finalize()

def _certid_matches(resp, leaf, issuer) -> bool:
    alg = resp.hash_algorithm                                    # the algorithm the CertID actually uses
    kb = _key_bits(issuer.public_key())
    return (kb is not None
            and resp.serial_number == leaf.serial_number
            and resp.issuer_name_hash == _digest(alg, issuer.subject.public_bytes())
            and resp.issuer_key_hash == _digest(alg, kb))

def _responder_is_issuer(resp, issuer) -> bool:
    if resp.responder_name is not None:
        return resp.responder_name == issuer.subject
    if resp.responder_key_hash is not None:
        kb = _key_bits(issuer.public_key())
        return kb is not None and resp.responder_key_hash == _digest(hashes.SHA1(), kb)  # SHA-1 per RFC 6960 byKey
    return False

def _signature_ok(resp, issuer_pub) -> str:           # "ok" | "bad" | "unsupported"
    h, sig, tbs = resp.signature_hash_algorithm, resp.signature, resp.tbs_response_bytes
    try:
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            pad = getattr(resp, "signature_algorithm_parameters", None) or padding.PKCS1v15()   # VERIFY attr (cryptography>=43)
            issuer_pub.verify(sig, tbs, pad, h)
        elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(sig, tbs, ec.ECDSA(h))
        elif isinstance(issuer_pub, ed25519.Ed25519PublicKey):
            issuer_pub.verify(sig, tbs)
        else:
            return "unsupported"
        return "ok"
    except InvalidSignature:
        return "bad"
    except (UnsupportedAlgorithm, ValueError, TypeError):
        return "unsupported"
```

`evaluate_ocsp` order:

1. No staple: `NOT_EVALUATED`, no finding.
2. Decode with bounds, then `load_der_ocsp_response`. A failure: `UNAVAILABLE` + `ocsp_malformed` (info).
3. Response status not SUCCESSFUL: `UNAVAILABLE`.
4. Issuer = the chain element whose subject equals `leaf.issuer`, not blindly `intermediates[0]`. None found: `UNAVAILABLE`.
5. `_certid_matches` false: `UNAVAILABLE` + `ocsp_malformed`.
6. Freshness (use the `*_utc` accessors, **VERIFY** names): reject `produced_at` or `this_update` later than `now + SKEW`. If `next_update` exists, reject when earlier than `now - SKEW`. If it is absent, reject when `now - this_update > MAX_AGE_NO_NEXT_UPDATE`. Stale: `UNAVAILABLE` + `ocsp_stale`.
7. Authenticated = `_responder_is_issuer` **and** `_signature_ok == "ok"` **and** the response embeds no extra `certificates` (delegated responders are out of scope).
8. Authenticated GOOD, REVOKED or UNKNOWN map to the matching `RevocationStatus`. Authenticated REVOKED also emits `ocsp_revoked` (Strong). Unauthenticated anything maps to `UNAVAILABLE` plus `ocsp_unauthenticated` (info). An unauthenticated REVOKED must **not** change the verdict.

Until the tests in §16 for tampered signature, wrong hash algorithm and wrong issuer all pass, do not let OCSP influence `trust_verdict`. A one-line feature flag `OCSP_AFFECTS_VERDICT=false` is acceptable until then.

---

## 11. Trust verdict (complete truth table)

`VALID` is reachable only through the last row. Everything unexpected falls to `INCONCLUSIVE`.

| # | Condition (first match wins) | Verdict |
|---|---|---|
| 1 | distrust == COMPROMISED | `compromised` |
| 2 | distrust == DISTRUSTED | `distrusted` |
| 3 | revocation == REVOKED (authenticated only) | `invalid` |
| 4 | chain in {NOT_YET_VALID, EXPIRED, SIGNATURE_INVALID, PATH_CONSTRAINT_VIOLATED} | `invalid` |
| 5 | hostname in {MISMATCHED, MISSING_SAN_MISMATCHED, MISSING_SAN_IP_MISMATCHED, IP_MISMATCH, PUBLIC_SUFFIX_WILDCARD_REJECTED} | `invalid` |
| 6 | any broken-crypto finding (`broken_key_size`, `broken_hash`) | `invalid` |
| 7 | chain in {SELF_SIGNED, UNTRUSTED_ROOT} | `untrusted` |
| 8 | chain == INCOMPLETE_CHAIN | `incomplete` |
| 9 | chain in {INCONCLUSIVE, RESOURCE_LIMIT_EXCEEDED} or finding `unsupported_algorithm` | `inconclusive` |
| 10 | hostname in {INVALID_TARGET, NOT_EVALUATED} | `inconclusive` |
| 11 | distrust == NOT_EVALUATED | `inconclusive` |
| 12 | chain != VALID_TRUSTED or hostname != MATCHED (defensive catch-all) | `inconclusive` |
| 13 | any weak-config finding (`weak_key_size`, `legacy_hash`, `excessive_validity_period`) | `configuration_issues` |
| 14 | otherwise | `valid` |

```python
def compute_trust_verdict(*, chain, hostname, revocation, distrust, fired: set[str]) -> TrustVerdict:
    if distrust == COMPROMISED: return COMPROMISED_V
    if distrust == DISTRUSTED:  return DISTRUSTED_V
    if revocation == RevocationStatus.REVOKED: return INVALID
    if chain in _INVALID_CHAIN: return INVALID
    if hostname in _BAD_HOSTNAME: return INVALID
    if fired & _BROKEN: return INVALID
    if chain in (SELF_SIGNED, UNTRUSTED_ROOT): return UNTRUSTED
    if chain == INCOMPLETE_CHAIN: return INCOMPLETE
    if chain in (INCONCLUSIVE, RESOURCE_LIMIT_EXCEEDED) or "unsupported_algorithm" in fired: return INCONCLUSIVE
    if hostname in (INVALID_TARGET, NOT_EVALUATED): return INCONCLUSIVE
    if distrust == NOT_EVALUATED: return INCONCLUSIVE
    if chain != VALID_TRUSTED or hostname != MATCHED: return INCONCLUSIVE
    if fired & _WEAK: return CONFIGURATION_ISSUES
    return VALID
```

Test: a parametrised test that enumerates the full product of `ChainStatus x HostnameStatus x CADistrustClassification` (small enough) and asserts `VALID` is returned only when chain is `VALID_TRUSTED`, hostname is `MATCHED`, distrust is `TRUSTED`, and no broken/unsupported finding fired.

---

## 12. The check, deadline and statuses

```python
@register_check("tls_certificate", depends_on=("normalise",), timeout=10.0, needs_network=True)
async def check_tls_certificate(ctx):
    started = time.monotonic()
    if ctx.nurl is None:
        return _res(started, "unavailable", "normalise did not complete"), []
    if ctx.nurl.scheme != "https":
        ctx.values["tls_reports"] = {}
        return _res(started, "skipped", "input is not HTTPS; no TLS analysis performed"), []

    authorities = _resolve_authorities(ctx)         # input + final destination, https and port 443 only (F4)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + settings.TLS_PROBE_TIMEOUT_BUDGET     # config validator: <= 8.0
    async with httpx.AsyncClient(timeout=None) as client:
        raw = await asyncio.gather(
            *[probe_and_analyze(client, settings.FETCHER_URL, h, p, k, deadline) for h, p, k in authorities],
            return_exceptions=True,
        )
    ...
```

Rules:

- `probe_and_analyze` wraps each fetcher call in `asyncio.timeout_at(deadline)`. There are **no `max(0.2, ...)` or `max(0.5, ...)` floors anywhere**. If the deadline has passed, return an inconclusive report immediately.
- `TLS_PROBE_TIMEOUT_BUDGET` (default 7.0) must be at most 8.0 (validator in `config.py`), which leaves headroom inside the 10 s check timeout.
- Aggregate status: `skipped` for HTTP input; `unavailable` when **all** attempted probes failed (`probe_ok=False`); `ok` when at least one produced real evidence, with failures listed in `limitations`; `ok` with empty reports only when no authority was eligible, with the reason recorded.
- A report is saved for **every** attempted authority (including failed ones), keyed by `canonical_authority()`.
- Copy limitations into `ctx.values["limitations"]` and into each report.
- When `chain_status == UNTRUSTED_ROOT` and no distrust record matched, append the eMudhra limitation text (§17).

---

## 13. CA distrust intelligence (verified or absent)

**The hash values in v2.5 must not be shipped.** They were never reproduced from a source artifact, and at least one looks malformed. Treat them as unverified.

### 13.1 Dataset layout

```
src/links/data/ca_distrust/
  manifest.json            # version, records[]
  certs/<id>.pem           # the actual certificate, committed
scripts/build_distrust_dataset.py   # recomputes and checks everything
```

Each record in `manifest.json`:

```json
{
  "id": "diginotar-root",
  "entity": "DigiNotar",
  "classification": "compromised",
  "source_url": "<CCADB / Mozilla / vendor advisory URL>",
  "source_record": "<exact record or bug reference>",
  "retrieved_on": "2026-11-xx",
  "cert_file": "certs/diginotar-root.pem",
  "expected_cert_sha256": "<value taken from the source, entered independently of the PEM>",
  "scope": {"type": "all"}
}
```

Scope types: `all`, or `leaf_not_before_gte` with `cutoff` (applies to certificates issued by this CA on or after the cutoff; the comparison uses the end-entity certificate's `notBefore` when the matched certificate is a CA in the chain, and the matched certificate's own `notBefore` when it is the leaf).

### 13.2 Loader rules

1. For each record, load the PEM and compute SHA-256 fingerprint, SPKI SHA-256, subject, issuer and serial **in code**.
2. A record enters the live dataset only if the computed fingerprint equals `expected_cert_sha256`. A mismatch rejects that record and logs it. It does not crash startup.
3. `build_distrust_dataset.py` prints a table of subject, issuer, serial and both hashes for human review before commit. Your acceptance criterion is "I compared each fingerprint to the source page".
4. `distrust_dataset_version` = manifest version plus the verified record count. A loaded dataset with zero verified records is valid (`TRUSTED` means "no match in dataset vX (0 records)"), but the UI must display the record count so an empty dataset is never mistaken for coverage. If the manifest cannot be loaded at all, classification is `NOT_EVALUATED` and the verdict is capped at `inconclusive` (row 11).
5. Matching considers **every** certificate in the presented chain, by SPKI hash or certificate fingerprint.

For the demo you need at least one verified record. Obtain the certificate from the original CCADB/Mozilla removal record or the vendor advisory, commit it, and enter the expected fingerprint by hand from the source page.

---

## 14. Findings and severities (unchanged from v2.5 except as noted)

| Rule | Severity | Group |
|---|---|---|
| `compromised_ca`, `distrusted_ca` | strong | `reputation_ca` |
| `signature_invalid`, `broken_key_size`, `broken_hash`, `ocsp_revoked` | strong | `tls_trust` |
| `hostname_mismatch`, `cert_expired`, `cert_not_yet_valid`, `untrusted_root`, `self_signed`, `chain_incomplete`, `path_constraint_violated` | moderate | `tls_trust` |
| `weak_key_size`, `legacy_hash`, `excessive_validity_period` | weak | `tls_trust` |
| `unsupported_algorithm`, `resource_limit` | moderate | `tls_trust` |
| `ocsp_unauthenticated`, `ocsp_stale`, `ocsp_malformed`, `probe_error` | info | `tls_trust` |

`finding()` populates `source`, `timestamp`, `evidence_group` and `target` explicitly and never passes `evidence_class` (V4, V5).

---

## 15. Fix-while-coding instructions

Each item says what to do when you reach that file, and the test that proves it. Do not open new review rounds for these. If the test passes, the item is closed.

**F1. Certificate lifetime policy (`validity.py`)**
- Compute `lifetime = not_after - not_before` as a `timedelta` and compare to `timedelta(days=band)`. Do not use `.days`.
- Apply the finding only when the leaf is a **public TLS subscriber certificate**: chain status `VALID_TRUSTED` against the public store, leaf is not a CA, and EKU is absent or contains serverAuth. Private or untrusted chains get no lifetime finding.
- Band lookup is by `not_before`. **VERIFY** the dates and limits against the current CA/Browser Forum baseline requirements before coding (as of v2.5: 398 days before 2026-03-15, 200 until 2027-03-15, 100 until 2029-03-15, 47 after).
- Evidence includes `measured_seconds`, `limit_days`, and `policy: "cabf-br-validity-schedule@<date you verified>"`.
- Tests: a certificate exceeding the limit by 6 hours is flagged; a private-root chain is not.

**F2. Embedded SCT parsing (`ct.py`)**
- Delete the hand parser. Use `x509.PrecertificateSignedCertificateTimestamps` through `get_extension_for_class`; iterate it for `version`, `log_id`, `timestamp`. Catch `ValueError` (malformed encoding) and return `EMBEDDED_PRESENT_MALFORMED`.
- `EMBEDDED_PRESENT_PARSED` requires at least one SCT. Zero SCTs in a present extension is `MALFORMED`.
- Keep `ct_coverage = PARTIAL_EMBEDDED_ONLY`. The README states this is not CT log monitoring.
- Tests: absent, one, two, malformed, empty list.

**F3. Algorithm matrix (`weak_crypto.py`)**
- RSA under 1024 bits: `broken_key_size`; under 2048: `weak_key_size`. EC under 160 bits: `broken_key_size`; under 224: `weak_key_size`. DSA public key: `weak_key_size` with `algorithm: DSA`. Ed25519/Ed448: no key finding.
- Hash check applies to **non-anchor** certificates only (root self-signatures with SHA-1 are harmless). MD2/MD5: `broken_hash`; SHA-1: `legacy_hash`.
- Wrap every property access (`signature_hash_algorithm`, `public_key()`) in `try/except (UnsupportedAlgorithm, ValueError)` and emit `unsupported_algorithm` instead of crashing.
- Tests: one per row, plus a certificate with an unsupported signature algorithm.

**F4. Ports (`_resolve_authorities`)**
- MVP supports 443 only. For an HTTPS authority on another port, do not probe. Add the limitation `tls_non_default_port_not_analysed:<port>` and show it in the UI as a scope note, not as a certificate fault.
- If every authority was excluded this way, return `skipped` with that reason.
- Tests: `https://example.com:8443/` yields `skipped` and the limitation text.

**F5. Immutability**
- Use `tuple[str, ...]` for SAN, key-usage and limitation fields in `CertificateDetails` and `TLSReport`, and `Mapping`-style read-only dicts only where needed. Test that mutating a returned collection raises.

**F6. Docker and fetcher hardening (verify with commands, not diagrams)**
- Compose fetcher service: `user` non-root after the entrypoint drops privileges, `cap_drop: [ALL]` (re-adding only `NET_ADMIN`, `SETUID`, `SETGID` for the entrypoint, as in Module 1), `read_only: true` with a `tmpfs`, `pids_limit`, memory and CPU caps, no Docker socket mount, only `127.0.0.1:8001` published, attached to `egress` and **not** to the data network.
- Verification script `scripts/verify_fetcher_isolation.sh` run against the live container: `id` is not root; `grep CapEff /proc/1/status` shows zero after startup; connections to `10.0.0.1`, `169.254.169.254`, the Postgres and Redis container addresses all fail; no `/var/run/docker.sock`; IPv6 egress is blocked.
- Record the output in `tests/RESULTS.md`. This also closes the open Module 1 isolation items (T0.5, T6.3).

**F7. Corrected tests**
- *IP pinning:* do not use a public-IP/local-listener arrangement. Inject `resolve` and wrap `loop.sock_connect` to record its address argument, then raise `ConnectionRefusedError`. Assert the recorded address is the validated IP, the hostname is never connected to, and the resolver was called once.
- *Byte cap:* test `perform_handshake` directly over a `socket.socketpair()` with a peer that sends more than 128 KiB. Assert `_Limit` is raised and the peer's total bytes read by us is at most cap plus one chunk.
- *Handshake mechanics:* test `perform_handshake` against a local TLS server built from the fixture PKI. This bypasses the guard on purpose, because the guard correctly refuses loopback. No test hooks go into the production guard.
- *Verification policy:* `/probe/tls` returns the chain from a self-signed server; `/fetch` against the same server aborts with `tls_error`.
- *Deadline:* a peer that never answers finishes within `budget + 0.5 s` wall time, and no code path uses a minimum timeout floor (grep test for `max(0.` in the probe files).

**F8. Evidence-group registration** is covered in §2.3. The completeness test is the check.

**F9. Module 5 contract**
- Add a test with a fake Module 5 consumer that reads `ctx.values["tls_reports"][canonical_authority(host, port)]` for the six cases in §3. Missing report means `hsts_ineligible_no_tls_report`.

**F10. HTTP and error statuses** are specified in §12 (`skipped`, `unavailable`, `ok`). Tests: HTTP input gives `skipped`; all probes failing gives `unavailable`; one of two failing gives `ok` with a limitation.

---

## 16. Test plan: proof tests for every must-fix

All offline and deterministic. Generate fixtures with `scripts/make_tls_fixtures.py` and commit the outputs.

| Must-fix | Proving test |
|---|---|
| P0.1 | Contract tests V1 to V10 recorded; eleven registered, ten gating; existing risk tests unchanged |
| P0.2 | `perform_handshake` over `socketpair` aborts at the cap (F7) |
| P0.3 | OCSP fixtures: authenticated good/revoked/unknown, tampered signature, wrong issuer, wrong CertID hash algorithm (SHA-256 CertID), `next_update` past, `this_update` future, no `next_update` older than 7 days. Only direct-issuer valid signatures authenticate |
| P0.4 | One test per `ChainStatus`, including: self-issued with a bad self-signature, path length with two intermediates (a valid chain must pass, a `pathLen=0` CA above an intermediate must fail), expired intermediate, not-yet-valid intermediate, incomplete chain, untrusted root, and a **fixed `now`** used by both manual checks and the policy verifier |
| P0.5 | `*.co.uk` then `example.com` returns `MATCHED` |
| P0.6 | Deadline test and grep test (F7) |
| P0.7 | Exhaustive verdict product test (§11); `INVALID_TARGET` never yields `valid` |
| P0.8 | Fault-injection: monkeypatch each stage (context creation, connect, handshake, chain export) to raise `RuntimeError`; the handler returns a `TLSProbeResponse` with `internal_error` and the socket is closed (assert via a socket wrapper) |
| P0.9 | Bad base64, over-long strings, 11 certificates, one 17 KiB cert, 65 KiB total, oversized OCSP, all rejected before parsing |
| Distrust | Loader rejects a record whose expected fingerprint does not match its PEM; dataset version and count appear in the report |
| Authority | Six canonicalisation cases (§3) |
| Failure info | A failed probe produces a saved report with `probe_error_kind` and limitations |

Existing v2.5 test files remain, with the corrections above. The `-m live` evidence suite stays optional and is never an acceptance criterion.

---

## 17. Build order

| Step | Deliverable | Done when |
|---|---|---|
| S0 | Record V1 to V10 answers | Written in the PR |
| S1 | Module 1 changes (§2): `CHECK_IDS`, `GATING_CHECKS`, groups, `Context.values`, `Report.tls_reports`, test updates | All Module 1 tests green |
| S2 | `models_tls.py`, `authority.py`, shared probe models and byte-identity tests | Model and authority tests green |
| S3 | `trust_store.py`, `signature_verifier.py` (tri-state) with RSA, PSS, ECDSA, Ed25519 fixtures | Signature tests green |
| S4 | `path_validator.py` (§7) | All P0.4 tests green |
| S5 | `hostname_verifier.py` (§9) | P0.5 test green |
| S6 | `weak_crypto.py` (F3), `validity.py` (F1), `ct.py` (F2) | Their tests green |
| S7 | Distrust loader and `build_distrust_dataset.py` (§13) | Loader tests green; at least one verified record, or documented as empty |
| S8 | `ocsp.py` (§10) behind `OCSP_AFFECTS_VERDICT` | All P0.3 tests green, then flip the flag |
| S9 | `verdict.py` (§11) and `findings.py` | Exhaustive test green |
| S10 | Fetcher: request model, guard, `perform_handshake`, `run_tls_probe`, route, token, semaphore | P0.2, P0.6, P0.8 tests green |
| S11 | Host client, bounds, `probe_and_analyze`, check (§6, §8, §12) | P0.9 and status tests green; coverage shows 11 |
| S12 | Compose hardening and `verify_fetcher_isolation.sh` (F6) | Script output recorded |
| S13 | Module 5 contract test (F9), README, checklist update, limitations | Full offline `pytest` green |

**Time:** the v2.5 estimate was about 50 hours. The memory-BIO probe, the OCSP rewrite and the distrust loader add roughly 6 to 8 hours. Plan for about 58 hours, one developer.

**Cut line (if time runs short):** cut live evidence, F2 (report `ct_status = NOT_EVALUATED`), and `OCSP_AFFECTS_VERDICT` (leave the flag off). Do not cut S3, S4, S9, S10, S11 or the exhaustive verdict test. Those carry the correctness and safety properties.

---

## 18. Known limitations (copy to the README)

- A URL alone cannot reveal an internal CA key-generation weakness. eMudhra-style certificates may appear as `untrusted_root` or only match the distrust dataset if a verified record exists. Display this text whenever `untrusted_root` fires with no distrust match.
- The distrust dataset covers only verified records shipped in `data/ca_distrust/`. Its record count is shown in every report.
- CT is embedded-SCT presence and structure only. There is no CT log search or issuance monitoring.
- OCSP: stapled responses only, direct-issuer signatures only. Delegated responders, active OCSP (AIA) and CRL are not implemented.
- Only the negotiated protocol and cipher are reported. Legacy protocol and cipher probing are not performed.
- Port 443 only. Other HTTPS ports are reported as out of scope.
- `VERIFY_NONE` on `/probe/tls` relies on the SSRF guard. Any change to `guard.py` must re-run the Module 1 SSRF suite and the Module 2 guard tests.
- The trust store is the certifi bundle (Mozilla roots) at the version recorded in each report. It is not the OS store, so results can differ from a specific browser.
- A `valid` TLS verdict means the certificate and chain checked out. It does **not** mean the website is safe. The overall `risk_class` is Module 1's.
- `tls_certificate` never moves the Module 1 confidence or Low-Risk gates. It can raise risk and never lower it.
