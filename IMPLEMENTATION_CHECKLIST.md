# TrustLens implementation checklist

Source of requirements: the user-supplied Module 1 implementation plan (not committed) and the repository-local `TrustLens_Module2_Implementation_v2.6.md`. This checklist distinguishes verified implementation (`[x]`), partial implementation (`[~]`), and blocked/not implemented (`[ ]`). A file existing is not sufficient for `[x]`.

## Agreed architecture

- Python 3.12 / FastAPI API runs on the host, per the user's explicit direction. `run.py` loads `.env`; the API connects through loopback-published ports.
- Compose contains only the isolated fetcher, PostgreSQL 16 + pgvector, and Redis 7. PostgreSQL is persistent; Redis is URLhaus indicator storage. The fetcher has no route to the `data` network.
- The ten original Module 1 checks remain unchanged. Module 2 adds `tls_certificate` as check 11; URLhaus remains check 10 and Redis is not a check.
- URLhaus import is manual and one-time. The importer is not part of API startup or a scheduler.
- Modules 1 and 2 are implemented. Module 5, embeddings, LLM explanations, and a dashboard are not present in this repository.

## Phase 0 — Existing scaffold and services

- [x] T0.1 Reuse the existing `src/main.py`, `src/links/`, uv project, and `.env.example`; no secrets copied into the example.
- [x] T0.2 Declare dependencies in `pyproject.toml`, regenerate `uv.lock`, and export `requirements.txt`; `python-dotenv` is explicit because both `run.py` and the manual importer use it.
- [~] T0.3 Wire `/api/v1/analyse/url`, health routes, and the isolated fetcher. API executes on the host as directed. Fetcher probing and isolation have been verified; a current-code API response including TLS data and its persisted GET round-trip remain unverified.
- [~] T0.4 Compose has `pgvector/pgvector:pg16`, vector init SQL, async pool, migration runner, and report/cache/usage schema. The PostgreSQL integration test has passed against the disposable `trustlens_test` database. The current-code API report persistence/GET flow and production-database expiry/counters/cache behavior remain unverified.
- [~] T0.5 Compose has Redis 7, password, persistence, and a dedicated bridge attached only to PostgreSQL/Redis; loopback ports serve the host-run API. The fetcher is not attached. `internal: true` was removed because it prevented effective host-published ports. A real URLhaus import succeeded (167,217 records: 111,995 active, 55,222 historical), application lookups verified active confirmation and historical non-confirmation, and rebuilt-image probes confirmed PostgreSQL/Redis destinations are blocked. Import idempotency and failed-live-import behavior remain unverified.

## Phase 1 — Models, check framework, URL normalization

- [x] T1.1 Models cover normalized URLs, findings, checks, hops, targets, domain metadata, intel matches, evidence groups, redirect summaries, coverage, and reports. Enum validation and JSON round-trip coverage for the typed report models are tested.
- [x] T1.2 Registry has ten original Module 1 checks and eleven total after Module 2, with ordered dependencies, required-success dependencies, timeouts, skip status, exception containment, concurrent ready checks, and deterministic aggregation. Unit tests cover timeout, dependency failure, independent checks, and check registration.
- [~] T1.3 Normalizer handles schemes, IDNA, defanged input, userinfo, whitespace, Unicode dots, mapped/decimal/hex/octal/short IPv4, ports, nested URL cap, browser-style encoded dot-segment resolution, base64 embedded URL extraction, and host parser-disagreement signaling. Malformed-host and exhaustive browser parser differential cases remain unverified.
- [~] T1.4 Hypothesis fuzzing checks canonical result or `ValueError`; targeted O9/O20/O22 cases pass, but the full obfuscation corpus and differential `ada-url` oracle are not implemented.

## Phase 2 — Local lexical and brand detection

- [~] T2.1 Data files exist for brands, known-good domains, risky TLDs, shorteners, keywords, and known redirect pairs. Brand count exceeds 60, but official-domain verification and `verified_on` provenance for every entry are missing.
- [~] T2.2 Lexical rules cover IP host, userinfo, obfuscation, URL length, hyphens, risky TLD, keywords, shorteners, subdomains, entropy, nested destinations, ports, and known-good dampening. A complete positive/negative test for every rule and complete finalized S-cases are outstanding.
- [~] T2.3 Brand check uses Damerau-Levenshtein lookalikes, combosquats, brand claims, and brand-in-subdomain rules. It is not yet verified against every plan case or the curated official-domain corpus.
- [~] T2.4 Mixed-script homographs are detected; pure-script IDN, punycode, Greek/Cyrillic coverage and false-positive review remain incomplete.
- [~] T2.5 Known-good dampening and shared-host suffix guard exist; full dampening/no-dampening independence coverage is outstanding.

## Phase 3 — SSRF-safe fetcher and redirect analysis

- [~] T3.1 Guard validates HTTP/HTTPS and ports, resolves A/AAAA, rejects private/mixed answers, and recognizes noncanonical IPv4 forms. Coverage of all reserved/special ranges and all section 16.2 cases remains incomplete.
- [~] T3.2 Requests pin the TCP connection to a vetted IP and retain hostname-based TLS verification. Unit mocks assert pinned address/SNI; real certificate-valid/mismatch integration tests are still missing.
- [~] T3.3 Fetcher supports bounded hops/body/headers/time, HTTP redirects, Refresh, meta refresh (up to 5 seconds), literal JS, loops, TLS errors, and intermediate HTML. Real-socket slow-loris, compression, header-size, redirect-limit and full redirect-corpus tests remain outstanding. The final loopback health-rule adjustment has not been runtime-verified.
- [~] T3.4 Host API client streams and caps fetcher response size and validates key structure and hop/page limits. Malicious/malformed response tests and actual API-to-fetcher integration are outstanding.
- [~] T3.5 Input/final/hop targets receive local lexical/brand analysis, relation metadata and selected redirect findings. Full R1–R21 behavior, target prioritization, and per-hop DNS/RDAP/reputation evidence mapping remain incomplete.
- [~] T3.6 Password-form inspection checks HTML from intermediate and final hops, cross-domain actions, and HTTP actions. Dedicated positive/negative fixtures are not yet present.
- [~] T3.7 Mock resolver and transport patterns exist across security tests; a shared, reusable fixture suite and full adversarial fixtures are incomplete.
- [~] T3.8 Implemented cross-site, known-pair, brand mismatch, downgrade, IP, blocked destination, loop, hop-limit, obfuscation, shared-hosting, static redirect and open-redirect findings. Full R1–R21 acceptance table is not tested.

## Phase 4 — DNS, persistence, external intel, URLhaus

- [~] T4.1 DNS check queries A/AAAA/MX/NS/TXT and handles NXDOMAIN/timeouts. Deterministic DNS fixtures and final-target reuse tests are outstanding.
- [~] T4.2 RDAP uses IANA bootstrap cache and registration age bands. Deterministic bootstrap/date/unavailable tests and runtime cache checks are outstanding.
- [~] T4.3 PostgreSQL code implements migrations, JSONB report storage, report retrieval, hashed cache keys/TTL, atomic daily usage, and retention purge. A disposable PostgreSQL integration suite exists but was skipped because `TEST_DATABASE_URL` is unset; the running DB lacks tables; acceptance remains incomplete.
- [~] T4.4 Safe Browsing v4 batches up to 50 URLs, caches hits/cleans, rate-limits, and sanitizes errors. Only a mocked match test exists; clean/cache-hit/status/quota fixtures and official test URL are outstanding.
- [~] T4.5 VirusTotal URL and registered-domain lookups, GSB engine exclusion, cache, per-minute/daily quotas, 404/429 handling, and partial findings are implemented. Full 0/3/8, domain cap, retry/error/quota and target coverage fixtures are outstanding.
- [~] T4.6 Request option skips Safe Browsing and VirusTotal while URLhaus remains registered/runnable. Explicit check-status assertions for skip behavior are incomplete.
- [~] T4.7 Manual streaming importer supports comment-prefixed headerless URLhaus dumps, headered CSV, quoted values, FTP IOCs, malformed/conflicting duplicate rejection, identical duplicates, active/historical partitions, staging cleanup and generation pointer switching. Fakeredis tests pass. Real import succeeded with 167,217 records and application lookups verified active confirmation versus historical non-confirmation; real rerun idempotency and failed-live-import behavior remain unverified.

## Phase 5 — Risk engine and API

- [~] T5.1 Risk rules implement the finalized confirmation, High, Suspicious, Low/Inconclusive, URLhaus historical/active, VirusTotal domain cap, confidence, group, and target behavior. Unit/property tests cover key boundaries and independent-group monotonicity; complete section 16.7 cases remain.
- [~] T5.2 Risk reasoning and per-class recommendation text exist. Recommendation/limitation wording and reputation-skipped/incomplete-chain cases are not fully exercised.
- [~] T5.3 POST analysis validates URLs and returns eleven checks (ten original checks plus TLS); GET report retrieval, clean 400s, rate limiting, CORS and `/healthz` handling are wired. A user-provided current-server POST returned 200, but its response body did not establish TLS inclusion and a current report's PostgreSQL GET round-trip remains unverified.

## Phase 6 — Deployment hardening

- [x] T6.1 Current entrypoint is default-deny for OUTPUT, permits the narrow loopback health port, Docker DNS and established replies, allows new TCP 80/443 only after private/special-range drops, then uses `setpriv` to remove `NET_ADMIN`. The latest image runs as UID 10001 with `CapEff=0`; private, metadata, PostgreSQL, Redis, and IPv6 probes were blocked and loopback health passed.
- [x] T6.2 Compose config validates. The latest fetcher image was rebuilt and recreated from the workspace; its `tls_probe.py` and `models.py` hashes match the source. Compose has a read-only filesystem, tmpfs, resource caps, capability drops, host-loopback ports, PostgreSQL 16 and Redis 7. Current API-to-database report persistence remains separately unverified.
- [~] T6.3 App guard unit tests and firewall direct-connect probes pass. The broad per-layer SSRF matrix remains outstanding; fetcher-to-PostgreSQL/Redis isolation and Docker network reachability were verified against the rebuilt image.

## Phase 7 — UI, corpora and evidence

- [ ] T7.1 Dashboard is blocked: the separate frontend project/location has not been identified. No dashboard was added to the backend repository.
- [~] T7.2 Offline corpus test and `scripts/build_test_results.py` now generate `tests/RESULTS.md` with input observations, expected/observed class, findings/groups, coverage/confidence, corpus hashes, benign rule counts, per-category rates, and pending FP/evasion notes. There are 5 benign and 40 adversarial entries. The plan requires at least 40 currently verified benign entries, human FP dispositions, all redirect/E2E cases, and a full API coverage/confidence run; those remain incomplete.
- [~] T7.3 README describes the implemented Module 1 architecture, run steps, manual importer, risk thresholds, and known verification gaps. Runtime status must be refreshed after the next real Compose run.
- [ ] T7.4 Full false-positive review, dated verification of benign entries, adversarial per-category pass criteria, and one-hour manual red-team pass remain undone.

## Latest verification

- Latest recorded full suite: **472 passed, 1 skipped, 2 warnings**. The skipped test was PostgreSQL integration in that run because `TEST_DATABASE_URL` was unset; the warning types were Starlette's TestClient deprecation and a certifi certificate parsing warning. The PostgreSQL integration test was separately run against the configured disposable `_test` database and passed.
- `uv run python -m compileall -q src fetcher scripts run.py` passed.
- `uv run python scripts/build_test_results.py` passed; it generated offline results for 5 benign and 40 adversarial entries.
- `docker compose config --quiet` passed. The latest fetcher image was rebuilt and recreated; the `fetcher/tls_probe.py` and `fetcher/models.py` hashes match the workspace. Rebuilt-image isolation checks passed for UID 10001, zero effective capabilities, absent Docker socket, DNS, blocked private/metadata/database/Redis/IPv6 egress, and loopback health.
- PostgreSQL and Redis are healthy with loopback-published ports. URLhaus import and active/historical lookups were verified. The user provided logs of a current API POST returning 200, but those logs do not include the response body; the current report's `tls_reports` field and GET-by-ID round-trip have not been verified.

## Architecture reconciliation

The finalized guide describes a Compose API container plus a separately isolated fetcher. Earlier user direction explicitly changed local operation to run the Python API on the host and keep only fetcher, PostgreSQL, and Redis in Compose. This repository follows that explicit local-development decision: host API connects to loopback-published data-service ports and the fetcher; the fetcher is attached to its egress network and cannot join the private PostgreSQL/Redis network. For deployment using the original two-container boundary, an API service/container still needs to be added and verified; it is not silently treated as implemented.

## Remaining acceptance blockers

1. Verify a current-code API POST response includes all eleven checks and `tls_reports`, then GET its report ID to confirm PostgreSQL persistence.
2. Add the complete redirect/response-limit security suite and finish all Module 1 input/hop/final-target coverage and section 16.7 risk cases.
3. Complete provider fixtures, benign-corpus verification and human false-positive/evasion review.
4. Verify and expand the benign corpus to 40 entries; complete human FP/evasion dispositions and the manual red-team review from `tests/RESULTS.md`. Dashboard remains blocked on frontend location.

## Module 2 — TLS certificate and web trust (2026-11-09)

- [x] Added the 11th `tls_certificate` check. Coverage displays 11; confidence and Low-Risk gates use the unchanged ten Module 1 check IDs.
- [x] Added canonical authority formatting, frozen TLS report/certificate models, JSON report persistence, bounded host-side response decoding, and byte-identical host/fetcher wire-model and authority copies.
- [x] Added async memory-BIO TLS handshake with a 128 KiB received-byte cap, one deadline, pinned-IP guard reuse, response chain limits, shared token authentication, and four-probe concurrency limit.
- [x] Added hostname verification with the wildcard continuation fix, public certifi trust store versioning, chain signature/path checks, crypto weakness checks, public certificate validity schedule, verdict truth table, distrust manifest verification, authenticated direct-issuer OCSP staples, and embedded SCT structural parsing.
- [x] Fixed cross-sign anchoring in `path_validator.validate_chain`: examples of (b) occurred for `example.com` and `google.com`; the fetcher supplied a complete, correctly ordered chain whose top certificate was cross-signed by an issuer absent from certifi but had the same SPKI as a certifi root. The validator had checked only exact top-certificate fingerprints or issuer-name presence, so it missed the matching trusted key.
- [x] Anchor selection now accepts supplied root fingerprints, DER issuer-to-root subject matches with compatible AKI/SKI, and supplied certificates with an SPKI matching a trust root. It truncates above root fingerprint/SPKI matches and keeps `PolicyBuilder` failures `inconclusive` with one shared `now`.
- [x] Added deterministic fixed-time path fixtures and tests covering every `ChainStatus`, cross-sign regression, DER string-type variation, validity, signatures, path length, unsupported Ed448, and chain-depth bounds. Added fault-injection coverage for resolve, connect, handshake, chain export, and response building; runtime errors return `internal_error`, and created sockets are closed.
- [x] Module 2 tests cover authority and wire-copy identity, 11/10 check gates, verdict catch-all, wildcard behavior, six-hour lifetime overage, report immutability/round-trip, response bounds, socket byte cap, local TLS handshake, OCSP good/revoked/unknown/tampered/wrong-issuer/SHA-256 CertID/freshness, SCT structure, non-default port scope, and distrust fingerprint rejection.
- [x] Live `/probe/tls` diagnostics against `example.com`, `google.com`, `github.com`, and `wikipedia.org` show before/after chain statuses: `incomplete_chain` → `valid_trusted`, `incomplete_chain` → `valid_trusted`, `valid_trusted` → `valid_trusted`, and `valid_trusted` → `valid_trusted`. Full certificate/path output is in `scripts/diagnose_chain_output.txt`.
- [x] PostgreSQL integration ran with the configured `trustlens_test` database and passed (1 test); the Windows-only test connection aliases `localhost` to the published IPv4 loopback while keeping application configuration unchanged.
- [x] Latest recorded full suite: 472 passed, 1 skipped, 2 warnings; the PostgreSQL integration test was separately run against the configured `_test` database and passed. `compileall` passed.
- [x] Rebuilt and force-recreated the fetcher image from the current working tree (image manifest `sha256:ea1028954156ddce8fe009d65cd79b23eaf14f165e10a97b01dbddf22cbf41f3`). The image's `fetcher/tls_probe.py` and `fetcher/models.py` hashes match the workspace: `0488a95d942777ec728ae68bdded99481763946f741e6516a13851679c44ba44` and `90b13f48c7aa83cb114153c680c31065473f7010a9ffeca2e22f23e580d12fbb`.
- [x] Isolation recheck passed against that rebuilt image: PID 1 UID 10001; `CapEff=0`; Docker socket absent; Docker DNS working; connections to `10.0.0.1:443`, `169.254.169.254:80`, PostgreSQL `172.22.0.2:5432`, and Redis `172.22.0.3:6379` blocked; IPv6 egress blocked; loopback `/healthz` returned 200. The Bash script could not run because WSL/Bash is unavailable, so the same checks ran directly through PowerShell and `docker compose exec`.
- [x] Added a Mozilla-documented compromised eMudhra intermediate (CCADB A012302); the committed PEM fingerprint was independently matched to Mozilla's incident record and the CT archive.
- [ ] Module 5 is not present in this repository, so its HSTS consumer test is deferred.

### v2.6 Module 1 reconciliation (V1–V10)

| # | Answer |
|---|---|
| V1 | `registry.execute` accepts `(CheckResult, list[Finding])`; `tls_certificate` uses it. |
| V2 | `Context` is a dataclass and already has `values: dict`. |
| V3 | `ctx.fetch_result` is a dict; the TLS check reads `final_url` from it. |
| V4 | `Finding` has `source`, `timestamp`, `evidence_group`, `target`, and `dampenable`; the TLS finding sets source/target/group and relies on defaults for timestamp/dampenable. |
| V5 | `Finding` does have `evidence_class`, so the TLS finding passes it. This differs from the v2.6 "never pass" instruction but is not a verdict defect; the group-to-class map for TLS lives in `tls/findings.py`. |
| V6 | The runner converts an escaped check exception to `status="error"`; Module 2 does not rely on it. |
| V7 | `risk.classify` groups by `Finding.evidence_group` and takes the class from the finding; `findings.RULES`/`EVIDENCE_GROUPS` define the TLS contracts. |
| V8 | Confidence and Low-Risk gates are in `risk.py`; `_ok_gating` uses the ten original IDs, with unchanged `>=7`/`>=8` thresholds. |
| V9 | `tests/unit/test_registry.py` and `test_tls_is_11th_check_but_not_gating` carry the check-count assertions. |
| V10 | Fetcher routes are in `fetcher/app.py`, the probe in `fetcher/tls_probe.py`, and probe/image dependencies in `requirements-fetcher.txt`/`Dockerfile.fetcher`. |

### v2.6 review verification (2026-11-09)

- Added proof tests for truth-table break/weak rows, pinned-IP and absolute-deadline probe behavior, and the check status contract (HTTP skipped, all probes failed unavailable, one of two failed ok). The latest recorded full-suite count is listed above; its single skipped test was PostgreSQL integration because `TEST_DATABASE_URL` was unset for that run.
- `uv run python -m compileall -q src fetcher scripts run.py`: passed.
- Live host-side probes of `example.com`, `google.com`, `github.com`, and `wikipedia.org`: all `valid_trusted`/`matched`/`valid`; `example.com` also returned an authenticated GOOD OCSP staple, and its live leaf parsed two embedded SCTs.
- Live container `/probe/tls`: incorrect token 401; `example.com` 200 with four certificates, TLS 1.3, and a staple; loopback and `10.0.0.1` returned `blocked`.
- The latest image build and isolation recheck are recorded above. The user-provided server log shows a current API POST returned 200, but the response body and persisted GET-by-ID result have not been verified.

### v2.6 documented limitations (not must-fix by the admission rule)

- IPv6-only authorities fail closed: the probe reconstructs a bracketless URL before the guard and receives `Blocked: port_not_allowed`. No certificate evidence is produced.
- `TLS_PROBE_TIMEOUT_BUDGET` is read directly from the environment; the spec's `<= 8.0` config validator is absent. Values above 8 still end at the runner's 10 s timeout.
- Hash-policy anchor classification still treats only a self-issued terminal certificate as an anchor; an old SHA-1 cross-signature can therefore produce a `legacy_hash` false positive, which raises rather than lowers the verdict. This is separate from the fixed trust-path cross-sign anchoring.
- The Module 5 HSTS consumer contract test cannot run because Module 5 is absent.
