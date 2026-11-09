# TrustLens Module 1 — implementation handoff context

## Architecture and scope

- The API runs on the host (`uv run python run.py`), as Malik requested. `run.py` loads the root `.env`; local connections use loopback-published ports. On Windows the shared launcher runs Uvicorn's server coroutine with an explicit Selector loop factory because Uvicorn 0.54 otherwise forces Proactor, which Psycopg async mode cannot use.
- Docker Compose contains the isolated fetcher, PostgreSQL 16 with `pgvector`, and Redis 7. The current Compose file publishes fetcher 8001, PostgreSQL 55432, and Redis 6379 to loopback only. Redis is URLhaus indicator storage, never an analysis check.
- Eleven checks are registered after Module 2 integration, with `tls_certificate` at position 11. The original ten remain the confidence and Low-Risk gates. Manual one-time URLhaus import only; no startup importer or scheduler.
- Module 1 and the core Module 2 TLS certificate/web trust analysis are implemented. Module 5, dashboard, embeddings, and LLM explanation code are not present.

## Current integrated implementation

- FastAPI exposes analysis, report, health, and monitoring routes. It has clean invalid-input handling, per-IP rate limiting, restricted CORS, sanitized analysis errors, and PostgreSQL-backed report and monitoring lifecycles in code.
- The standalone `scripts/create_api_key.py` command creates a hashed monitoring key and prints the raw key once. On Windows it uses the shared Selector event-loop factory required by Psycopg async mode.
- The runner registers eleven checks, enforces ordering and required-success dependencies, applies timeouts, runs ready checks concurrently, preserves partial findings on unavailable checks, and returns one result slot per check. TLS check results use the runner's explicit `(CheckResult, findings)` return form.
- Normalization includes IDNA, defanged inputs, userinfo removal/flagging, whitespace and Unicode-dot handling, scheme repair, mapped and alternate IPv4 forms, nested URL scan caps, browser-style encoded dot-segment resolution, base64 embedded URL extraction, parser-disagreement signaling, and port/obfuscation markers. Targeted O9/O20/O22 tests pass; the full browser differential corpus is still incomplete. Lexical and brand checks use local JSON datasets; brand matching includes fuzzy distance, combosquat, subdomain claims, and mixed-script signals.
- Fetcher resolves every hop, rejects private/mixed/non-global records using the app guard, pins connections to validated IPs, keeps TLS verification and hostname SNI, applies connect/read/hop/total budgets and body/header/hop caps, follows HTTP/Refresh/meta/quoted-JS redirects, preserves intermediate HTML, and records TLS/blocked-hop details. Its API client caps and validates the fetcher response.
- PostgreSQL code provides migrations, JSONB reports, report lookup/retention, cache TTLs, daily usage counts, and purge. Redis app access uses a lifespan-managed async client. URLhaus import stages a generation and switches one active pointer only after full validation. Active exact URL/host records can confirm; historical records cannot; domain-level URLhaus confirmation does not exist.
- Safe Browsing v4 and VirusTotal clients use PostgreSQL caching, rate/quota tracking, bounded lookup targets, sanitized errors, and partial-result handling. VT excludes Safe Browsing from malicious engine counts and registered-domain matches are capped at Moderate.
- Risk rules group evidence and implement the finalized thresholds, confidence/coverage gates, active-versus-historical URLhaus rules, report reasoning, and risk-specific recommendations.
- Core report types are explicit Pydantic models for `Target`, `IntelMatch`, `DomainInfo`, `EvidenceGroup`, and `RedirectSummary`, with constrained risk/target/status literals and JSON round-trip validation tests.

## Tests currently in the repository

- Unit: registry, normalization/detection, risk aggregation, mocked Safe Browsing/VT, importer, fakeredis, API response shape, and offline corpus checks.
- Security: SSRF IP/mixed-DNS/obfuscated-address guard checks; fetcher pinned-IP/SNI mock, body cap, blocked redirect, intermediate HTML, static redirect forms, and TLS error recording.
- Property tests: normalizer fuzzing and order/independent-group monotonicity.
- Corpora: five benign and forty synthetic adversarial offline URLs. `scripts/build_test_results.py` writes `tests/RESULTS.md` with corpus hashes, static-only observed classes, groups, coverage/confidence, benign rule counts, and per-category adversarial rates. The benign set is too small and is not manually/date verified, so this is not the completed section 16.6 evaluation.

## Current verification and service state (2026-11-09)

- Latest recorded full suite: **472 passed, 1 skipped, 2 warnings**. The skipped test was PostgreSQL integration because `TEST_DATABASE_URL` was unset for that full-suite run; the warnings were Starlette's `httpx` TestClient deprecation and a certifi certificate parsing warning. The PostgreSQL integration test was separately run with the configured disposable `_test` database and passed.
- `uv run python -m compileall -q src fetcher scripts run.py` and `uv run python scripts/build_test_results.py` passed.
- Compose PostgreSQL and Redis are healthy with loopback-published ports. The DB integration test verified migration, cache, usage counter, report save/retrieval, and retention behavior. URLhaus import and active/historical Redis lookups were also verified.
- The latest fetcher image was rebuilt and recreated from the workspace; `fetcher/tls_probe.py` and `fetcher/models.py` hashes match. Isolation checks passed: UID 10001, `CapEff=0`, no Docker socket, DNS and loopback health working, private/metadata/database/Redis/IPv6 egress blocked.
- The user-provided current API log shows a POST to `/api/v1/analyse/url` returned 200. The response body did not establish whether `tls_reports` was present, and the corresponding GET-by-ID round-trip has not been verified.

## Module 2 v2.6 review (2026-11-09)

- `TrustLens_Module2_Implementation_v2.6.md` is copied into the repository root and is the current Module 2 specification.
- The full-suite result is recorded once in “Current verification and service state” above. The PostgreSQL integration test was separately run with the configured test database and passed.
- Added proof tests for the v2.6 truth-table break/weak rows, the probe's pinned-IP and absolute-deadline properties (F7), and the check status contract (F10: HTTP skipped, all probes failed unavailable, one of two failed ok).
- Live host-side probe code against `example.com`, `google.com`, `github.com`, and `wikipedia.org` returned chain `valid_trusted`, hostname `matched`, verdict `valid` for all four. `example.com` returned a GOOD authenticated OCSP staple, and a live leaf fetch parsed two embedded SCTs through `inspect_embedded_scts`; the other three sent no staple.
- Live container `/probe/tls`: wrong token returned 401; `example.com` returned 200 with four certificates, TLS 1.3, and a staple; `127.0.0.1` and `10.0.0.1` returned `ok=false`, `error_kind=blocked`.
- Running fetcher image: PID 1 is `uvicorn` as UID 10001 with `CapEff=0`; no Docker socket; connections to `10.0.0.1:443`, `169.254.169.254:80`, PostgreSQL `172.22.0.2:5432`, and Redis `172.22.0.3:6379` failed; IPv6 egress was unreachable; the loopback health endpoint returned 200. The running image's `fetcher/tls_probe.py` and `fetcher/models.py` SHA-256 values match the working tree.
- The latest fetcher build and isolation check are verified above. A current API POST returned 200, but the response body and persisted GET-by-ID result have not been verified.
- Documented limitations found: IPv6-only authorities fail closed because the probe reconstructs a bracketless URL before the guard (`Blocked: port_not_allowed`); `TLS_PROBE_TIMEOUT_BUDGET` is read from the environment without the spec's `<= 8.0` validator; a SHA-1 cross-signature may still raise a `legacy_hash` false positive because hash-policy anchor classification treats only self-issued terminal certificates as anchors. Trust-path cross-sign anchoring itself is fixed. The Module 5 HSTS consumer test remains deferred because Module 5 is absent.

## Outstanding work

1. Verify the current API response contains all eleven checks and `tls_reports`, then retrieve that report by ID to confirm persistence through the API.
2. Complete the full fetcher redirect/response-limit suite and remaining Module 1 input/hop/final-target and risk-matrix coverage.
3. Complete provider fixtures and the dated benign-corpus and human false-positive/evasion review.
4. Add the full fetcher SSL certificate valid/mismatch integration test, compressed/slow-loris/response-header/redirect-budget tests, and all R1–R21 tests.
5. Finish checks' input/hop/final target coverage, Safe Browsing/VT fixtures and limits, deterministic DNS/RDAP tests, and complete section 16.7 risk cases.
6. Grow the benign corpus to at least 40 entries with current verification dates. The adversarial corpus has 40 synthetic offline rows. Complete human FP/evasion dispositions and the one-hour manual red-team review using the generated `tests/RESULTS.md`.
7. T7.1 dashboard work is blocked until the separate frontend project's location is provided.

## Architecture reconciliation

The finalized guide's deployment diagram calls for API and fetcher containers. Malik later explicitly requested that the Python backend run on the host, leaving fetcher, PostgreSQL, and Redis in Compose. This repository follows that local-development instruction; host ports are loopback-bound. It does not claim that the source-plan API-container deployment boundary has been implemented or runtime-tested. If deployment must strictly use the plan's API-container network boundary, that deployment work remains outstanding.

`IMPLEMENTATION_CHECKLIST.md` has the T0–T7 requirement-by-requirement ledger and verification/blocker record. Do not flip partial items to complete without the corresponding evidence.
