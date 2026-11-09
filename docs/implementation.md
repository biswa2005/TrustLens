# TrustLens — Implementation Status

Generated from a full review of the repository source, tests, and contracts.

## 1. Application bootstrap

- `src/main.py` — FastAPI app with CORS middleware and `/` and `/health` endpoints.
- Router `src/api/threat_reports.py` mounted under `/threat-reports`.
- `.env` loaded via python-dotenv.
- SQLite by default (`sqlite:///./trustlens.db`), PostgreSQL when `DATABASE_URL` starts with `postgres...`.

## 2. Threat report lifecycle (implemented)

- **Create report** `POST /threat-reports`
  - Computes a 32-byte SHA-256 commitment over a canonicalized (sorted-key, compact) payload.
  - Persists `threat_reports`, `report_revisions`, and (when chain is available) `onchain_refs`.
  - Attempts on-chain submission via `ChainClient.submit_report`; failure returns `502`.
- **Get report** `GET /threat-reports/{id}` — off-chain retrieval.
- **Revise** `POST /threat-reports/{id}/revise` — new commitment, version increment.
- **Dispute** `POST /threat-reports/{id}/dispute` — reason hashing + on-chain dispute.
- **Validate** `POST /threat-reports/{id}/validate` — on-chain validate + status update.
- **Verify** `GET /threat-reports/{id}/verify` — compares supplied commit to on-chain commitment fetched through `getReport`.
- **Provenance** `GET /threat-reports/{id}/provenance` — revisions, disputes, validations, on-chain refs.
- **On-chain view** `GET /threat-reports/{id}/onchain` — metadata snapshot.

## 3. Cryptographic commitment system (implemented)

- `src/hashing.py`
  - `canonicalize()` deterministic JSON (`sort_keys=True`, compact separators).
  - `compute_nonce()` 32-byte hex (64 chars) via `secrets.token_hex(32)`.
  - `fingerprint(payload, nonce)` SHA-256 commitment.
  - `to_bytes32()` helper for bytes32 conversion.

## 4. Database layer (implemented)

- `src/db.py`
  - Dual SQLite / PostgreSQL connection wrappers with dict-like cursors.
  - Schema tables: `threat_reports`, `report_revisions`, `report_disputes`, `report_validations`, `onchain_refs`.
  - `get_db()` initializes schema and yields / closes connections.

## 5. Web3 client (implemented in Python)

- `src/chain.py::ChainClient`
  - RPC connection (default `http://127.0.0.1:8545`), contract address, private key, chain ID (default 31337).
  - Loads ABI from built artifact if present, falls back to `MINIMAL_ABI`.
  - Methods: `submit_report`, `revise_report`, `dispute_report`, `validate_report`, `fetch_commitment`, `fetch_status`, `fetch_revision_count`, `fetch_revision`.
  - Robust error if disconnected / unconfigured.

## 6. Smart contract stack (implemented)

- `contracts/contracts/ThreatRegistry.sol` present.
- `contracts/hardhat.config.js`, deploy script, tests (`contracts/test/ThreatRegistry.test.js`).
- Local deployment evidence:
  - `contracts/deployments/localhost.json`: chainId 31337, contract `0x5FbDB2315678afecb367f032d93F642f64180aa3`, tx `0x13a7...`, block 1.
- Sepolia deployment evidence:
  - `contracts/deployments/sepolia.json` present.

## 7. Tests

- `tests/test_hashing.py` — 3 tests covering canonical determinism, fingerprint length, nonce changes.
- No API, database, chain, or contract integration tests in the repo.

## 8. Not implemented / declared but absent in code

The project README/spec describes large feature areas that are **not present** in the current backend:

- URL and website analysis modules (normalization, typo/homoglyph/phishing checks on submission), risk grading engine beyond report persistence.
- TLS configuration audit (legacy protocol probing), certificate chain verification as a service endpoint.
- Security header audit (HSTS, CSP, XFO, nosniff) — Module 5 entirely.
- Dashboard / frontend implementation.
- Browser extension.
- Proactive domain monitoring / Certstream daemon.
- QR code scam detection.
- Screenshot-based impersonation detection.
- Email security analysis (SPF/DKIM/DMARC).
- Community scam reporting.
- STIX/TAXII or peer broadcast “threat intelligence sharing APIs.”

## 9. Running locally

Working venv requires a Python interpreter whose native modules are not blocked by Windows Application Control. The current `.venv` has been recreated with Python 3.12.14. Start the server with:

```bash
uv run uvicorn src.main:app --host 0.0.0.0 --port 8000
```

Health check: `GET /` → `{"status":"ok"}`.
