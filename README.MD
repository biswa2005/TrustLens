# TrustLens
# 🛡️ TrustLens: AI-Powered Web Threat Detection & Digital Trust Intelligence

## 📖 Overview
The internet's growing complexity has led to highly sophisticated digital threats, from homograph phishing domains to compromised Certificate Authorities and social engineering scams. 

**TrustLens** is an intelligent digital security platform that combines **Artificial Intelligence, Cybersecurity, and Web3** to investigate suspicious digital content, analyze website security, and provide evidence-based security assessments. 

Built with a "Zero-Friction" philosophy, the platform features a centralized investigative backend powering multiple interfaces: a comprehensive Web Dashboard, a real-time Chrome Extension for pre-navigation protection, and a Mobile-friendly Chatbot for instant message scanning.

---

## 🏗️ Architecture & Ecosystem

*   **TrustLens Core (Backend API):** The central nervous system handling threat correlation, external intelligence queries, active non-intrusive scanning, and Web3 interactions.
*   **TrustLens Extension (Browser):** A Manifest V3 Chrome extension providing real-time, pre-navigation blocking and on-page DOM scanning.
*   **TrustLens Dashboard (Web):** A central hub for deep-dive investigations, raw URL/message submissions, and viewing the Decentralized Threat Intelligence ledger.
*   **TrustLens Mobile (Chatbot/PWA):** Frictionless checking for mobile users to forward suspicious messages, QR codes, or links via native share sheets or chat interfaces.

---

## ✨ Core Features

### 1. Intelligent URL and Website Analysis
Submit any suspicious URL or domain for a comprehensive investigation.
*   Normalizes and inspects URLs for domain spoofing, typosquatting, and deceptive character substitutions.
*   Examines redirect chains and embedded parameters.
*   Checks domain reputation against authoritative threat intelligence sources.

### 2. TLS Certificate and Web Trust Analysis
Validates the cryptographic trust infrastructure of any submitted URL.
*   Verifies domain identity, Subject Alternative Names (SANs), and certificate expiration.
*   Inspects the Issuing Certificate Authority, certificate chains, and revocation status.
*   Checks Certificate Transparency logs and flags known compromised CAs or weak signature algorithms.

### 3. AI-Powered Scam and Message Analysis
Paste suspicious emails, SMS messages, or social media communications for AI-driven intent analysis.
*   Identifies urgency-based manipulation, payment requests, and impersonation attempts.
*   Extracts embedded URLs, emails, and phone numbers for correlation.
*   Provides evidence-grounded explanations of risk without treating urgent language as definitive proof of fraud.

### 4. Intelligent Threat Correlation
Connects the dots between isolated incidents to uncover broader fraud campaigns.
*   Identifies reused infrastructure, shared domains, and recurring impersonation patterns across multiple user reports.
*   Uses AI to summarize relationships while backing connections with deterministic technical evidence.

### 5. Website Security Assessment
Performs safe, non-intrusive vulnerability checks on publicly accessible websites.
*   Inspects missing/misconfigured security headers and weak TLS configurations.
*   Detects mixed-content issues and exposed sensitive endpoints via passive inspection.
*   Provides actionable remediation recommendations and severity classifications.

### 6. Decentralized Threat Intelligence (Web3)
A transparent, tamper-evident registry for verified security intelligence.
*   Records cryptographic commitments (hashes) of threat reports on-chain.
*   Ensures raw URLs and sensitive user data remain completely off-chain.
*   Maintains a verifiable reporting history for independent integrity checks and provenance tracking.

---
## Web3 Verification Evidence
* **Contract (registry):** `ThreatRegistry.sol`
* **Network:** Hardhat local blockchain (chainId 31337) — reproducible local setup.
* **Contract address:** `0x5FbDB2315678afecb367f032d93F642f64180aa3`
* **Deployment transaction:** `0x13a7dcd9d66aa13bda38252d6c84d6cc53455fe47707e359a6554a655829c558` (block 1)
* **Verification evidence file:** `contracts/deployments/localhost.json`

### On-chain integrity scope
The blockchain record proves **integrity and history only**, never the truth of a report. Raw URLs, domains, incident text, evidence references, and PII stay entirely off-chain in PostgreSQL/SQLite. Only the 32-byte SHA-256 commitment of the canonical (salted) report is recorded.

### Independent integrity check
`GET /threat-reports/{id}/verify?commitment=<hex>` (or omit `commitment` to use the stored off-chain commitment) fetches the on-chain commitment and returns whether it matches, with the supporting transaction references. Lifecycle events are exposed via `GET /threat-reports/{id}/provenance`.

### Running the Web3 stack locally
```bash
cd contracts
npm install
npx hardhat node                # Terminal 1
npx hardhat run scripts/deploy.js --network localhost   # Terminal 2
```
Copy `contracts/deployments/localhost.json` values into `.env` (`CONTRACT_ADDRESS`, etc.), or run against Sepolia by setting `SEPOLIA_RPC_URL` and `PRIVATE_KEY` and using `--network sepolia`.

---

## 🚀 Advanced Extensions Implemented

Beyond the core requirements, this project integrates several advanced capabilities to maximize user protection and accessibility:

*   **Browser Extension (Pre-Navigation Check):** Automatically intercepts and scans links before the browser resolves them.
*   **Real-Time Phishing Protection:** Actively monitors the DOM via `IntersectionObserver` to flag malicious links during scrolling.
*   **QR Code Scam Detection:** Allows users to upload or scan QR codes to extract and investigate the underlying destination.
*   **Screenshot-Based Impersonation Detection:** Analyzes uploaded images to extract text and URLs for scam verification.
*   **Email Security Analysis:** Deep inspection of email headers and content for sophisticated phishing attempts.
*   **Domain Monitoring:** Alerts for suspicious certificate issuance.
*   **Lookalike & Homoglyph Detection:** Advanced string comparison to catch sophisticated visual domain spoofing.
*   **Compromised CA Monitoring:** Real-time tracking of distrusted or compromised certificate authorities.
*   **Automated Audits:** Continuous, non-intrusive TLS and security header assessments.
*   **Threat Intelligence Sharing APIs:** RESTful endpoints allowing external security tools to pull risk data and push new threat indicators programmatically.
*   **Community-Based Reporting:** A collaborative validation system for submitted scams.
*   **Organization-Level Dashboard:** A high-level view for monitoring security postures and enterprise-wide threat exposure.

---

## 📊 Risk Classification System

All investigations strictly adhere to a standardized grading scale to ensure clarity:
1.  **Low Risk:** No significant malicious indicators identified.
2.  **Suspicious:** One or more indicators require further investigation.
3.  **High Risk:** Multiple significant indicators suggest a substantial threat.
4.  **Confirmed Malicious:** Supported by authoritative threat intelligence or validated evidence.
5.  **Inconclusive:** Insufficient data or unavailable verification sources.

*(Note: The system never treats the absence of known threats as proof that a website is 100% safe.)*

---

## 🛠️ Technology Stack

*   **Backend:** Python (FastAPI), OpenSSL, native DNS analysis.
*   **Frontend/Dashboard:** Next.js, React, Tailwind CSS, TypeScript.
*   **Browser Extension:** Manifest V3, JavaScript, Chrome APIs.
*   **AI/LLM:** [Insert Model here, e.g., OpenAI API / Gemini / Local RAG system]
*   **Web3:** Solidity (Smart Contracts), Ethers.js, EVM-compatible Testnet (e.g., Sepolia).
*   **Threat Intel APIs:** Google Safe Browsing, VirusTotal, crt.sh (Certificate Transparency).
*   **Database:** PostgreSQL (Relational Data), Redis (Caching/Rate Limiting).

---

## 🔒 Security & Privacy Notice

**TrustLens is built with security-first principles:**
*   **Passive Scanning Only:** The platform does not exploit vulnerabilities, execute malicious scripts, or perform intrusive active scanning.
*   **SSRF Protection:** Strict request limits, URL parsing, and IP validation prevent server-side request forgery during URL inspection.
*   **Data Minimization:** No personal information, passwords, or seed phrases are ever requested or stored. All decentralized reporting utilizes cryptographic hashing to preserve privacy.
Boilerplate FastAPI project managed with `uv`.

## Run

```bash
uv sync
python run.py --host 0.0.0.0 --port 8000```

Then open http://localhost:8000.

## Health

- `GET /` -> `{"status": "ok"}`
