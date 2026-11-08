import { useState } from 'react'
import './App.css'

const API = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

function log(setLogs, message) {
  const stamp = new Date().toLocaleTimeString()
  setLogs((prev) => [`[${stamp}] ${message}`, ...prev].slice(0, 120))
}

export default function App() {
  const [domain, setDomain] = useState('evil-paypal.com')
  const [url, setUrl] = useState('http://evil-paypal.example/login')
  const [summary, setSummary] = useState('credential harvesting phishing')
  const [reportId, setReportId] = useState('')
  const [commitment, setCommitment] = useState('')
  const [txHash, setTxHash] = useState('')
  const [result, setResult] = useState(null)
  const [logs, setLogs] = useState([])
  const [busy, setBusy] = useState(false)

  async function call(path, options = {}) {
    log(setLogs, `-> ${options.method || 'GET'} ${path}`)
    const res = await fetch(`${API}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    })
    const text = await res.text()
    let data
    try {
      data = JSON.parse(text)
    } catch {
      data = text
    }
    log(setLogs, `<- ${res.status} ${path} ${typeof data === 'object' ? JSON.stringify(data) : data}`)
    if (!res.ok) throw new Error(`${res.status} ${path}: ${text}`)
    return data
  }

  async function runStep(name, fn) {
    setBusy(true)
    try {
      log(setLogs, `=== ${name} ===`)
      await fn()
    } catch (err) {
      log(setLogs, `ERROR: ${err.message}`)
    } finally {
      setBusy(false)
    }
  }

  async function createReport() {
    await runStep('Create Threat Report', async () => {
      const data = await call('/threat-reports', {
        method: 'POST',
        body: JSON.stringify({
          reporter_pseudonym: 'demo-analyst',
          indicators: { domain, url },
          campaign_summary: summary,
          incident_summary: 'users redirected to fake login',
          evidence_refs: ['sha256:demo-evidence'],
        }),
      })
      setReportId(data.report_id)
      setCommitment(data.commitment)
      setTxHash(data.tx_hash || '')
      setResult(data)
    })
  }

  async function verifyStored() {
    await runStep('Verify Stored Commitment', async () => {
      const data = await call(`/threat-reports/${reportId}/verify`)
      setResult(data)
    })
  }

  async function revise() {
    await runStep('Revise Report', async () => {
      const data = await call(`/threat-reports/${reportId}/revise`, {
        method: 'POST',
        body: JSON.stringify({
          indicators: { domain, url },
          campaign_summary: `${summary} (revised)`,
          incident_summary: 'users redirected to fake login',
          evidence_refs: ['sha256:demo-evidence'],
        }),
      })
      setCommitment(data.commitment)
      setTxHash(data.tx_hash || '')
      setResult(data)
    })
  }

  async function dispute() {
    await runStep('Dispute Report', async () => {
      const data = await call(`/threat-reports/${reportId}/dispute`, {
        method: 'POST',
        body: JSON.stringify({ reason: 'possible false positive', disputant: 'reviewer-2' }),
      })
      setTxHash(data.tx_hash || '')
      setResult(data)
    })
  }

  async function validate() {
    await runStep('Validate Report', async () => {
      const data = await call(`/threat-reports/${reportId}/validate`, {
        method: 'POST',
        body: JSON.stringify({ verdict: true, validator: 'validator-1' }),
      })
      setTxHash(data.tx_hash || '')
      setResult(data)
    })
  }

  async function provenance() {
    await runStep('Provenance', async () => {
      const data = await call(`/threat-reports/${reportId}/provenance`)
      setResult(data)
    })
  }

  async function onchain() {
    await runStep('On-chain Public View', async () => {
      const data = await call(`/threat-reports/${reportId}/onchain`)
      setResult(data)
    })
  }

  return (
    <div className="app">
      <header>
        <h1>TrustLens — Decentralized Threat Intelligence Demo</h1>
        <p>End-to-end UI over the local Web3 registry.</p>
      </header>

      <section className="card">
        <h2>Report Input (stays off-chain)</h2>
        <label>Domain<input value={domain} onChange={(e) => setDomain(e.target.value)} /></label>
        <label>URL<input value={url} onChange={(e) => setUrl(e.target.value)} /></label>
        <label>Campaign Summary<input value={summary} onChange={(e) => setSummary(e.target.value)} /></label>
      </section>

      <section className="card">
        <h2>Workflow</h2>
        <div className="buttons">
          <button disabled={busy} onClick={createReport}>1. Create Report</button>
          <button disabled={busy || !reportId} onClick={verifyStored}>2. Verify</button>
          <button disabled={busy || !reportId} onClick={revise}>3. Revise</button>
          <button disabled={busy || !reportId} onClick={dispute}>4. Dispute</button>
          <button disabled={busy || !reportId} onClick={validate}>5. Validate</button>
          <button disabled={busy || !reportId} onClick={provenance}>6. Provenance</button>
          <button disabled={busy || !reportId} onClick={onchain}>7. On-chain View</button>
        </div>
        {reportId && (
          <div className="meta">
            <div><b>report_id:</b> {reportId}</div>
            <div><b>commitment:</b> {commitment}</div>
            <div><b>tx_hash:</b> {txHash}</div>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Result</h2>
        <pre>{result ? JSON.stringify(result, null, 2) : 'No result yet'}</pre>
      </section>

      <section className="card">
        <h2>Live Log</h2>
        <pre className="log">{logs.join('\n')}</pre>
      </section>
    </div>
  )
}
