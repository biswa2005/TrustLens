import { useState } from 'react'
import './App.css'

const API = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '')

async function request(path, options = {}) {
  const res = await fetch(`${API}${path}`, options)
  const text = await res.text()
  let data
  try {
    data = JSON.parse(text)
  } catch {
    data = text
  }
  if (!res.ok) throw new Error(typeof data === 'object' ? (data.detail || JSON.stringify(data)) : text)
  return data
}

const pretty = (value) => JSON.stringify(value, null, 2)

export default function App() {
  const [tab, setTab] = useState('health')
  const [health, setHealth] = useState(null)
  const [messageText, setMessageText] = useState('Your KYC is pending. Click this link to verify your account now.')
  const [messageSender, setMessageSender] = useState('+91-9999999999')
  const [report, setReport] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const [registryDomain, setRegistryDomain] = useState('evil-paypal.example')
  const [registryUrl, setRegistryUrl] = useState('http://evil-paypal.example/login')
  const [registrySummary, setRegistrySummary] = useState('credential harvesting phishing')
  const [reportId, setReportId] = useState('')
  const [commitment, setCommitment] = useState('')
  const [txHash, setTxHash] = useState('')
  const [registryResult, setRegistryResult] = useState(null)

  const [investigations, setInvestigations] = useState([])
  const [selectedInvestigation, setSelectedInvestigation] = useState(null)

  async function run(fn) {
    setBusy(true)
    setError('')
    try {
      await fn()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function checkHealth() {
    const data = await request('/api/v1/health')
    setHealth(data)
  }

  async function analyzeMessage() {
    const data = await request('/api/v1/messages/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: messageText,
        sender: messageSender,
        channel: 'sms',
        language: 'auto',
      }),
    })
    setReport(data)
  }

  async function loadInvestigations() {
    const data = await request('/api/v1/investigations?limit=20')
    setInvestigations(data)
  }

  async function openInvestigation(id) {
    const data = await request(`/api/v1/investigations/${id}`)
    setSelectedInvestigation(data)
  }

  async function verifyInvestigation(id) {
    const data = await request(`/api/v1/investigations/${id}/verify`, { method: 'POST' })
    setSelectedInvestigation((prev) => (prev ? { ...prev, verification: data } : prev))
  }

  async function analyzeImage(endpoint, file) {
    const form = new FormData()
    form.append('image', file)
    const data = await request(endpoint, { method: 'POST', body: form })
    setReport(data)
  }

  async function analyzeEmail(file) {
    const form = new FormData()
    form.append('eml', file)
    const data = await request('/api/v1/email/analyze', { method: 'POST', body: form })
    setReport(data)
  }

  async function createThreatReport() {
    const data = await request('/api/v1/threat-reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        reporter_pseudonym: 'demo-analyst',
        indicators: { domain: registryDomain, url: registryUrl },
        campaign_summary: registrySummary,
        incident_summary: 'users redirected to fake login',
        evidence_refs: ['sha256:demo-evidence'],
      }),
    })
    setReportId(data.report_id)
    setCommitment(data.commitment)
    setTxHash(data.tx_hash || '')
    setRegistryResult(data)
  }

  async function verifyThreatReport() {
    const data = await request(`/api/v1/threat-reports/${reportId}/verify`)
    setRegistryResult(data)
  }

  async function reviseThreatReport() {
    const data = await request(`/api/v1/threat-reports/${reportId}/revise`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        indicators: { domain: registryDomain, url: registryUrl },
        campaign_summary: `${registrySummary} (revised)`,
        incident_summary: 'users redirected to fake login',
        evidence_refs: ['sha256:demo-evidence'],
      }),
    })
    setCommitment(data.commitment)
    setTxHash(data.tx_hash || '')
    setRegistryResult(data)
  }

  async function disputeThreatReport() {
    const data = await request(`/api/v1/threat-reports/${reportId}/dispute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: 'possible false positive', disputant: 'reviewer-2' }),
    })
    setTxHash(data.tx_hash || '')
    setRegistryResult(data)
  }

  async function validateThreatReport() {
    const data = await request(`/api/v1/threat-reports/${reportId}/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verdict: true, validator: 'validator-1' }),
    })
    setTxHash(data.tx_hash || '')
    setRegistryResult(data)
  }

  async function provenanceThreatReport() {
    const data = await request(`/api/v1/threat-reports/${reportId}/provenance`)
    setRegistryResult(data)
  }

  async function viewOnChain() {
    const data = await request(`/api/v1/threat-reports/${reportId}/onchain`)
    setRegistryResult(data)
  }

  return (
    <div className="app-shell">
      <header>
        <h1>TrustLens Forensics Console</h1>
        <p>Evidence-first investigation dashboard wired to the backend API.</p>
        <p><strong>API:</strong> {API}</p>
      </header>

      <nav className="tabs">
        {['health', 'message', 'qr', 'visual', 'email', 'investigations', 'registry'].map((item) => (
          <button key={item} className={tab === item ? 'active' : ''} onClick={() => setTab(item)}>
            {item}
          </button>
        ))}
      </nav>

      {error && <div className="error">{error}</div>}

      {tab === 'health' && (
        <section className="card">
          <h2>Backend Health</h2>
          <button disabled={busy} onClick={() => run(checkHealth)}>Check Health</button>
          <pre>{health ? pretty(health) : 'No health result yet'}</pre>
        </section>
      )}

      {tab === 'message' && (
        <section className="card">
          <h2>Message Investigation</h2>
          <label>Message text<textarea value={messageText} onChange={(e) => setMessageText(e.target.value)} /></label>
          <label>Sender<input value={messageSender} onChange={(e) => setMessageSender(e.target.value)} /></label>
          <button disabled={busy} onClick={() => run(analyzeMessage)}>Analyze Message</button>
          {report && <pre>{pretty(report)}</pre>}
        </section>
      )}

      {tab === 'qr' && (
        <section className="card">
          <h2>QR Investigation</h2>
          <input type="file" accept="image/*" onChange={(e) => {
            const file = e.target.files?.[0]
            if (file) run(() => analyzeImage('/api/v1/qr/analyze', file))
          }} />
          {report && <pre>{pretty(report)}</pre>}
        </section>
      )}

      {tab === 'visual' && (
        <section className="card">
          <h2>Visual Investigation</h2>
          <input type="file" accept="image/*" onChange={(e) => {
            const file = e.target.files?.[0]
            if (file) run(() => analyzeImage('/api/v1/visual/analyze', file))
          }} />
          {report && <pre>{pretty(report)}</pre>}
        </section>
      )}

      {tab === 'email' && (
        <section className="card">
          <h2>Email Investigation</h2>
          <input type="file" accept=".eml,message/rfc822" onChange={(e) => {
            const file = e.target.files?.[0]
            if (file) run(() => analyzeEmail(file))
          }} />
          {report && <pre>{pretty(report)}</pre>}
        </section>
      )}

      {tab === 'investigations' && (
        <section className="card">
          <h2>Stored Investigations</h2>
          <button disabled={busy} onClick={() => run(loadInvestigations)}>Load Recent</button>
          <ul>
            {investigations.map((item) => (
              <li key={item.id}>
                <button onClick={() => run(() => openInvestigation(item.id))}>{item.id}</button>
                <span> {item.module || 'investigation'}</span>
              </li>
            ))}
          </ul>
          {selectedInvestigation && (
            <>
              <button disabled={busy} onClick={() => run(() => verifyInvestigation(selectedInvestigation.id))}>
                Verify Evidence Chain
              </button>
              <pre>{pretty(selectedInvestigation)}</pre>
            </>
          )}
        </section>
      )}

      {tab === 'registry' && (
        <section className="card">
          <h2>Threat Report Registry</h2>
          <label>Domain<input value={registryDomain} onChange={(e) => setRegistryDomain(e.target.value)} /></label>
          <label>URL<input value={registryUrl} onChange={(e) => setRegistryUrl(e.target.value)} /></label>
          <label>Summary<textarea value={registrySummary} onChange={(e) => setRegistrySummary(e.target.value)} /></label>
          <div className="buttons">
            <button disabled={busy} onClick={() => run(createThreatReport)}>Submit Report</button>
            <button disabled={busy || !reportId} onClick={() => run(verifyThreatReport)}>Check Integrity</button>
            <button disabled={busy || !reportId} onClick={() => run(reviseThreatReport)}>Update Report</button>
            <button disabled={busy || !reportId} onClick={() => run(disputeThreatReport)}>Challenge Report</button>
            <button disabled={busy || !reportId} onClick={() => run(validateThreatReport)}>Validate Report</button>
            <button disabled={busy || !reportId} onClick={() => run(provenanceThreatReport)}>View History</button>
            <button disabled={busy || !reportId} onClick={() => run(viewOnChain)}>Public Record</button>
          </div>
          {reportId && (
            <div className="meta">
              <div><b>Report ID:</b> {reportId}</div>
              <div><b>Fingerprint:</b> {commitment}</div>
              <div><b>Latest transaction:</b> {txHash || 'pending'}</div>
            </div>
          )}
          <pre>{registryResult ? pretty(registryResult) : 'No registry activity yet'}</pre>
        </section>
      )}
    </div>
  )
}