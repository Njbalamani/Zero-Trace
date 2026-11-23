import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import api, { errorMessage } from '../services/api'
import { Alert, Card, PageHeader, RiskBadge, ScanProgress, SeverityPill } from '../components/UI'
import Icon from '../components/Icon'

const STEPS = [
  'Verifying token and repository access',
  'Enumerating authorised files',
  'Scanning source content',
  'Running Gitleaks engine',
]

export default function RepositoryScan() {
  const [form, setForm] = useState({ repository: '', token: '', authorize: false })
  const [busy, setBusy] = useState(false)
  const [stage, setStage] = useState(0)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const timer = useRef(null)

  useEffect(() => () => clearInterval(timer.current), [])

  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }))

  const submit = async (event) => {
    event.preventDefault()
    if (!form.authorize || busy) return
    setBusy(true)
    setError('')
    setResult(null)
    setStage(0)
    timer.current = setInterval(() => setStage((current) => Math.min(current + 1, STEPS.length - 1)), 1100)
    try {
      const { data } = await api.post('/scans/repositories/', form)
      setResult(data)
      setForm((current) => ({ ...current, token: '' }))
    } catch (requestError) {
      setError(errorMessage(requestError, 'Repository scan failed.'))
    } finally {
      clearInterval(timer.current)
      setBusy(false)
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="MODULE 02"
        title="Authorised Repository Scanner"
        description="Find accidentally committed API keys, hardcoded credentials and exposed configuration secrets in repositories you own."
      />

      <Alert tone="danger" title="Authorization is mandatory">
        ZeroTrace never scans a repository without your explicit confirmation. Access tokens are used only for this request; only a one-way fingerprint is stored.
      </Alert>

      <div className="scan-layout">
        <div>
          {busy ? (
            <Card><ScanProgress step={stage} steps={STEPS} label="Scanning repository" /></Card>
          ) : (
            <Card title="Repository details" subtitle="Use a token with read access to the target repository.">
              <form onSubmit={submit} className="stack-form">
                <label>
                  <span>Repository</span>
                  <input value={form.repository} onChange={(event) => update('repository', event.target.value)} placeholder="owner/repository" pattern="[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+" required />
                  <small>Must be in owner/repository format.</small>
                </label>
                <label>
                  <span>GitHub access token</span>
                  <input type="password" value={form.token} onChange={(event) => update('token', event.target.value)} placeholder="ghp_..." required minLength={10} autoComplete="off" />
                  <small>The token is never written to the database, logs or reports.</small>
                </label>
                <label className="checkbox-line">
                  <input type="checkbox" checked={form.authorize} onChange={(event) => update('authorize', event.target.checked)} required />
                  <span>I confirm I own or am explicitly authorised to scan this repository.</span>
                </label>
                {error && <Alert tone="danger">{error}</Alert>}
                <button className="btn btn-primary" disabled={!form.authorize || !form.repository || !form.token}>
                  <Icon name="github" size={16} /> Authorise and scan
                </button>
              </form>
            </Card>
          )}

          {result && (
            <Card
              title="Repository scan complete"
              subtitle={`${result.metadata?.files_scanned || 0} files scanned · ${result.source_name}`}
              action={<RiskBadge level={result.risk_level} />}
              className="result-card"
            >
              <div className="result-summary">
                <div><span>Risk score</span><strong>{result.risk_score}/100</strong></div>
                <div><span>Findings</span><strong>{result.summary.total}</strong></div>
                <div><span>Critical</span><strong className="critical-text">{result.summary.critical_count}</strong></div>
                <div><span>Gitleaks</span><strong>{result.metadata?.gitleaks_available ? 'Active' : 'Not installed'}</strong></div>
              </div>
              {result.findings.length > 0 && (
                <div className="finding-preview">
                  <h3>Top detections</h3>
                  {result.findings.slice(0, 6).map((finding) => (
                    <div className="finding-row" key={finding.id}>
                      <SeverityPill severity={finding.severity} />
                      <div><strong>{finding.title}</strong><span>{finding.redacted_evidence}</span></div>
                      <small>{finding.location}</small>
                    </div>
                  ))}
                </div>
              )}
              <div className="form-actions">
                <Link className="btn btn-primary" to={`/scans/${result.id}`}>Open full report <Icon name="arrow" size={16} /></Link>
                <button className="btn btn-ghost" onClick={() => api.downloadReport(result.id)}><Icon name="download" size={16} /> Download PDF</button>
              </div>
            </Card>
          )}
        </div>

        <aside className="scan-aside">
          <Card title="How scanning works">
            <ol className="numbered-list">
              <li>Validate token and confirm access.</li>
              <li>Enumerate text and configuration files in the repository tree.</li>
              <li>Run regex, entropy and Gitleaks engines on fetched content.</li>
              <li>Store only redacted evidence, fingerprints and file locations.</li>
            </ol>
          </Card>
          <Card title="Engine limits">
            <ul className="check-list muted-list">
              <li><Icon name="lock" size={14} /> No force-push or write operations</li>
              <li><Icon name="lock" size={14} /> No repository cloning outside temp storage</li>
              <li><Icon name="lock" size={14} /> Binary and large files are skipped</li>
              <li><Icon name="lock" size={14} /> Token plaintext never persisted</li>
            </ul>
          </Card>
        </aside>
      </div>
    </>
  )
}
