import { useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import api, { errorMessage } from '../services/api'
import { Alert, Card, PageHeader } from '../components/UI'
import Icon from '../components/Icon'

export default function Settings() {
  const { user, setConsent } = useAuth()
  const [health, setHealth] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.get('/health/').then(({ data }) => setHealth(data)).catch(() => setHealth(null))
  }, [])

  const toggle = async () => {
    setBusy(true)
    setError('')
    try {
      await setConsent(!user.ai_consent)
    } catch (requestError) {
      setError(errorMessage(requestError, 'Unable to update consent.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="PRIVACY CONTROLS"
        title="Privacy Settings"
        description="Control optional AI analysis and review the active detection capabilities."
      />
      {error && <Alert tone="danger">{error}</Alert>}

      <div className="settings-grid">
        <Card title="External AI analysis" subtitle="Optional and disabled by default">
          <div className="consent-panel">
            <div className={`consent-toggle ${user?.ai_consent ? 'on' : ''}`}><span /></div>
            <div>
              <h3>Google Gemini risk narrative</h3>
              <p>
                When enabled, ZeroTrace sends only redacted finding metadata (category, severity, title, location and fingerprint reference)
                to the configured Gemini endpoint. Uploaded documents, raw secrets and file contents are never transmitted.
              </p>
              <button className="btn btn-primary" onClick={toggle} disabled={busy}>
                {busy ? 'Updating…' : user?.ai_consent ? 'Disable AI analysis' : 'Enable AI analysis'}
              </button>
            </div>
          </div>
          <Alert tone="info" title="Consent record">
            {user?.ai_consent_at ? `Opted in on ${new Date(user.ai_consent_at).toLocaleString()}.` : 'No external AI consent has been recorded.'}
          </Alert>
        </Card>

        <Card title="Detection engines" subtitle="Current backend capability report">
          <ul className="engine-list">
            <li><span className="engine-dot" /> Regex + entropy secret detection <strong>Active</strong></li>
            <li><span className="engine-dot" /> PyMuPDF / python-docx extraction <strong>Active</strong></li>
            <li><span className={`engine-dot ${health?.detectors?.spacy_model_loaded ? '' : 'inactive'}`} /> spaCy NER <strong>{health?.detectors?.spacy_model_loaded ? 'Active' : 'Pattern fallback'}</strong></li>
            <li><span className="engine-dot" /> GitHub REST API scanner <strong>Active</strong></li>
            <li><span className={`engine-dot ${health?.gitleaks_available ? '' : 'inactive'}`} /> Gitleaks integration <strong>{health?.gitleaks_available ? 'Ready' : 'Not installed'}</strong></li>
          </ul>
          <p className="muted small">Model: {health?.detectors?.model || 'not reported'}</p>
        </Card>

        <Card title="Data minimisation" subtitle="How ZeroTrace handles your information">
          <ul className="check-list">
            <li><Icon name="check" size={14} /> Uploaded files are read in memory and never written to storage</li>
            <li><Icon name="check" size={14} /> Only redacted evidence and SHA-256 fingerprints are persisted</li>
            <li><Icon name="check" size={14} /> Access tokens are replaced with one-way fingerprints</li>
            <li><Icon name="check" size={14} /> Repository scans require a fresh explicit authorization flag</li>
            <li><Icon name="check" size={14} /> PDF reports contain redacted evidence only</li>
          </ul>
        </Card>

        <Card title="API access" subtitle="Integrate ZeroTrace with your tooling">
          <p className="muted">All endpoints are available under <code className="mono">/api/</code> and use Django REST token authentication.</p>
          <div className="endpoint-list mono">
            <span>POST /api/scans/documents/</span>
            <span>POST /api/scans/repositories/</span>
            <span>GET /api/dashboard/</span>
            <span>GET /api/scans/&lt;id&gt;/report/</span>
          </div>
        </Card>
      </div>
    </>
  )
}
