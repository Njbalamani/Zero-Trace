import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import api, { errorMessage } from '../services/api'
import { Alert, Card, PageHeader, RiskBadge, SeverityPill } from '../components/UI'
import Icon from '../components/Icon'

const formatDate = (value) => value ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—'

export default function ScanDetail() {
  const { id } = useParams()
  const [scan, setScan] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [severityFilter, setSeverityFilter] = useState('all')
  const [downloading, setDownloading] = useState(false)
  const [reviewing, setReviewing] = useState(null)

  useEffect(() => {
    let active = true
    const load = async () => {
      setLoading(true)
      try {
        const { data } = await api.get(`/scans/${id}/`)
        if (active) setScan(data)
      } catch (requestError) {
        if (active) setError(errorMessage(requestError, 'Unable to load scan.'))
      } finally {
        if (active) setLoading(false)
      }
    }
    load()
    return () => { active = false }
  }, [id])

  const download = async () => {
    setDownloading(true)
    try {
      await api.downloadReport(id)
    } catch (requestError) {
      setError(errorMessage(requestError, 'Unable to download report.'))
    } finally {
      setDownloading(false)
    }
  }

  const reviewFinding = async (findingId, falsePositive) => {
    setReviewing(findingId)
    setError('')
    try {
      const { data } = await api.post(`/findings/${findingId}/review/`, { false_positive: falsePositive })
      setScan(data)
    } catch (requestError) {
      setError(errorMessage(requestError, 'Unable to update finding review.'))
    } finally {
      setReviewing(null)
    }
  }

  if (loading) return <div className="loading-panel"><span className="spinner" /> Loading scan report…</div>
  if (!scan) return <><PageHeader title="Scan not found" /><Alert tone="danger">{error || 'This scan does not exist or is not accessible.'}</Alert><Link className="btn btn-ghost" to="/scans">Back to history</Link></>

  const findings = severityFilter === 'all' ? scan.findings : scan.findings.filter((item) => item.severity === severityFilter)
  const metadata = scan.metadata || {}

  return (
    <>
      <PageHeader
        eyebrow={`${scan.scan_type.toUpperCase()} SCAN`}
        title={scan.source_name}
        description={`Created ${formatDate(scan.created_at)} · Status: ${scan.status}`}
        action={
          <div className="header-actions">
            <RiskBadge level={scan.risk_level} />
            <button className="btn btn-ghost" onClick={download} disabled={downloading}>
              <Icon name="download" size={16} /> {downloading ? 'Preparing…' : 'Download PDF report'}
            </button>
          </div>
        }
      />

      {error && <Alert tone="danger">{error}</Alert>}
      {scan.status === 'failed' && <Alert tone="danger" title="Scan failed">{scan.error_message}</Alert>}

      <div className="detail-grid">
        <Card title="Risk assessment" subtitle="Aggregate score derived from severity-weighted findings">
          <div className="risk-hero">
            <div className="risk-score-ring" style={{ '--score': `${scan.risk_score * 3.6}deg` }}>
              <div><strong>{scan.risk_score}</strong><span>/100</span></div>
            </div>
            <div className="risk-copy">
              <RiskBadge level={scan.risk_level} />
              <p>{scan.summary?.total || 0} findings detected across {Object.keys(scan.summary?.by_category || {}).length} categories.</p>
              <div className="risk-mini-grid">
                {Object.entries(scan.summary?.by_severity || {}).map(([level, count]) => (
                  <div key={level}><span>{level}</span><strong>{count}</strong></div>
                ))}
              </div>
            </div>
          </div>
          {scan.ai_summary && (
            <div className="ai-summary">
              <div className="ai-summary-head"><Icon name="bulb" size={16} /><strong>AI privacy assessment</strong><span className="tag">{scan.ai_used ? 'Gemini enabled' : 'Deterministic engine'}</span></div>
              <p>{scan.ai_summary}</p>
            </div>
          )}
        </Card>

        <Card title="Scan context" subtitle="Non-sensitive technical details">
          <dl className="meta-list">
            <div><dt>Scan ID</dt><dd className="mono">{scan.id}</dd></div>
            <div><dt>Type</dt><dd>{scan.scan_type}</dd></div>
            <div><dt>MIME type</dt><dd>{scan.mime_type || '—'}</dd></div>
            <div><dt>Processed bytes</dt><dd>{scan.size_bytes?.toLocaleString() || 0}</dd></div>
            <div><dt>Source hash</dt><dd className="mono">{scan.source_hash ? `${scan.source_hash.slice(0, 16)}…` : '—'}</dd></div>
            <div><dt>Completed</dt><dd>{formatDate(scan.completed_at)}</dd></div>
            {scan.scan_type === 'repository' && (
              <>
                <div><dt>Files scanned</dt><dd>{metadata.files_scanned || 0}</dd></div>
                <div><dt>Files skipped</dt><dd>{metadata.files_skipped || 0}</dd></div>
                <div><dt>Gitleaks</dt><dd>{metadata.gitleaks_available ? 'Available' : 'Not installed'}</dd></div>
                <div><dt>Branch</dt><dd>{metadata.default_branch || '—'}</dd></div>
              </>
            )}
            {scan.scan_type === 'document' && (
              <>
                <div><dt>Pages / paragraphs</dt><dd>{metadata.page_count ?? metadata.paragraph_count ?? '—'}</dd></div>
                <div><dt>Metadata fields</dt><dd>{metadata.metadata_fields_present?.length || 0}</dd></div>
              </>
            )}
          </dl>
        </Card>
      </div>

      <Card
        title={`Findings (${scan.findings.length})`}
        subtitle="All evidence is redacted; raw values are never stored or returned."
        action={
          <div className="filter-bar compact">
            {['all', 'critical', 'high', 'medium', 'low'].map((level) => (
              <button key={level} className={`filter-btn ${severityFilter === level ? 'active' : ''}`} onClick={() => setSeverityFilter(level)}>{level}</button>
            ))}
          </div>
        }
      >
        {findings.length ? (
          <div className="finding-list">
            {findings.map((finding) => (
              <details className="finding-item" key={finding.id}>
                <summary>
                  <SeverityPill severity={finding.severity} />
                  <div className="finding-main">
                    <strong>{finding.title}</strong>
                    <span className="mono">{finding.redacted_evidence}</span>
                  </div>
                  <span className="tag">{finding.category.replace('_', ' ')}</span>
                  {finding.false_positive && <span className="tag dismissed">dismissed</span>}
                  <small className="mono">{finding.location}</small>
                  <Icon name="arrow" size={15} className="chevron" />
                </summary>
                <div className="finding-detail">
                  <div><h4>Why it matters</h4><p>{finding.explanation}</p></div>
                  <div><h4>Recommended action</h4><p>{finding.remediation}</p></div>
                  {finding.redacted_context && <div><h4>Redacted context</h4><p className="mono context-line">{finding.redacted_context}</p></div>}
                  <div className="finding-meta">
                    <span>Engine: {finding.source_tool}</span>
                    <span>Confidence: {Math.round(finding.confidence * 100)}%</span>
                    <button
                      className="btn btn-ghost btn-mini"
                      disabled={reviewing === finding.id}
                      onClick={() => reviewFinding(finding.id, !finding.false_positive)}
                    >
                      {finding.false_positive ? 'Restore finding' : 'Mark as false positive'}
                    </button>
                  </div>
                </div>
              </details>
            ))}
          </div>
        ) : (
          <div className="empty-inline"><Icon name="check" size={20} /><span>No findings match this filter.</span></div>
        )}
      </Card>

      <Card title="Remediation plan" subtitle="Actions ordered by priority">
        <ol className="remediation-list">
          {scan.recommendations.map((item) => (
            <li key={item.id}>
              <span className="priority">P{item.priority}</span>
              <div><strong>{item.title}</strong><p>{item.description}</p></div>
            </li>
          ))}
        </ol>
      </Card>
    </>
  )
}
