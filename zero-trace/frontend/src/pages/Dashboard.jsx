import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api, { errorMessage } from '../services/api'
import { RiskDoughnut, RiskTrendLine, SeverityBar, TrendLine } from '../components/Charts'
import { Alert, Card, EmptyState, PageHeader, RiskBadge, StatCard } from '../components/UI'
import Icon from '../components/Icon'

const formatDate = (value) => value ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—'

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const { data: payload } = await api.get('/dashboard/')
      setData(payload)
    } catch (requestError) {
      setError(errorMessage(requestError, 'Unable to load dashboard.'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const totals = data?.totals || {}

  return (
    <>
      <PageHeader
        eyebrow="OVERVIEW"
        title="Privacy Dashboard"
        description="A consolidated view of exposures, severity and remediation progress across your workspace."
        action={<button className="btn btn-ghost" onClick={load}><Icon name="scan" size={16} /> Refresh</button>}
      />

      {error && <Alert tone="danger" title="Dashboard unavailable">{error}</Alert>}

      {loading && !data ? (
        <div className="loading-panel"><span className="spinner" /> Loading privacy telemetry…</div>
      ) : data ? (
        <>
          <div className="stat-grid">
            <StatCard icon="file" label="Documents scanned" value={totals.documents || 0} hint={`${totals.scans || 0} total scans`} tone="teal" />
            <StatCard icon="list" label="Privacy findings" value={totals.findings || 0} hint={`${totals.high || 0} high severity`} tone="blue" />
            <StatCard icon="alert" label="Critical exposures" value={totals.critical || 0} hint={totals.critical ? 'Immediate action required' : 'No critical findings'} tone="red" />
            <StatCard icon="github" label="Repositories scanned" value={totals.repositories || 0} hint="Explicitly authorised only" tone="violet" />
          </div>

          <div className="chart-grid">
            <Card title="Risk distribution" subtitle="Completed scans grouped by overall risk level">
              <RiskDoughnut distribution={data.risk_distribution} />
            </Card>
            <Card title="Finding severity" subtitle="All non-dismissed findings by severity">
              <SeverityBar distribution={data.severity_distribution} />
            </Card>
            <Card title="Scan activity" subtitle="Scans performed over the last seven days">
              <TrendLine trend={data.scan_trend} />
            </Card>
            <Card title="Risk score timeline" subtitle="Last 12 completed scans (0–100)">
              <RiskTrendLine timeline={data.risk_timeline} />
            </Card>
          </div>

          <div className="lower-grid">
            <Card title="Recent scan activity" subtitle="Latest analysis results" action={<Link className="link-btn" to="/scans">View all <Icon name="arrow" size={14} /></Link>}>
              {data.recent_scans.length ? (
                <div className="table-scroll">
                  <table className="data-table">
                    <thead>
                      <tr><th>Source</th><th>Type</th><th>Risk</th><th>Findings</th><th>Scanned</th></tr>
                    </thead>
                    <tbody>
                      {data.recent_scans.map((scan) => (
                        <tr key={scan.id}>
                          <td><Link className="table-link" to={`/scans/${scan.id}`}>{scan.source_name}</Link></td>
                          <td><span className="tag">{scan.scan_type}</span></td>
                          <td><RiskBadge level={scan.risk_level} /></td>
                          <td>{scan.finding_count ?? scan.summary?.total ?? 0}</td>
                          <td>{formatDate(scan.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <EmptyState
                  title="No scans yet"
                  message="Upload a PDF/DOCX or scan an authorised repository to populate your dashboard."
                  action={<Link className="btn btn-primary" to="/scan/document">Start a scan</Link>}
                />
              )}
            </Card>

            <div className="side-stack">
              <Card title="Privacy improvement" subtitle="Recent vs earlier scan risk scores">
                <div className="improvement">
                  <strong className={data.privacy_improvement.percent >= 0 ? 'positive' : 'negative'}>
                    {data.privacy_improvement.percent > 0 ? '+' : ''}{data.privacy_improvement.percent}%
                  </strong>
                  <p>{data.privacy_improvement.interpretation}</p>
                </div>
              </Card>
              <Card title="Quick actions" subtitle="Launch a new analysis">
                <div className="quick-actions">
                  <Link to="/scan/document"><Icon name="file" size={18} /><span><strong>Scan a document</strong><small>PDF or DOCX privacy check</small></span></Link>
                  <Link to="/scan/repository"><Icon name="github" size={18} /><span><strong>Scan a repository</strong><small>Secrets in authorised code</small></span></Link>
                  <Link to="/recommendations"><Icon name="bulb" size={18} /><span><strong>Review guidance</strong><small>Prioritised remediation</small></span></Link>
                </div>
              </Card>
            </div>
          </div>
        </>
      ) : null}
    </>
  )
}
