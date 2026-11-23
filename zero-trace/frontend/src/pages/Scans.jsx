import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api, { errorMessage } from '../services/api'
import { Alert, Card, EmptyState, PageHeader, RiskBadge } from '../components/UI'
import Icon from '../components/Icon'

const formatDate = (value) => value ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—'

export default function Scans() {
  const [scans, setScans] = useState([])
  const [filter, setFilter] = useState('all')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/scans/', { params: { limit: 200 } })
      setScans(data)
    } catch (requestError) {
      setError(errorMessage(requestError, 'Unable to load scan history.'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const visible = filter === 'all' ? scans : scans.filter((scan) => scan.scan_type === filter)

  return (
    <>
      <PageHeader
        eyebrow="HISTORY"
        title="Scan History"
        description="Every analysis run in your workspace with its risk posture and finding count."
        action={<Link className="btn btn-primary" to="/scan/document"><Icon name="scan" size={16} /> New scan</Link>}
      />
      {error && <Alert tone="danger">{error}</Alert>}
      <Card>
        <div className="filter-bar">
          {['all', 'document', 'repository'].map((value) => (
            <button key={value} className={`filter-btn ${filter === value ? 'active' : ''}`} onClick={() => setFilter(value)}>
              {value[0].toUpperCase() + value.slice(1)}
            </button>
          ))}
          <span className="filter-count">{visible.length} result{visible.length === 1 ? '' : 's'}</span>
        </div>
        {loading ? (
          <div className="loading-panel"><span className="spinner" /> Loading scans…</div>
        ) : visible.length ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr><th>Source</th><th>Type</th><th>Status</th><th>Risk level</th><th>Score</th><th>Findings</th><th>Created</th><th /></tr>
              </thead>
              <tbody>
                {visible.map((scan) => (
                  <tr key={scan.id}>
                    <td><Link className="table-link" to={`/scans/${scan.id}`}>{scan.source_name}</Link></td>
                    <td><span className="tag">{scan.scan_type}</span></td>
                    <td><span className={`status status-${scan.status}`}>{scan.status}</span></td>
                    <td><RiskBadge level={scan.risk_level} /></td>
                    <td><strong>{scan.risk_score}</strong></td>
                    <td>{scan.finding_count ?? scan.summary?.total ?? 0}</td>
                    <td>{formatDate(scan.created_at)}</td>
                    <td><Link className="row-action" to={`/scans/${scan.id}`} aria-label="Open scan"><Icon name="arrow" size={16} /></Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No matching scans" message="Try another filter or start a new privacy scan." action={<Link className="btn btn-primary" to="/scan/document">Scan a document</Link>} />
        )}
      </Card>
    </>
  )
}
