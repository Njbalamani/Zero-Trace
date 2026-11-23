import { useEffect, useState } from 'react'
import api, { errorMessage } from '../services/api'
import { Alert, Card, EmptyState, PageHeader } from '../components/UI'
import Icon from '../components/Icon'

const actionLabels = {
  login: 'Signed in',
  ai_consent_changed: 'AI consent updated',
  document_scan: 'Document scanned',
  document_scan_failed: 'Document scan failed',
  batch_document_scan: 'Batch scan completed',
  document_sanitized: 'Document sanitized',
  repository_scan: 'Repository scanned',
  repository_scan_failed: 'Repository scan failed',
  finding_reviewed: 'Finding reviewed',
}

export default function Audit() {
  const [events, setEvents] = useState([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const { data } = await api.get('/audit/')
        if (active) setEvents(data)
      } catch (requestError) {
        if (active) setError(errorMessage(requestError, 'Unable to load audit trail.'))
      } finally {
        if (active) setLoading(false)
      }
    }
    load()
    return () => { active = false }
  }, [])

  return (
    <>
      <PageHeader
        eyebrow="ACCOUNTABILITY"
        title="Audit Trail"
        description="Privacy-safe activity log for scans, consent changes, sanitization and finding reviews."
      />
      {error && <Alert tone="danger">{error}</Alert>}
      <Card>
        {loading ? (
          <div className="loading-panel"><span className="spinner" /> Loading activity…</div>
        ) : events.length ? (
          <div className="table-scroll">
            <table className="data-table audit-table">
              <thead><tr><th>Event</th><th>Target</th><th>Details</th><th>Time</th></tr></thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id}>
                    <td><span className="audit-action"><Icon name={event.action.includes('failed') ? 'alert' : 'check'} size={14} /> {actionLabels[event.action] || event.action}</span></td>
                    <td className="mono">{event.target || '—'}</td>
                    <td>
                      {Object.entries(event.metadata || {}).map(([key, value]) => (
                        <span className="audit-meta" key={key}>{key}: <strong>{String(value)}</strong></span>
                      ))}
                      {!Object.keys(event.metadata || {}).length && <span className="muted">—</span>}
                    </td>
                    <td>{new Date(event.created_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No activity recorded" message="Actions such as scans and consent changes will appear here." />
        )}
      </Card>
    </>
  )
}
