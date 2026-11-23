import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api, { errorMessage } from '../services/api'
import { Alert, Card, EmptyState, PageHeader } from '../components/UI'
import Icon from '../components/Icon'

export default function Recommendations() {
  const [items, setItems] = useState([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const { data } = await api.get('/recommendations/')
        if (active) setItems(data)
      } catch (requestError) {
        if (active) setError(errorMessage(requestError, 'Unable to load recommendations.'))
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
        eyebrow="MODULE 05"
        title="Privacy Recommendations"
        description="Prioritised remediation guidance generated from your scan findings."
      />
      {error && <Alert tone="danger">{error}</Alert>}
      {loading ? (
        <div className="loading-panel"><span className="spinner" /> Loading guidance…</div>
      ) : items.length ? (
        <div className="recommendation-grid">
          {items.map((item) => (
            <Card key={item.id} className="recommendation-card">
              <div className="recommendation-top">
                <span className="priority">P{item.priority}</span>
                <span className="tag">{item.category}</span>
              </div>
              <h3>{item.title}</h3>
              <p>{item.description}</p>
              <Link className="link-btn" to={`/scans/${item.scan_id}`}>View source scan <Icon name="arrow" size={14} /></Link>
            </Card>
          ))}
        </div>
      ) : (
        <Card><EmptyState title="No recommendations yet" message="Run a scan to receive tailored privacy remediation steps." action={<Link className="btn btn-primary" to="/scan/document">Start scanning</Link>} /></Card>
      )}
    </>
  )
}
