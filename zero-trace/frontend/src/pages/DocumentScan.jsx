import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import api, { errorMessage } from '../services/api'
import { Alert, Card, PageHeader, RiskBadge, ScanProgress, SeverityPill } from '../components/UI'
import Icon from '../components/Icon'

function ResultCard({ result }) {
  return (
    <Card
      title="Scan complete"
      subtitle={`Source: ${result.source_name}`}
      action={<RiskBadge level={result.risk_level} />}
      className="result-card"
    >
      <div className="result-summary">
        <div><span>Risk score</span><strong>{result.risk_score}/100</strong></div>
        <div><span>Findings</span><strong>{result.summary.total}</strong></div>
        <div><span>Critical</span><strong className="critical-text">{result.summary.critical_count}</strong></div>
        <div><span>Engines</span><strong>{result.metadata?.detector_status?.spacy_model_loaded ? 'NLP + Regex' : 'Regex'}</strong></div>
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
  )
}

export default function DocumentScan() {
  const [files, setFiles] = useState([])
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)
  const [stage, setStage] = useState(0)
  const [error, setError] = useState('')
  const [results, setResults] = useState([])
  const [failed, setFailed] = useState([])
  const timer = useRef(null)

  useEffect(() => () => clearInterval(timer.current), [])

  const choose = (list) => {
    const incoming = Array.from(list || [])
    if (!incoming.length) return
    const invalid = incoming.filter((item) => !['pdf', 'docx'].includes(item.name.split('.').pop()?.toLowerCase()))
    const valid = incoming.filter((item) => !invalid.includes(item)).slice(0, 10)
    if (invalid.length) setError(`${invalid.length} file(s) skipped. Only PDF and DOCX are supported.`)
    else if (incoming.length > 10) setError('Maximum 10 files per batch. Extra files were skipped.')
    else setError('')
    setResults([])
    setFailed([])
    setFiles(valid)
  }

  const submit = async (event) => {
    event.preventDefault()
    if (!files.length || busy) return
    setBusy(true)
    setError('')
    setResults([])
    setFailed([])
    setStage(0)
    timer.current = setInterval(() => setStage((current) => Math.min(current + 1, 3)), 900)

    const form = new FormData()
    const batch = files.length > 1
    if (batch) files.forEach((file) => form.append('files', file))
    else form.append('file', files[0])

    try {
      const { data } = await api.post(
        batch ? '/scans/documents/batch/' : '/scans/documents/',
        form,
        { headers: { 'Content-Type': 'multipart/form-data' } },
      )
      setResults(batch ? data.completed : [data])
      setFailed(batch ? data.failed : [])
    } catch (requestError) {
      setError(errorMessage(requestError, 'Document scan failed.'))
    } finally {
      clearInterval(timer.current)
      setBusy(false)
    }
  }

  const totalSize = files.reduce((total, file) => total + file.size, 0)

  return (
    <>
      <PageHeader
        eyebrow="MODULE 01"
        title="Document Privacy Scanner"
        description="Detect exposed identifiers, secrets, confidential markers and risky metadata inside your own PDF and DOCX files. Scan up to 10 files at once."
      />

      <div className="scan-layout">
        <div>
          {busy ? (
            <Card><ScanProgress step={stage} label={`Analysing ${files.length} document${files.length === 1 ? '' : 's'}`} /></Card>
          ) : (
            <Card title="Upload documents" subtitle="Files are processed in memory and discarded immediately.">
              <form onSubmit={submit}>
                <div
                  className={`dropzone ${dragging ? 'dragging' : ''} ${files.length ? 'has-file' : ''}`}
                  onDragOver={(event) => { event.preventDefault(); setDragging(true) }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={(event) => {
                    event.preventDefault()
                    setDragging(false)
                    choose(event.dataTransfer.files)
                  }}
                >
                  <input
                    id="document-input"
                    type="file"
                    multiple
                    accept=".pdf,.docx,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    onChange={(event) => choose(event.target.files)}
                  />
                  <label htmlFor="document-input">
                    <span className="drop-icon"><Icon name="file" size={28} /></span>
                    {files.length ? (
                      <>
                        <strong>{files.length} file{files.length === 1 ? '' : 's'} ready</strong>
                        <p>{(totalSize / 1024).toFixed(1)} KB total · Click to replace selection</p>
                        <div className="file-chips">
                          {files.map((file) => <span key={`${file.name}-${file.size}`}>{file.name}</span>)}
                        </div>
                      </>
                    ) : (
                      <>
                        <strong>Drop PDF or DOCX files here</strong>
                        <p>or click to browse · up to 10 files · 20 MB each</p>
                      </>
                    )}
                  </label>
                </div>
                {error && <Alert tone="danger">{error}</Alert>}
                <div className="form-actions">
                  <button className="btn btn-primary" disabled={!files.length}>
                    <Icon name="scan" size={16} /> Run privacy scan{files.length > 1 ? ` (${files.length})` : ''}
                  </button>
                  {files.length > 0 && <button type="button" className="btn btn-ghost" onClick={() => { setFiles([]); setResults([]); setFailed([]); setError('') }}>Clear</button>}
                </div>
              </form>
            </Card>
          )}

          {failed.length > 0 && (
            <Card title="Files that could not be scanned" className="result-card">
              {failed.map((item, index) => (
                <div className="failed-row" key={`${item.source_name}-${index}`}>
                  <Icon name="alert" size={15} />
                  <span>{item.source_name}</span>
                  <small>{item.error}</small>
                </div>
              ))}
            </Card>
          )}

          {results.map((result) => <ResultCard key={result.id} result={result} />)}
        </div>

        <aside className="scan-aside">
          <Card title="What this scanner checks">
            <ul className="check-list">
              <li><Icon name="check" size={14} /> Email addresses and phone numbers</li>
              <li><Icon name="check" size={14} /> API keys and hardcoded credentials</li>
              <li><Icon name="check" size={14} /> Author, custom and XMP metadata</li>
              <li><Icon name="check" size={14} /> Government and payment identifiers</li>
              <li><Icon name="check" size={14} /> Confidentiality markers</li>
            </ul>
          </Card>
          <Card title="Privacy guarantees">
            <ul className="check-list muted-list">
              <li><Icon name="lock" size={14} /> No raw detected value is stored or returned</li>
              <li><Icon name="lock" size={14} /> No uploaded file is persisted</li>
              <li><Icon name="lock" size={14} /> External AI requires explicit opt-in</li>
              <li><Icon name="lock" size={14} /> Reports contain redacted evidence only</li>
            </ul>
          </Card>
        </aside>
      </div>
    </>
  )
}
