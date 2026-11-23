import { useState } from 'react'
import { Link } from 'react-router-dom'
import api, { errorMessage } from '../services/api'
import { Alert, Card, PageHeader, Spinner } from '../components/UI'
import Icon from '../components/Icon'

export default function PrivacyTools() {
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [cleanName, setCleanName] = useState('')

  const choose = (candidate) => {
    if (!candidate) return
    const extension = candidate.name.split('.').pop()?.toLowerCase()
    if (!['pdf', 'docx'].includes(extension)) {
      setError('Only PDF and DOCX files can be sanitized.')
      setFile(null)
      return
    }
    setError('')
    setCleanName('')
    setFile(candidate)
  }

  const sanitize = async (event) => {
    event.preventDefault()
    if (!file || busy) return
    setBusy(true)
    setError('')
    const form = new FormData()
    form.append('file', file)
    try {
      const response = await api.post('/tools/sanitize/', form, { headers: { 'Content-Type': 'multipart/form-data' }, responseType: 'blob' })
      const disposition = response.headers['content-disposition'] || ''
      const match = disposition.match(/filename="([^"]+)"/)
      const filename = match?.[1] || `${file.name.split('.')[0]}-clean.${file.name.split('.').pop()}`
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      setCleanName(filename)
    } catch (requestError) {
      setError(errorMessage(requestError, 'Unable to sanitize this document.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="MODULE 06"
        title="Privacy Tools"
        description="Produce a clean copy of a document by removing hidden metadata before you share it."
      />

      <div className="tool-layout">
        <Card title="Metadata sanitizer" subtitle="The original file is never stored; the clean copy is generated in memory.">
          <Alert tone="info" title="Real file transformation">
            This tool rewrites the uploaded file with author fields, custom properties, XMP metadata and embedded attachments stripped. The content of your document is preserved.
          </Alert>
          <form onSubmit={sanitize}>
            <div
              className={`dropzone ${file ? 'has-file' : ''}`}
              onDragOver={(event) => event.preventDefault()}
              onDrop={(event) => { event.preventDefault(); choose(event.dataTransfer.files[0]) }}
            >
              <input
                id="sanitize-input"
                type="file"
                accept=".pdf,.docx"
                onChange={(event) => choose(event.target.files[0])}
              />
              <label htmlFor="sanitize-input">
                <span className="drop-icon"><Icon name="shield" size={28} /></span>
                {file ? (
                  <><strong>{file.name}</strong><p>{(file.size / 1024).toFixed(1)} KB · Ready to sanitize</p></>
                ) : (
                  <><strong>Choose a PDF or DOCX file</strong><p>or drop it here · 20 MB maximum</p></>
                )}
              </label>
            </div>
            {error && <Alert tone="danger">{error}</Alert>}
            <div className="form-actions">
              <button className="btn btn-primary" disabled={!file || busy}>
                {busy ? <Spinner label="Cleaning…" /> : <><Icon name="shield" size={16} /> Create clean copy</>}
              </button>
              {file && <button type="button" className="btn btn-ghost" onClick={() => { setFile(null); setCleanName(''); setError('') }}>Clear</button>}
            </div>
          </form>
          {cleanName && (
            <div className="tool-success">
              <Icon name="check" size={18} />
              <div><strong>Clean copy downloaded</strong><p>{cleanName}</p></div>
              <Link className="btn btn-ghost" to="/scan/document">Re-scan it</Link>
            </div>
          )}
        </Card>

        <Card title="What gets removed">
          <ul className="check-list">
            <li><Icon name="check" size={14} /> PDF document info dictionary</li>
            <li><Icon name="check" size={14} /> PDF XMP metadata stream</li>
            <li><Icon name="check" size={14} /> PDF embedded attachments</li>
            <li><Icon name="check" size={14} /> DOCX author and last-modified-by</li>
            <li><Icon name="check" size={14} /> DOCX custom properties</li>
            <li><Icon name="check" size={14} /> Company and manager fields</li>
          </ul>
        </Card>
      </div>
    </>
  )
}
