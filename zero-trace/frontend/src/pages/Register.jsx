import { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { errorMessage } from '../services/api'
import Icon from '../components/Icon'

export default function Register() {
  const { user, register } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', email: '', password: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  if (user) return <Navigate to="/dashboard" replace />

  const update = (key) => (event) => setForm((current) => ({ ...current, [key]: event.target.value }))

  const submit = async (event) => {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await register(form.username, form.email, form.password)
      navigate('/dashboard')
    } catch (requestError) {
      setError(errorMessage(requestError, 'Unable to create account.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-visual">
        <div className="auth-brand"><span className="brand-mark"><Icon name="shield" size={24} /></span> ZEROTRACE</div>
        <div className="auth-visual-copy">
          <span className="eyebrow">GET STARTED</span>
          <h1>Your privacy, measured.</h1>
          <p>Create a workspace to scan your own files and authorised repositories. You control every consent decision.</p>
        </div>
        <ul className="auth-points">
          <li><Icon name="file" size={16} /> PDF and DOCX scanning</li>
          <li><Icon name="github" size={16} /> Authorised repository checks</li>
          <li><Icon name="bulb" size={16} /> Prioritised remediation steps</li>
        </ul>
        <div className="auth-grid" />
      </div>

      <div className="auth-panel">
        <form className="auth-card" onSubmit={submit}>
          <span className="eyebrow">CREATE WORKSPACE</span>
          <h2>Start protecting your data</h2>
          <p className="muted">Only an email and a strong password are required.</p>
          {error && <div className="form-error"><Icon name="alert" size={16} /> {error}</div>}
          <label>
            <span>Username</span>
            <input value={form.username} onChange={update('username')} placeholder="analyst" required autoComplete="username" />
          </label>
          <label>
            <span>Email address</span>
            <input type="email" value={form.email} onChange={update('email')} placeholder="you@company.com" required autoComplete="email" />
          </label>
          <label>
            <span>Password</span>
            <input type="password" value={form.password} onChange={update('password')} placeholder="12+ characters" required minLength={8} autoComplete="new-password" />
            <small>Use at least 8 characters with a mix of letters, numbers and symbols.</small>
          </label>
          <button className="btn btn-primary btn-block" disabled={busy}>
            {busy ? 'Creating…' : <>Create account <Icon name="arrow" size={16} /></>}
          </button>
          <p className="auth-switch">Already registered? <Link to="/login">Sign in</Link></p>
        </form>
      </div>
    </div>
  )
}
