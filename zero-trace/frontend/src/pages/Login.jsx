import { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { errorMessage } from '../services/api'
import Icon from '../components/Icon'

export default function Login() {
  const { user, login } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  if (user) return <Navigate to="/dashboard" replace />

  const submit = async (event) => {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await login(email, password)
      navigate('/dashboard')
    } catch (requestError) {
      setError(errorMessage(requestError, 'Unable to sign in.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-visual">
        <div className="auth-brand"><span className="brand-mark"><Icon name="shield" size={24} /></span> ZEROTRACE</div>
        <div className="auth-visual-copy">
          <span className="eyebrow">PRIVACY INTELLIGENCE PLATFORM</span>
          <h1>Find what you<br />didn't mean to expose.</h1>
          <p>Scan documents and authorised repositories for personal data, secrets and risky metadata. Get redacted, actionable evidence in seconds.</p>
        </div>
        <ul className="auth-points">
          <li><Icon name="lock" size={16} /> Local-first document processing</li>
          <li><Icon name="eye" size={16} /> Secrets never displayed in clear text</li>
          <li><Icon name="shield" size={16} /> Explicit consent for every repository</li>
        </ul>
        <div className="auth-grid" />
      </div>

      <div className="auth-panel">
        <form className="auth-card" onSubmit={submit}>
          <span className="eyebrow">WELCOME BACK</span>
          <h2>Sign in to ZeroTrace</h2>
          <p className="muted">Access your privacy command centre.</p>
          {error && <div className="form-error"><Icon name="alert" size={16} /> {error}</div>}
          <label>
            <span>Email address</span>
            <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" required autoComplete="email" />
          </label>
          <label>
            <span>Password</span>
            <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="••••••••••••" required autoComplete="current-password" />
          </label>
          <button className="btn btn-primary btn-block" disabled={busy}>
            {busy ? 'Signing in…' : <>Sign in <Icon name="arrow" size={16} /></>}
          </button>
          <p className="auth-switch">New to ZeroTrace? <Link to="/register">Create an account</Link></p>
        </form>
      </div>
    </div>
  )
}
