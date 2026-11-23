import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import Icon from './Icon'

const NAV = [
  { to: '/dashboard', label: 'Dashboard', icon: 'grid' },
  { to: '/scan/document', label: 'Document Scanner', icon: 'file' },
  { to: '/scan/repository', label: 'Repository Scanner', icon: 'github' },
  { to: '/scans', label: 'Scan History', icon: 'list' },
  { to: '/tools', label: 'Privacy Tools', icon: 'shield' },
  { to: '/recommendations', label: 'Recommendations', icon: 'bulb' },
  { to: '/audit', label: 'Audit Trail', icon: 'clock' },
  { to: '/settings', label: 'Privacy Settings', icon: 'settings' },
]

export default function Layout() {
  const { user, logout } = useAuth()
  const [open, setOpen] = useState(false)
  const location = useLocation()
  const navigate = useNavigate()

  useEffect(() => setOpen(false), [location.pathname])

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${open ? 'open' : ''}`}>
        <div className="brand">
          <span className="brand-mark"><Icon name="shield" size={24} /></span>
          <span className="brand-text">
            <strong>ZEROTRACE</strong>
            <small>PRIVACY INTELLIGENCE</small>
          </span>
          <button className="icon-btn sidebar-close" onClick={() => setOpen(false)} aria-label="Close navigation">
            <Icon name="close" size={18} />
          </button>
        </div>

        <nav className="nav">
          <span className="nav-section">Workspace</span>
          {NAV.map((item) => (
            <NavLink key={item.to} to={item.to} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
              <Icon name={item.icon} size={18} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="privacy-chip">
            <Icon name="lock" size={15} />
            <span>Privacy-first architecture</span>
          </div>
          <div className="user-block">
            <div className="avatar">{user?.email?.[0]?.toUpperCase() || 'Z'}</div>
            <div className="user-meta">
              <strong>{user?.username || 'User'}</strong>
              <span>{user?.email}</span>
            </div>
          </div>
          <button className="nav-item logout-btn" onClick={handleLogout}>
            <Icon name="logout" size={18} />
            <span>Sign out</span>
          </button>
        </div>
      </aside>

      {open && <div className="sidebar-overlay" onClick={() => setOpen(false)} />}

      <div className="main-shell">
        <header className="topbar">
          <button className="icon-btn menu-btn" onClick={() => setOpen(true)} aria-label="Open navigation">
            <Icon name="menu" size={20} />
          </button>
          <div className="topbar-title">
            <span>ZeroTrace Console</span>
            <span className="status-dot" />
            <small>Systems operational</small>
          </div>
          <div className="topbar-actions">
            <span className={`consent-chip ${user?.ai_consent ? 'on' : ''}`}>
              <Icon name="eye" size={14} />
              AI {user?.ai_consent ? 'opted in' : 'disabled'}
            </span>
            <span className="topbar-user">{user?.email}</span>
          </div>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
