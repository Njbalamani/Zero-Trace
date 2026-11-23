import Icon from './Icon'

export function Card({ title, subtitle, action, children, className = '' }) {
  return (
    <section className={`card ${className}`}>
      {(title || action) && (
        <header className="card-head">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <p>{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      {children}
    </section>
  )
}

export function StatCard({ icon, label, value, hint, tone = 'teal' }) {
  return (
    <article className={`stat-card tone-${tone}`}>
      <div className="stat-icon"><Icon name={icon} size={20} /></div>
      <div className="stat-body">
        <span className="stat-label">{label}</span>
        <strong className="stat-value">{value}</strong>
        {hint && <span className="stat-hint">{hint}</span>}
      </div>
    </article>
  )
}

export function RiskBadge({ level }) {
  const value = (level || 'minimal').toLowerCase()
  return <span className={`badge risk-${value}`}>{value}</span>
}

export function SeverityPill({ severity }) {
  const value = (severity || 'info').toLowerCase()
  return <span className={`pill severity-${value}`}>{value}</span>
}

export function Badge({ children, tone = 'neutral' }) {
  return <span className={`badge tone-${tone}`}>{children}</span>
}

export function EmptyState({ title, message, action }) {
  return (
    <div className="empty-state">
      <Icon name="scan" size={26} />
      <h3>{title}</h3>
      <p>{message}</p>
      {action}
    </div>
  )
}

export function Spinner({ label = 'Working' }) {
  return (
    <div className="spinner-wrap">
      <span className="spinner" />
      <span>{label}</span>
    </div>
  )
}

const DEFAULT_STEPS = [
  'Preparing secure local buffer',
  'Extracting content and metadata',
  'Running detection engines',
  'Scoring risk and building recommendations',
]

export function ScanProgress({ step = 0, steps = DEFAULT_STEPS, label = 'Scanning' }) {
  const active = Math.min(step, steps.length - 1)
  return (
    <div className="scan-progress">
      <div className="scan-radar">
        <span className="radar-ring ring-one" />
        <span className="radar-ring ring-two" />
        <Icon name="scan" size={30} />
      </div>
      <h3>{label}</h3>
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${((active + 1) / steps.length) * 100}%` }} />
      </div>
      <ol className="progress-steps">
        {steps.map((item, index) => (
          <li key={item} className={index < active ? 'done' : index === active ? 'active' : ''}>
            <span className="step-dot">{index < active ? <Icon name="check" size={12} /> : index + 1}</span>
            {item}
          </li>
        ))}
      </ol>
      <p className="progress-note"><Icon name="lock" size={13} /> Files are processed in memory and never sent to external AI services.</p>
    </div>
  )
}

export function Alert({ tone = 'info', title, children }) {
  return (
    <div className={`alert alert-${tone}`}>
      <Icon name={tone === 'danger' ? 'alert' : tone === 'success' ? 'check' : 'lock'} size={17} />
      <div>
        {title && <strong>{title}</strong>}
        <p>{children}</p>
      </div>
    </div>
  )
}

export function PageHeader({ eyebrow, title, description, action }) {
  return (
    <header className="page-header">
      <div>
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {action}
    </header>
  )
}
