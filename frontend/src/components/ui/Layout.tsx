import { Outlet, NavLink } from 'react-router-dom'

const NAV_ITEMS = [
  { path: '/dashboard',   label: 'Dashboard',     icon: '◈' },
  { path: '/intel',       label: 'Intelligence',  icon: '⬡' },
  { path: '/actors',      label: 'Threat Actors', icon: '◎' },
  { path: '/campaigns',   label: 'Campaigns',     icon: '◌' },
  { path: '/attack',      label: 'ATT&CK',        icon: '⬛' },
  { path: '/hunting',     label: 'Hunting',       icon: '◈' },
  { path: '/rules',       label: 'Rules',         icon: '◧' },
  { path: '/alert-rules', label: 'Alert Rules',   icon: '◆' },
  { path: '/cases',       label: 'Cases',         icon: '⬟' },
  { path: '/darkweb',     label: 'Dark Web',      icon: '◉' },
  { path: '/connectors',  label: 'Connectors',    icon: '⬢' },
  { path: '/compliance',  label: 'Compliance',    icon: '◫' },
  { path: '/settings',    label: 'Settings',      icon: '◐' },
  { path: null, label: '─────────', icon: '·', disabled: true },
  { url: '/api/docs/user-manual',  label: 'User Manual',  icon: '📖', external: true },
  { url: '/api/docs/admin-manual', label: 'Admin Manual', icon: '⚙️', external: true },
  { url: '/api/docs', label: 'API Docs', icon: '📚', external: true },
]

export default function Layout() {
  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* Sidebar */}
      <nav style={{
        width: 220,
        background: 'var(--bg-secondary)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
      }}>
        {/* Logo */}
        <div style={{ padding: '20px 16px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: 2, color: 'var(--accent)' }}>
            SOCINT
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            Threat Intelligence
          </div>
        </div>

        {/* Nav links */}
        <div style={{ flex: 1, padding: '8px 0', overflow: 'auto' }}>
          {NAV_ITEMS.map((item) => {
            if (item.disabled) {
              return (
                <div
                  key={item.label}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    padding: '8px 16px',
                    color: 'var(--text-tertiary)',
                    fontSize: 10,
                    letterSpacing: 1,
                  }}
                >
                  {item.label}
                </div>
              )
            }

            if (item.external) {
              return (
                <a
                  key={item.url}
                  href={item.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    padding: '10px 16px',
                    color: 'var(--text-secondary)',
                    background: 'transparent',
                    borderLeft: '2px solid transparent',
                    textDecoration: 'none',
                    fontSize: 13,
                    fontWeight: 400,
                    transition: 'all 0.15s',
                    cursor: 'pointer',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.color = 'var(--accent)'
                    e.currentTarget.style.borderLeft = '2px solid var(--accent)'
                    e.currentTarget.style.background = 'rgba(59,130,246,0.08)'
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.color = 'var(--text-secondary)'
                    e.currentTarget.style.borderLeft = '2px solid transparent'
                    e.currentTarget.style.background = 'transparent'
                  }}
                >
                  <span style={{ fontSize: 16 }}>{item.icon}</span>
                  {item.label}
                </a>
              )
            }

            return (
              <NavLink
                key={item.path as string}
                to={item.path as string}
                style={({ isActive }) => ({
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '10px 16px',
                  color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
                  background: isActive ? 'rgba(59,130,246,0.08)' : 'transparent',
                  borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                  textDecoration: 'none',
                  fontSize: 13,
                  fontWeight: isActive ? 600 : 400,
                  transition: 'all 0.15s',
                })}
              >
                <span style={{ fontSize: 16 }}>{item.icon}</span>
                {item.label}
              </NavLink>
            )
          })}
        </div>

        <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', fontSize: 11, color: '#4a5568' }}>
          local network mode
        </div>
      </nav>

      {/* Main content */}
      <main style={{
        flex: 1,
        overflow: 'auto',
        background: 'var(--bg-primary)',
        display: 'flex',
        flexDirection: 'column',
      }}>
        {/* Header with Help Button */}
        <div style={{
          display: 'flex',
          justifyContent: 'flex-end',
          alignItems: 'center',
          padding: '12px 20px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--bg-secondary)',
          gap: 12,
          flexShrink: 0,
        }}>
          <a href="/api/docs/user-manual" target="_blank" rel="noopener noreferrer" style={{
            fontSize: 12,
            padding: '6px 12px',
            borderRadius: 4,
            background: 'rgba(59,130,246,0.1)',
            color: 'var(--accent)',
            textDecoration: 'none',
            border: '1px solid rgba(59,130,246,0.3)',
            cursor: 'pointer',
            transition: 'all 0.2s',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(59,130,246,0.2)'
            e.currentTarget.style.borderColor = 'var(--accent)'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'rgba(59,130,246,0.1)'
            e.currentTarget.style.borderColor = 'rgba(59,130,246,0.3)'
          }}>
            📖 Help
          </a>
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflow: 'auto' }}>
          <Outlet />
        </div>
      </main>
    </div>
  )
}
