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
        <div style={{ flex: 1, padding: '8px 0' }}>
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
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
          ))}
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
      }}>
        <Outlet />
      </main>
    </div>
  )
}
