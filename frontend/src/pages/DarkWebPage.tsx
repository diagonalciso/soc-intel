import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  getRansomwareLeaks, getRansomwareStats, getCredentialExposures,
  getIABListings, getStealerLogs, getHoneypotIps, getDarkwebByType,
} from '../api/client'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

type Tab = 'ransomware' | 'credentials' | 'iab' | 'stealer' | 'honeypot' | 'cti-reports' | 'telegram'

export default function DarkWebPage() {
  const [tab, setTab] = useState<Tab>('ransomware')
  const [search, setSearch] = useState('')

  const { data: stats } = useQuery({
    queryKey: ['ransom-stats'],
    queryFn: () => getRansomwareStats().then((r) => r.data),
  })

  const { data: leaks } = useQuery({
    queryKey: ['ransomware-leaks', search],
    queryFn: () => getRansomwareLeaks({ q: search || undefined, size: 50 }).then((r) => r.data),
    enabled: tab === 'ransomware',
  })

  const { data: creds } = useQuery({
    queryKey: ['cred-exposures'],
    queryFn: () => getCredentialExposures({ size: 50 }).then((r) => r.data),
    enabled: tab === 'credentials',
  })

  const { data: iab } = useQuery({
    queryKey: ['iab-listings'],
    queryFn: () => getIABListings({ size: 50 }).then((r) => r.data),
    enabled: tab === 'iab',
  })

  const { data: stealer } = useQuery({
    queryKey: ['stealer-logs'],
    queryFn: () => getStealerLogs({ size: 50 }).then((r) => r.data),
    enabled: tab === 'stealer',
  })

  const { data: honeypot } = useQuery({
    queryKey: ['honeypot-ips'],
    queryFn: () => getHoneypotIps().then((r) => r.data),
    enabled: tab === 'honeypot',
  })

  const { data: ctiReports } = useQuery({
    queryKey: ['cti-reports'],
    queryFn: () => getDarkwebByType('cti-report', 50).then((r) => r.data),
    enabled: tab === 'cti-reports',
  })

  const { data: tgMessages } = useQuery({
    queryKey: ['tg-messages'],
    queryFn: () => getDarkwebByType('tg-message', 100).then((r) => r.data),
    enabled: tab === 'telegram',
  })

  const byCountry = Object.entries(stats?.by_country || {})
    .sort(([, a], [, b]) => (b as number) - (a as number))
    .slice(0, 8)
    .map(([name, count]) => ({ name, count }))

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>Dark Web Intelligence</h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 24 }}>
        Ransomware victims, credential exposures, IAB listings, stealer logs, CTI news, and Telegram intel.
      </p>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 24 }}>
        <div style={statCard}>
          <div style={{ fontSize: 26, fontWeight: 700, color: '#ef4444' }}>{stats?.total ?? '—'}</div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Ransomware Victims</div>
        </div>
        <div style={{ ...statCard, gridColumn: 'span 2' }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>Top Victim Countries</div>
          <ResponsiveContainer width="100%" height={100}>
            <BarChart data={byCountry}>
              <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} />
              <YAxis hide />
              <Tooltip
                contentStyle={{ background: '#1e2533', border: '1px solid #2d3748', color: '#e2e8f0' }}
              />
              <Bar dataKey="count" fill="#ef4444" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 0, borderBottom: '1px solid var(--border)' }}>
        {([
          ['ransomware', 'Ransomware Leaks'],
          ['credentials', 'Credential Exposures'],
          ['iab', 'IAB Listings'],
          ['stealer', 'Stealer Logs'],
          ['honeypot', 'Honeypot IPs'],
          ['cti-reports', 'CTI News'],
          ['telegram', 'Telegram'],
        ] as [Tab, string][]).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            style={{
              padding: '8px 18px',
              background: 'none',
              border: 'none',
              borderBottom: tab === key ? '2px solid var(--accent)' : '2px solid transparent',
              color: tab === key ? 'var(--accent)' : 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: 13,
              fontWeight: tab === key ? 600 : 400,
            }}
          >
            {label}
          </button>
        ))}
      </div>

      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        borderTop: 'none',
        borderRadius: '0 0 6px 6px',
        padding: 20,
      }}>
        {tab === 'ransomware' && (
          <>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search victims, groups..."
              style={{ ...searchInput, marginBottom: 16 }}
            />
            <RansomwareTable data={leaks?.objects || []} />
          </>
        )}

        {tab === 'credentials' && (
          <CredentialsTable data={creds?.objects || []} />
        )}

        {tab === 'iab' && (
          <IABTable data={iab?.objects || []} />
        )}

        {tab === 'stealer' && (
          <StealerTable data={stealer?.objects || []} />
        )}

        {tab === 'honeypot' && (
          <HoneypotTable ips={honeypot?.ips || []} />
        )}

        {tab === 'cti-reports' && (
          <CTIReportsTable data={ctiReports?.objects || []} />
        )}

        {tab === 'telegram' && (
          <TelegramTable data={tgMessages?.objects || []} />
        )}
      </div>
    </div>
  )
}

function RansomwareTable({ data }: { data: any[] }) {
  if (!data.length) return <Empty />
  return (
    <table style={tableStyle}>
      <thead>
        <tr>
          {['Group', 'Victim', 'Domain', 'Country', 'Sector', 'Date Posted', 'Files'].map((h) => (
            <th key={h} style={thStyle}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.map((row, i) => (
          <tr key={i} style={{ borderBottom: '1px solid #1a2030' }}>
            <td style={tdStyle}><GroupBadge name={row.group_name} /></td>
            <td style={tdStyle}>{row.victim_name}</td>
            <td style={{ ...tdStyle, color: 'var(--accent)' }}>{row.victim_domain}</td>
            <td style={tdStyle}>{row.country || '—'}</td>
            <td style={tdStyle}>{row.sector || '—'}</td>
            <td style={tdStyle}>{row.date_posted?.slice(0, 10) || '—'}</td>
            <td style={tdStyle}>
              {row.files_published ? (
                <span style={{ color: '#ef4444', fontSize: 11 }}>Published</span>
              ) : '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function CredentialsTable({ data }: { data: any[] }) {
  if (!data.length) return <Empty />
  return (
    <table style={tableStyle}>
      <thead>
        <tr>
          {['Victim / Email / Domain', 'Type', 'Threat Actor', 'Records', 'Data Classes', 'Discovered'].map((h) => (
            <th key={h} style={thStyle}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.map((row, i) => (
          <tr key={i} style={{ borderBottom: '1px solid #1a2030' }}>
            <td style={tdStyle}>{row.victim_name || row.email || row.domain || '—'}</td>
            <td style={tdStyle}>{row.exposure_type}</td>
            <td style={tdStyle}>
              {row.threat_actor ? <GroupBadge name={row.threat_actor} /> : <span style={{ color: 'var(--text-secondary)' }}>{row.malware_family || '—'}</span>}
            </td>
            <td style={tdStyle}>
              {row.records_exposed ? row.records_exposed.toLocaleString() : '—'}
            </td>
            <td style={{ ...tdStyle, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {Array.isArray(row.data_classes) ? row.data_classes.slice(0, 3).join(', ') : (row.data_classes || '—')}
            </td>
            <td style={tdStyle}>{row.date_discovered?.slice(0, 10) || '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function IABTable({ data }: { data: any[] }) {
  if (!data.length) return <Empty />
  return (
    <table style={tableStyle}>
      <thead>
        <tr>
          {['Access Type', 'Sector', 'Country', 'Price (USD)', 'Forum', 'Source'].map((h) => (
            <th key={h} style={thStyle}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.map((row, i) => (
          <tr key={i} style={{ borderBottom: '1px solid #1a2030' }}>
            <td style={tdStyle}><code style={{ fontSize: 11 }}>{row.access_type}</code></td>
            <td style={tdStyle}>{row.target_sector || '—'}</td>
            <td style={tdStyle}>{row.target_country || '—'}</td>
            <td style={tdStyle}>
              {row.asking_price_usd ? `$${row.asking_price_usd.toLocaleString()}` : '—'}
            </td>
            <td style={tdStyle}>{row.forum_name || '—'}</td>
            <td style={tdStyle}>{row.source}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function StealerTable({ data }: { data: any[] }) {
  if (!data.length) return <Empty />
  return (
    <table style={tableStyle}>
      <thead>
        <tr>
          {['Malware', 'Credentials', 'Domains', 'Date Exfiltrated', 'Source'].map((h) => (
            <th key={h} style={thStyle}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.map((row, i) => (
          <tr key={i} style={{ borderBottom: '1px solid #1a2030' }}>
            <td style={tdStyle}><GroupBadge name={row.malware_family} /></td>
            <td style={tdStyle}>{row.credentials_count?.toLocaleString() || '—'}</td>
            <td style={tdStyle}>{(row.domains || []).slice(0, 3).join(', ')}{(row.domains?.length || 0) > 3 ? '...' : ''}</td>
            <td style={tdStyle}>{row.date_exfiltrated?.slice(0, 10) || '—'}</td>
            <td style={tdStyle}>{row.source}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function HoneypotTable({ ips }: { ips: string[] }) {
  if (!ips.length) return <Empty />
  return (
    <table style={tableStyle}>
      <thead>
        <tr>
          <th style={thStyle}>#</th>
          <th style={thStyle}>IP Address</th>
        </tr>
      </thead>
      <tbody>
        {ips.map((ip, i) => (
          <tr key={ip} style={{ borderBottom: '1px solid #1a2030' }}>
            <td style={{ ...tdStyle, color: 'var(--text-secondary)', width: 48 }}>{i + 1}</td>
            <td style={tdStyle}>
              <a
                href={`https://www.abuseipdb.com/check/${ip}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: 'var(--accent)', textDecoration: 'none', fontFamily: 'monospace' }}
              >
                {ip}
              </a>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function CTIReportsTable({ data }: { data: any[] }) {
  if (!data.length) return <Empty />
  return (
    <table style={tableStyle}>
      <thead>
        <tr>
          {['Source', 'Title', 'Actors', 'Keywords', 'Published'].map((h) => (
            <th key={h} style={thStyle}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.map((row, i) => (
          <tr key={i} style={{ borderBottom: '1px solid #1a2030' }}>
            <td style={tdStyle}><GroupBadge name={row.source} /></td>
            <td style={tdStyle}>
              {row.url ? (
                <a href={row.url} target="_blank" rel="noopener noreferrer"
                  style={{ color: 'var(--accent)', textDecoration: 'none' }}>
                  {row.title || '—'}
                </a>
              ) : (row.title || '—')}
            </td>
            <td style={tdStyle}>
              {(row.threat_actors || []).map((a: string) => (
                <GroupBadge key={a} name={a} />
              ))}
            </td>
            <td style={{ ...tdStyle, color: 'var(--text-secondary)', fontSize: 11 }}>
              {(row.keywords_matched || []).slice(0, 4).join(', ')}
            </td>
            <td style={tdStyle}>{row.published?.slice(0, 10) || '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function TelegramTable({ data }: { data: any[] }) {
  if (!data.length) return (
    <div style={{ color: 'var(--text-secondary)', fontSize: 13, padding: '20px 0' }}>
      No Telegram data. Configure TG_API_ID, TG_API_HASH, TG_SESSION, TG_CTI_CHANNELS and run connector.
    </div>
  )
  return (
    <table style={tableStyle}>
      <thead>
        <tr>
          {['Channel', 'Message', 'Keywords', 'Views', 'Date'].map((h) => (
            <th key={h} style={thStyle}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.map((row, i) => (
          <tr key={i} style={{ borderBottom: '1px solid #1a2030' }}>
            <td style={tdStyle}><GroupBadge name={row.channel_title || row.channel} /></td>
            <td style={{ ...tdStyle, maxWidth: 400 }}>
              {row.message_url ? (
                <a href={row.message_url} target="_blank" rel="noopener noreferrer"
                  style={{ color: 'var(--text-primary)', textDecoration: 'none', fontSize: 12 }}>
                  {(row.text || '').slice(0, 160)}{(row.text?.length || 0) > 160 ? '…' : ''}
                </a>
              ) : (row.text || '').slice(0, 160)}
            </td>
            <td style={{ ...tdStyle, color: 'var(--text-secondary)', fontSize: 11 }}>
              {(row.keywords_matched || []).slice(0, 3).join(', ')}
            </td>
            <td style={tdStyle}>{row.views?.toLocaleString() || '—'}</td>
            <td style={tdStyle}>{row.created?.slice(0, 10) || '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function GroupBadge({ name }: { name: string }) {
  const colors = ['#ef4444', '#f97316', '#f59e0b', '#8b5cf6', '#06b6d4', '#10b981']
  const color = colors[Math.abs(name?.charCodeAt(0) || 0) % colors.length]
  return (
    <span style={{
      fontSize: 11, padding: '2px 8px', borderRadius: 10,
      background: `${color}22`, color,
    }}>
      {name}
    </span>
  )
}

function Empty() {
  return <div style={{ color: 'var(--text-secondary)', fontSize: 13, padding: '20px 0' }}>No data yet. Run connectors to populate.</div>
}

const statCard: React.CSSProperties = {
  background: 'var(--bg-tertiary)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: '16px 20px',
}

const tableStyle: React.CSSProperties = { width: '100%', borderCollapse: 'collapse' }

const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '6px 8px', fontSize: 11,
  color: 'var(--text-secondary)', borderBottom: '1px solid var(--border)',
}

const tdStyle: React.CSSProperties = { padding: '8px 8px', fontSize: 12 }

const searchInput: React.CSSProperties = {
  width: '100%', maxWidth: 400, padding: '8px 12px',
  background: 'var(--bg-tertiary)', border: '1px solid var(--border)',
  borderRadius: 6, color: 'var(--text-primary)', fontSize: 13, outline: 'none',
}
