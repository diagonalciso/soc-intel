import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { searchObjects, getThreatActors, getIndicators, getMalware, getVulnerabilities } from '../api/client'

type Tab = 'threat-actor' | 'indicator' | 'malware' | 'vulnerability' | 'all'

const TLP_OPTIONS = ['', 'TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']

const TLP_COLORS: Record<string, { bg: string; text: string }> = {
  'TLP:CLEAR':        { bg: '#f0fdf4', text: '#166534' },
  'TLP:GREEN':        { bg: '#166534', text: '#bbf7d0' },
  'TLP:AMBER':        { bg: '#92400e', text: '#fde68a' },
  'TLP:AMBER+STRICT': { bg: '#7c2d12', text: '#fed7aa' },
  'TLP:RED':          { bg: '#7f1d1d', text: '#fca5a5' },
}

function TLPBadge({ tlp }: { tlp?: string }) {
  if (!tlp) return null
  const c = TLP_COLORS[tlp] || { bg: '#1e293b', text: '#94a3b8' }
  return (
    <span style={{
      fontSize: 9, padding: '2px 6px', borderRadius: 4, fontWeight: 700,
      background: c.bg, color: c.text, fontFamily: 'monospace', letterSpacing: 0.3,
      whiteSpace: 'nowrap',
    }}>
      {tlp}
    </span>
  )
}

export default function IntelPage() {
  const [tab, setTab] = useState<Tab>('all')
  const [search, setSearch] = useState('')
  const [tlpFilter, setTlpFilter] = useState('')

  const queryFn = () => {
    const params: Record<string, unknown> = {
      q: search || undefined,
      size: 50,
      tlp: tlpFilter || undefined,
    }
    if (tab === 'threat-actor') return getThreatActors(params).then((r) => r.data)
    if (tab === 'indicator') return getIndicators(params).then((r) => r.data)
    if (tab === 'malware') return getMalware(params).then((r) => r.data)
    if (tab === 'vulnerability') return getVulnerabilities(params).then((r) => r.data)
    return searchObjects({ ...params, type: undefined }).then((r) => r.data)
  }

  const { data, isLoading } = useQuery({
    queryKey: ['intel', tab, search, tlpFilter],
    queryFn,
  })

  const TABS: [Tab, string][] = [
    ['all', 'All'],
    ['threat-actor', 'Threat Actors'],
    ['indicator', 'Indicators'],
    ['malware', 'Malware'],
    ['vulnerability', 'Vulnerabilities'],
  ]

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700 }}>Intelligence</h1>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
          {data?.total ? `${data.total.toLocaleString()} objects` : ''}
        </div>
      </div>

      {/* Search + filters row */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search intelligence objects..."
          style={{
            flex: '1 1 300px', maxWidth: 500, padding: '8px 12px',
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderRadius: 6, color: 'var(--text-primary)', fontSize: 13, outline: 'none',
          }}
        />
        <select
          value={tlpFilter}
          onChange={(e) => setTlpFilter(e.target.value)}
          style={{
            padding: '8px 12px', background: 'var(--bg-secondary)',
            border: '1px solid var(--border)', borderRadius: 6,
            color: 'var(--text-primary)', fontSize: 12, outline: 'none', cursor: 'pointer',
          }}
        >
          <option value="">All TLP</option>
          {TLP_OPTIONS.slice(1).map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 0 }}>
        {TABS.map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            style={{
              padding: '8px 16px', background: 'none', border: 'none',
              borderBottom: tab === key ? '2px solid var(--accent)' : '2px solid transparent',
              color: tab === key ? 'var(--accent)' : 'var(--text-secondary)',
              cursor: 'pointer', fontSize: 13, fontWeight: tab === key ? 600 : 400,
            }}
          >
            {label}
          </button>
        ))}
      </div>

      <div style={{
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
        borderTop: 'none', borderRadius: '0 0 6px 6px',
      }}>
        {isLoading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-secondary)' }}>Loading...</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['Type', 'Name', 'Description', 'Labels', 'TLP', 'Conf', 'Modified'].map((h) => (
                  <th key={h} style={{
                    textAlign: 'left', padding: '10px 12px', fontSize: 11,
                    color: 'var(--text-secondary)', borderBottom: '1px solid var(--border)',
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(data?.objects || []).map((obj: any) => (
                <tr key={obj.id} style={{ borderBottom: '1px solid #1a2030' }}>
                  <td style={{ padding: '10px 12px' }}>
                    <TypeBadge type={obj.type} />
                  </td>
                  <td style={{ padding: '10px 12px', fontSize: 13 }}>
                    <Link to={`/intel/${obj.id}`} style={{ color: 'var(--accent)' }}>
                      {obj.name || obj.id.slice(0, 30) + '...'}
                    </Link>
                  </td>
                  <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-secondary)', maxWidth: 260 }}>
                    <span title={obj.description}>{(obj.description || '').slice(0, 70)}{obj.description?.length > 70 ? '…' : ''}</span>
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    {(obj.labels || []).slice(0, 2).map((l: string) => (
                      <span key={l} style={{
                        fontSize: 10, padding: '2px 6px', borderRadius: 8, marginRight: 4,
                        background: '#1e3a5f', color: '#60a5fa',
                      }}>
                        {l}
                      </span>
                    ))}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <TLPBadge tlp={obj.tlp} />
                  </td>
                  <td style={{ padding: '10px 12px', fontSize: 12 }}>
                    {obj.confidence ?? '—'}
                  </td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-secondary)' }}>
                    {obj.modified?.slice(0, 10)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {!isLoading && !data?.objects?.length && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-secondary)', fontSize: 13 }}>
            No objects found. Run connectors to populate intelligence.
          </div>
        )}
      </div>
    </div>
  )
}

function TypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    'threat-actor': '#ef4444',
    'intrusion-set': '#f97316',
    'malware': '#a855f7',
    'indicator': '#3b82f6',
    'vulnerability': '#f59e0b',
    'attack-pattern': '#06b6d4',
    'campaign': '#ec4899',
    'tool': '#10b981',
  }
  const color = colors[type] || '#6b7280'
  return (
    <span style={{
      fontSize: 10, padding: '2px 7px', borderRadius: 8,
      background: `${color}22`, color, fontFamily: 'monospace',
    }}>
      {type}
    </span>
  )
}
