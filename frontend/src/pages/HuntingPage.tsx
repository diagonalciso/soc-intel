import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { huntingPivot, getMalwareFamilies, getRules } from '../api/client'

type Tab = 'pivot' | 'families' | 'yara'

const TLP_COLORS: Record<string, { bg: string; text: string }> = {
  'TLP:CLEAR':        { bg: '#f0fdf4', text: '#166534' },
  'TLP:GREEN':        { bg: '#166534', text: '#bbf7d0' },
  'TLP:AMBER':        { bg: '#92400e', text: '#fde68a' },
  'TLP:AMBER+STRICT': { bg: '#7c2d12', text: '#fed7aa' },
  'TLP:RED':          { bg: '#7f1d1d', text: '#fca5a5' },
}

const TYPE_COLORS: Record<string, string> = {
  indicator: '#3b82f6',
  'threat-actor': '#ef4444',
  malware: '#f59e0b',
  vulnerability: '#8b5cf6',
  'attack-pattern': '#10b981',
  campaign: '#06b6d4',
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

function TypeBadge({ type }: { type: string }) {
  const bg = TYPE_COLORS[type] || '#6366f1'
  return (
    <span style={{
      fontSize: 10, padding: '2px 6px', borderRadius: 3, fontWeight: 600,
      background: bg, color: '#fff', whiteSpace: 'nowrap',
    }}>
      {type.replace('-', ' ')}
    </span>
  )
}

function PivotTab() {
  const [searchInput, setSearchInput] = useState('')
  const [searchTerm, setSearchTerm] = useState('')

  const { data: results, isLoading } = useQuery({
    queryKey: ['hunting-pivot', searchTerm],
    queryFn: () => huntingPivot(searchTerm, 25).then((r) => r.data),
    enabled: !!searchTerm,
  })

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (searchInput.trim()) {
      setSearchTerm(searchInput.trim())
    }
  }

  return (
    <div>
      <form onSubmit={handleSearch} style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', gap: 12 }}>
          <input
            type="text"
            placeholder="Search: IP, domain, hash, actor, malware family, ATT&CK technique..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            style={{
              flex: 1, padding: '10px 14px', border: '1px solid var(--border)',
              borderRadius: 6, background: 'var(--bg-secondary)', color: '#e2e8f0',
              fontSize: 13,
            }}
          />
          <button
            type="submit"
            style={{
              padding: '10px 24px', background: 'var(--accent)', color: '#fff',
              border: 'none', borderRadius: 6, fontWeight: 600, cursor: 'pointer',
            }}
          >
            Hunt
          </button>
        </div>
      </form>

      {isLoading && <div style={{ color: 'var(--text-secondary)' }}>Correlating results...</div>}

      {results && !isLoading && (
        <div>
          {/* Summary cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 24 }}>
            <div style={{ padding: 16, background: 'var(--bg-secondary)', borderRadius: 8 }}>
              <div style={{ fontSize: 24, fontWeight: 700, color: '#3b82f6' }}>
                {results.stix_objects?.length || 0}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>IOC Matches</div>
            </div>
            <div style={{ padding: 16, background: 'var(--bg-secondary)', borderRadius: 8 }}>
              <div style={{ fontSize: 24, fontWeight: 700, color: '#f59e0b' }}>
                {results.threat_actors?.length || 0}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>Threat Actors</div>
            </div>
            <div style={{ padding: 16, background: 'var(--bg-secondary)', borderRadius: 8 }}>
              <div style={{ fontSize: 24, fontWeight: 700, color: '#10b981' }}>
                {results.sigma_rules?.length || 0}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>Sigma Rules</div>
            </div>
            <div style={{ padding: 16, background: 'var(--bg-secondary)', borderRadius: 8 }}>
              <div style={{ fontSize: 24, fontWeight: 700, color: '#8b5cf6' }}>
                {results.yara_rules?.length || 0}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>YARA Rules</div>
            </div>
          </div>

          {/* IOCs Table */}
          {results.stix_objects && results.stix_objects.length > 0 && (
            <div style={{ marginBottom: 24 }}>
              <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Indicators of Compromise</h3>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Name</th>
                    <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Type</th>
                    <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>TLP</th>
                    <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {results.stix_objects.map((obj: any) => (
                    <tr key={obj.id} style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer' }}>
                      <td style={{ padding: '8px 12px' }}>
                        <Link to={`/intel/${obj.id}`} style={{ color: 'var(--accent)', textDecoration: 'none' }}>
                          {obj.name || obj.pattern?.substring(0, 50) || 'Unnamed'}
                        </Link>
                      </td>
                      <td style={{ padding: '8px 12px' }}><TypeBadge type={obj.type} /></td>
                      <td style={{ padding: '8px 12px' }}><TLPBadge tlp={obj.tlp} /></td>
                      <td style={{ padding: '8px 12px', color: 'var(--text-secondary)' }}>
                        {obj.x_clawint_source}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Sigma Rules */}
          {results.sigma_rules && results.sigma_rules.length > 0 && (
            <div style={{ marginBottom: 24 }}>
              <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Matching Sigma Rules</h3>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Rule</th>
                    <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Severity</th>
                    <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Techniques</th>
                  </tr>
                </thead>
                <tbody>
                  {results.sigma_rules.map((rule: any) => (
                    <tr key={rule.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '8px 12px' }}>{rule.name}</td>
                      <td style={{ padding: '8px 12px' }}>
                        <span style={{
                          fontSize: 11, padding: '2px 8px', borderRadius: 3, fontWeight: 600,
                          background: rule.severity === 'high' ? '#dc2626' : '#f59e0b',
                          color: '#fff',
                        }}>
                          {rule.severity}
                        </span>
                      </td>
                      <td style={{ padding: '8px 12px', color: 'var(--text-secondary)', fontSize: 11 }}>
                        {(rule.techniques || []).slice(0, 2).join(', ')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* YARA Rules */}
          {results.yara_rules && results.yara_rules.length > 0 && (
            <div>
              <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Matching YARA Rules</h3>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Rule</th>
                    <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Severity</th>
                    <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Tags</th>
                  </tr>
                </thead>
                <tbody>
                  {results.yara_rules.map((rule: any) => (
                    <tr key={rule.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '8px 12px' }}>{rule.name}</td>
                      <td style={{ padding: '8px 12px' }}>
                        <span style={{
                          fontSize: 11, padding: '2px 8px', borderRadius: 3, fontWeight: 600,
                          background: rule.severity === 'high' ? '#dc2626' : '#f59e0b',
                          color: '#fff',
                        }}>
                          {rule.severity}
                        </span>
                      </td>
                      <td style={{ padding: '8px 12px', color: 'var(--text-secondary)', fontSize: 11 }}>
                        {(rule.tags || []).slice(0, 2).join(', ')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function MalwareFamiliesTab() {
  const [search, setSearch] = useState('')
  const [from, setFrom] = useState(0)

  const { data: families } = useQuery({
    queryKey: ['malware-families', search, from],
    queryFn: () => getMalwareFamilies(search || undefined, from, 100).then((r) => r.data),
  })

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <input
          type="text"
          placeholder="Filter by malware family name..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value)
            setFrom(0)
          }}
          style={{
            width: '100%', padding: '10px 14px', border: '1px solid var(--border)',
            borderRadius: 6, background: 'var(--bg-secondary)', color: '#e2e8f0',
            fontSize: 13,
          }}
        />
      </div>

      {families?.objects && families.objects.length > 0 ? (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Name</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Aliases</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Description</th>
            </tr>
          </thead>
          <tbody>
            {families.objects.map((family: any) => (
              <tr key={family.id} style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer' }}>
                <td style={{ padding: '8px 12px' }}>
                  <Link to={`/intel/${family.id}`} style={{ color: 'var(--accent)', textDecoration: 'none' }}>
                    {family.name}
                  </Link>
                </td>
                <td style={{ padding: '8px 12px', color: 'var(--text-secondary)', fontSize: 11 }}>
                  {(family.aliases || []).slice(0, 2).join(', ')}
                </td>
                <td style={{ padding: '8px 12px', color: 'var(--text-secondary)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {family.description?.substring(0, 60)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: 32 }}>
          {search ? 'No malware families found' : 'Loading...'}
        </div>
      )}

      {families?.total && families.total > 100 && (
        <div style={{ marginTop: 16, display: 'flex', justifyContent: 'center', gap: 8 }}>
          <button
            onClick={() => setFrom(Math.max(0, from - 100))}
            disabled={from === 0}
            style={{ padding: '6px 12px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-secondary)', cursor: 'pointer', fontSize: 12 }}
          >
            ← Previous
          </button>
          <span style={{ color: 'var(--text-secondary)', fontSize: 12, padding: '6px 0' }}>
            {from + 1}–{Math.min(from + 100, families.total)} of {families.total}
          </span>
          <button
            onClick={() => setFrom(from + 100)}
            disabled={from + 100 >= (families.total || 0)}
            style={{ padding: '6px 12px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-secondary)', cursor: 'pointer', fontSize: 12 }}
          >
            Next →
          </button>
        </div>
      )}
    </div>
  )
}

function YARATab() {
  const [search, setSearch] = useState('')
  const [from, setFrom] = useState(0)

  const { data: rules } = useQuery({
    queryKey: ['yara-rules', search, from],
    queryFn: () => getRules({ type: 'yara', q: search || undefined, from, size: 20 }).then((r) => r.data),
  })

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <input
          type="text"
          placeholder="Filter by rule name, author, or tag..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value)
            setFrom(0)
          }}
          style={{
            width: '100%', padding: '10px 14px', border: '1px solid var(--border)',
            borderRadius: 6, background: 'var(--bg-secondary)', color: '#e2e8f0',
            fontSize: 13,
          }}
        />
      </div>

      {rules?.objects && rules.objects.length > 0 ? (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Rule</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Severity</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Author</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Tags</th>
            </tr>
          </thead>
          <tbody>
            {rules.objects.map((rule: any) => (
              <tr key={rule.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '8px 12px' }}>{rule.name}</td>
                <td style={{ padding: '8px 12px' }}>
                  <span style={{
                    fontSize: 11, padding: '2px 8px', borderRadius: 3, fontWeight: 600,
                    background: rule.severity === 'high' ? '#dc2626' : rule.severity === 'critical' ? '#991b1b' : '#f59e0b',
                    color: '#fff',
                  }}>
                    {rule.severity || 'medium'}
                  </span>
                </td>
                <td style={{ padding: '8px 12px', color: 'var(--text-secondary)', fontSize: 11 }}>
                  {rule.author}
                </td>
                <td style={{ padding: '8px 12px', color: 'var(--text-secondary)', fontSize: 11 }}>
                  {(rule.tags || []).slice(0, 2).join(', ')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: 32 }}>
          {search ? 'No YARA rules found' : 'Loading...'}
        </div>
      )}

      {rules?.total && rules.total > 20 && (
        <div style={{ marginTop: 16, display: 'flex', justifyContent: 'center', gap: 8 }}>
          <button
            onClick={() => setFrom(Math.max(0, from - 20))}
            disabled={from === 0}
            style={{ padding: '6px 12px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-secondary)', cursor: 'pointer', fontSize: 12 }}
          >
            ← Previous
          </button>
          <span style={{ color: 'var(--text-secondary)', fontSize: 12, padding: '6px 0' }}>
            {from + 1}–{Math.min(from + 20, rules.total)} of {rules.total}
          </span>
          <button
            onClick={() => setFrom(from + 20)}
            disabled={from + 20 >= (rules.total || 0)}
            style={{ padding: '6px 12px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-secondary)', cursor: 'pointer', fontSize: 12 }}
          >
            Next →
          </button>
        </div>
      )}
    </div>
  )
}

export default function HuntingPage() {
  const [tab, setTab] = useState<Tab>('pivot')

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>Threat Hunting Workbench</h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 24 }}>
        Correlate IOCs across threat intel, detection rules, and malware families.
      </p>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 24, borderBottom: '1px solid var(--border)' }}>
        {([
          ['pivot', 'Pivot Search'],
          ['families', 'Malware Families'],
          ['yara', 'YARA Rules'],
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
              fontWeight: 500,
              transition: 'color 0.2s',
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'pivot' && <PivotTab />}
      {tab === 'families' && <MalwareFamiliesTab />}
      {tab === 'yara' && <YARATab />}
    </div>
  )
}
