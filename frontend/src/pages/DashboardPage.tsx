import { useQuery } from '@tanstack/react-query'
import {
  getDarkwebSummary, getRansomwareStats, getAlerts,
  getConnectors, getIntelStats,
} from '../api/client'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  LineChart, Line, CartesianGrid,
} from 'recharts'

export default function DashboardPage() {
  const { data: darkwebSummary } = useQuery({
    queryKey: ['darkweb-summary'],
    queryFn: () => getDarkwebSummary().then((r) => r.data),
  })
  const { data: ransomStats } = useQuery({
    queryKey: ['ransom-stats'],
    queryFn: () => getRansomwareStats().then((r) => r.data),
  })
  const { data: alerts } = useQuery({
    queryKey: ['alerts'],
    queryFn: () => getAlerts({ status: 'new', size: 5 }).then((r) => r.data),
  })
  const { data: connectors } = useQuery({
    queryKey: ['connectors'],
    queryFn: () => getConnectors().then((r) => r.data),
  })
  const { data: intelStats } = useQuery({
    queryKey: ['intel-stats'],
    queryFn: () => getIntelStats().then((r) => r.data),
    refetchInterval: 60000,
  })

  const byGroup = Object.entries(ransomStats?.by_group || {})
    .sort(([, a], [, b]) => (b as number) - (a as number))
    .slice(0, 8)
    .map(([name, count]) => ({ name, count }))

  const overTime = (ransomStats?.over_time || []).slice(-12)

  const bySource = intelStats?.by_source || {}
  const c2Count = (bySource['feodotracker'] || 0) + (bySource['sslbl'] || 0)
  const phishCount = (bySource['openphish'] || 0)
  const attackIpCount = (bySource['dshield'] || 0)
  const malwareIocCount = (bySource['threatfox'] || 0)
  const urlCount = (bySource['urlhaus'] || 0)
  const vulnCount = intelStats?.by_type?.['vulnerability'] || 0
  const mitreCount = (bySource['mitre-attack'] || 0)

  // Source breakdown for bar chart
  const sourceData = Object.entries(bySource)
    .sort(([, a], [, b]) => (b as number) - (a as number))
    .slice(0, 10)
    .map(([name, count]) => ({ name: name.replace('-', '\u2011'), count }))

  return (
    <div style={{ padding: 16, overflowX: 'hidden' }}>
      <h1 style={{ fontSize: 18, fontWeight: 700, marginBottom: 16 }}>Dashboard</h1>

      {/* Primary stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10, marginBottom: 10 }}>
        <StatCard label="Ransom Victims" value={ransomStats?.total ?? 0} color="#ef4444" />
        <StatCard label="Total Indicators" value={intelStats?.total ?? 0} color="#3b82f6" />
        <StatCard label="Malicious URLs" value={urlCount} color="#f59e0b" />
        <StatCard label="MITRE ATT&CK" value={mitreCount} color="#8b5cf6" />
      </div>

      {/* Secondary stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 16 }}>
        <StatCard label="C2 Servers" value={c2Count} color="#ef4444" small />
        <StatCard label="Phishing URLs" value={phishCount} color="#f97316" small />
        <StatCard label="Attack Sources" value={attackIpCount} color="#eab308" small />
        <StatCard label="Malware IOCs" value={malwareIocCount} color="#06b6d4" small />
        <StatCard label="Vulns (KEV)" value={vulnCount} color="#10b981" small />
        <StatCard label="Cred Exposures" value={darkwebSummary?.credential_exposures ?? 0} color="#a855f7" small />
      </div>

      {/* Ransomware by group chart */}
      {byGroup.length > 0 && (
        <div style={{ ...cardStyle, marginBottom: 16 }}>
          <h3 style={cardTitle}>Top Ransomware Groups</h3>
          <div style={{ width: '100%', overflowX: 'auto' }}>
            <BarChart width={Math.max(300, byGroup.length * 60)} height={180} data={byGroup}>
              <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#1e2533', border: '1px solid #2d3748', color: '#e2e8f0', fontSize: 12 }} />
              <Bar dataKey="count" fill="#ef4444" radius={[3, 3, 0, 0]} />
            </BarChart>
          </div>
        </div>
      )}

      {/* Intel by source chart */}
      {sourceData.length > 0 && (
        <div style={{ ...cardStyle, marginBottom: 16 }}>
          <h3 style={cardTitle}>Intel by Source</h3>
          <div style={{ width: '100%', overflowX: 'auto' }}>
            <BarChart width={Math.max(300, sourceData.length * 70)} height={180} data={sourceData}>
              <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#1e2533', border: '1px solid #2d3748', color: '#e2e8f0', fontSize: 12 }} />
              <Bar dataKey="count" fill="#3b82f6" radius={[3, 3, 0, 0]} />
            </BarChart>
          </div>
        </div>
      )}

      {/* Victims over time chart */}
      {overTime.length > 0 && (
        <div style={{ ...cardStyle, marginBottom: 16 }}>
          <h3 style={cardTitle}>Ransomware Victims Over Time</h3>
          <div style={{ width: '100%', overflowX: 'auto' }}>
            <LineChart width={Math.max(300, overTime.length * 40)} height={150} data={overTime}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" />
              <XAxis dataKey="date" tick={{ fill: '#94a3b8', fontSize: 10 }} tickFormatter={(v) => (v || '').slice(0, 7)} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#1e2533', border: '1px solid #2d3748', color: '#e2e8f0', fontSize: 12 }} />
              <Line type="monotone" dataKey="count" stroke="#3b82f6" dot={false} strokeWidth={2} />
            </LineChart>
          </div>
        </div>
      )}

      {/* Recent alerts */}
      {(alerts?.objects || []).length > 0 && (
        <div style={{ ...cardStyle, marginBottom: 16 }}>
          <h3 style={cardTitle}>Recent Alerts</h3>
          {(alerts?.objects || []).map((a: any) => (
            <div key={a.id} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '7px 0', borderBottom: '1px solid var(--border)',
            }}>
              <div style={{ fontSize: 12 }}>{a.title}</div>
              <div style={{
                fontSize: 10, padding: '2px 7px', borderRadius: 10,
                background: a.severity === 'critical' ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.15)',
                color: a.severity === 'critical' ? '#ef4444' : '#f59e0b',
              }}>{a.severity}</div>
            </div>
          ))}
        </div>
      )}

      {/* Connectors */}
      <div style={cardStyle}>
        <h3 style={cardTitle}>Connectors ({(connectors || []).length})</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 8 }}>
          {(connectors || []).map((c: any) => (
            <div key={c.name} style={{
              background: 'var(--bg-primary)',
              border: '1px solid var(--border)',
              borderRadius: 5,
              padding: '8px 10px',
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 500 }}>{c.display_name}</div>
                <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>{c.schedule}</div>
              </div>
              <div style={{
                fontSize: 10, padding: '2px 7px', borderRadius: 10,
                background: 'rgba(16,185,129,0.15)', color: '#10b981', whiteSpace: 'nowrap',
              }}>
                active
              </div>
            </div>
          ))}
        </div>
        {!(connectors?.length) && (
          <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Loading connectors...</div>
        )}
      </div>
    </div>
  )
}

function StatCard({ label, value, color, small }: {
  label: string; value: number; color: string; small?: boolean
}) {
  return (
    <div style={{
      background: 'var(--bg-secondary)',
      border: `1px solid var(--border)`,
      borderLeft: `3px solid ${color}`,
      borderRadius: 6,
      padding: small ? '10px 12px' : '12px 14px',
    }}>
      <div style={{ fontSize: small ? 18 : 24, fontWeight: 700, color }}>{(value || 0).toLocaleString()}</div>
      <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>{label}</div>
    </div>
  )
}

const cardStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: 16,
}

const cardTitle: React.CSSProperties = {
  fontSize: 13, fontWeight: 600, marginBottom: 12, color: 'var(--text-primary)',
}
