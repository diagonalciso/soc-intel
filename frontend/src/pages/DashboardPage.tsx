import { useState, useMemo, useRef } from 'react'

const MOTD: string[] = [
  "Patch it before they hatch it.",
  "Your firewall called. It's overwhelmed.",
  "Have you tried turning off your attack surface?",
  "Today's forecast: 100% chance of phishing.",
  "Roses are red, violets are blue, port 22 is open, and so are you.",
  "In God we trust. All others we monitor.",
  "The attacker only has to be right once. You have to be right always. No pressure.",
  "Your password is bad and you should feel bad.",
  "Trust no one. Especially not that PDF from HR.",
  "Zero-day: when the vendor finds out the same time as the attacker.",
  "Error 403: Your OPSEC is forbidden.",
  "Threat intel: knowing what hit you before the postmortem.",
  "The call is coming from inside the subnet.",
  "We don't have a security problem, we have an awareness problem. And a security problem.",
  "Nation-state or script kiddie? The logs don't care.",
  "The chain is only as strong as the intern who clicked the link.",
  "If it's on the internet, it's everyone's attack surface.",
  "Ransomware: when your backups finally matter.",
  "Remember: the adversary also has a JIRA board.",
  "CVE just dropped. Have you met your new boss?",
  "IOC found. Containment optional. Chaos mandatory.",
  "Your SIEM has alerts. Your SOC has feelings.",
  "Every APT group started as a Tuesday.",
  "MFA: because one factor of forgetting your password wasn't enough.",
  "The threat is persistent. The advanced is debatable.",
  "Air gap: the network equivalent of hiding under the covers.",
  "Defense in depth means they have to pivot more.",
  "Lateral movement detected. Pizza tracker unavailable.",
  "Please rotate your credentials. And your soul.",
  "Your threat model is missing 'tired analyst at 3am'.",
  "STIX and stones may break my bones, but TAXII will never hurt me.",
  "Signed malware: because even hackers have code signing budgets now.",
  "Another day, another C2 beacon going home.",
  "Supply chain attack: why build a door when you can own the door factory?",
  "I SPF, therefore I spam.",
  "The CISO has left the building. The breach has not.",
  "It's not a backdoor, it's a 'legacy authentication pathway'.",
  "Living off the land: nature's APT technique.",
  "Credential stuffing: making password reuse someone else's problem.",
  "Your EDR is telling you things. Are you listening?",
  "DLP stands for: Did Lose the Password.",
  "Blue team: the night shift of the internet.",
  "Not all heroes wear capes. Some write YARA rules.",
  "Threat hunting: finding things you wish you hadn't.",
  "Your attack surface is showing.",
  "The darkweb called. Your data is doing well.",
  "Unpatched since 2019. Breached since 2019.",
  "Every indicator tells a story. This one is a tragedy.",
  "Least privilege: the principle everyone agrees with and nobody implements.",
  "The SOC analyst saw it. The ticket sat for 72 hours.",
  "Hardening a system: the art of making it less embarrassingly open.",
  "Pentest report delivered. Findings remediated: 0.",
  "We found it in the logs. We found it six months later.",
  "Assume breach. Then assume more breach.",
  "Your VPN is a false sense of security wrapped in UDP.",
  "The adversary has your org chart. Do you?",
  "Malware analysis: opening suspicious files so you don't have to.",
  "Phishing training: the one email your users will actually open.",
  "Behind every sophisticated attack is someone who found an open S3 bucket.",
  "Incident response begins before the incident.",
  "Compliance ≠ security. Please print and frame.",
  "The hash matched. The story didn't.",
  "Obfuscation is just job security for reverse engineers.",
  "PowerShell: the attacker's favorite feature.",
  "Defense is a team sport. Attackers get to play solo.",
  "Every CVE was once someone's Friday afternoon.",
  "Sandbox escaped. Analyst rebooting expectations.",
  "Your cloud config is public. So is your embarrassment.",
  "OSINT: the art of finding what you hoped no one would find.",
  "The breach notification letter template is ready. Just in case.",
  "Reputation feed says malicious. Finance says 'it's a vendor'.",
  "Threat actor renamed again. Same TTPs, new logo.",
  "When in doubt, pivot. When certain, also pivot.",
  "The log retention policy expired before the breach was discovered.",
  "IDS: I Detected Something. Now what?",
  "Your attack path looks like a career ladder.",
  "Encryption at rest: so they have to try harder.",
  "The IOC was on the blocklist. The blocklist wasn't deployed.",
  "Red team: paid to fail gracefully.",
  "404 security not found.",
  "Domain fronting: when the CDN becomes a co-conspirator.",
  "Beaconing every 300 seconds. Regular as rent.",
  "Threat intelligence is just structured anxiety.",
  "The firmware is fine. Probably.",
  "MITRE mapped. Remediated: eventually.",
  "Typosquatting: when one letter costs a million dollars.",
  "Every CISO has a plan until they get breached.",
  "Segmentation: the diet version of isolation.",
  "Adversary emulation: teaching the blue team to fear us professionally.",
  "Your OAuth scopes are writing checks your data can't cash.",
  "The analyst was right. The ticket was closed as a false positive.",
  "Memory forensics: archaeology for the recently compromised.",
  "Exfiltration complete. Thanks for the bandwidth.",
  "The payload was in the metadata.",
  "Security awareness training: watched, passed, forgotten.",
  "Dwell time: 197 days. Detection time: now.",
  "It's always DNS. Except when it's also DNS-over-HTTPS.",
  "Your third-party risk is having a great quarter.",
  "We have the telemetry. We lack the sleep.",
  "The crown jewels are in the public repo.",
  "Persistence mechanism: because they really like your network.",
]
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  getDarkwebSummary, getRansomwareStats, getAlerts,
  getConnectors, getIntelStats, pivotSearch,
} from '../api/client'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  LineChart, Line, CartesianGrid,
} from 'recharts'
import ThreatGlobe, { GlobeMarker, resolveCountry } from '../components/ui/ThreatGlobe'

export default function DashboardPage() {
  const nav = useNavigate()
  const motd = useRef(MOTD[Math.floor(Math.random() * MOTD.length)]).current
  const [pivotValue, setPivotValue] = useState('')
  const [pivotQuery, setPivotQuery] = useState('')
  const [pivotResults, setPivotResults] = useState<{ total: number; by_type: Record<string, number>; objects: unknown[] } | null>(null)
  const [pivotLoading, setPivotLoading] = useState(false)

  async function handlePivot() {
    if (!pivotQuery.trim()) return
    setPivotLoading(true)
    try {
      const res = await pivotSearch(pivotQuery.trim())
      setPivotResults(res.data)
    } catch {
      // ignore
    } finally {
      setPivotLoading(false)
    }
  }
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

  // Globe markers derived from ransomware victim countries
  const globeMarkers: GlobeMarker[] = useMemo(() => {
    const byCountry = ransomStats?.by_country as Record<string, number> | undefined
    if (!byCountry) return []
    const max = Math.max(...Object.values(byCountry), 1)
    const markers: GlobeMarker[] = []
    for (const [country, count] of Object.entries(byCountry)) {
      const coords = resolveCountry(country)
      if (!coords) continue
      // Jitter to avoid overlap for same-country multi-source markers
      const jitter = (): number => (Math.random() - 0.5) * 0.8
      markers.push({
        location: [coords[0] + jitter(), coords[1] + jitter()],
        size: 0.025 + (count / max) * 0.09,
        label: country,
        count,
      })
    }
    return markers
  }, [ransomStats?.by_country])

  // Top countries by victim count for the legend
  const topCountries = useMemo(() => {
    const byCountry = ransomStats?.by_country as Record<string, number> | undefined
    if (!byCountry) return []
    return Object.entries(byCountry)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
  }, [ransomStats?.by_country])

  return (
    <div style={{ padding: 16, overflowX: 'hidden' }}>
      <h1 style={{ fontSize: 18, fontWeight: 700, marginBottom: 6 }}>Dashboard</h1>
      <div style={{ fontSize: 12, color: '#4a7c59', fontStyle: 'italic', marginBottom: 16 }}>
        💀 {motd}
      </div>

      {/* Threat Globe */}
      <div style={{
        ...cardStyle,
        marginBottom: 16,
        display: 'flex',
        gap: 24,
        alignItems: 'center',
        flexWrap: 'wrap',
      }}>
        {/* Globe canvas */}
        <div style={{ flexShrink: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
          <ThreatGlobe markers={globeMarkers} width={340} />
          <div style={{ fontSize: 10, color: '#4a5568', letterSpacing: 1 }}>
            RECENT INCIDENT LOCATIONS
          </div>
        </div>

        {/* Right panel: title + legend */}
        <div style={{ flex: 1, minWidth: 180 }}>
          <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            Global Threat Map
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.5 }}>
            Ransomware victim locations from all active data sources.
            Marker size reflects victim count.
          </div>

          {topCountries.length > 0 ? (
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-secondary)', fontWeight: 600, letterSpacing: 1, marginBottom: 8 }}>
                TOP AFFECTED COUNTRIES
              </div>
              {topCountries.map(([country, count], i) => (
                <div key={country} style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '4px 0', borderBottom: '1px solid var(--border)',
                }}>
                  <div style={{
                    width: 18, height: 18, borderRadius: '50%',
                    background: `rgba(239,68,68,${0.9 - i * 0.08})`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 9, color: '#fff', fontWeight: 700, flexShrink: 0,
                  }}>
                    {i + 1}
                  </div>
                  <div style={{ fontSize: 12, flex: 1, textTransform: 'capitalize' }}>
                    {country.toLowerCase()}
                  </div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: '#ef4444' }}>
                    {count}
                  </div>
                  {/* mini bar */}
                  <div style={{
                    width: 50, height: 4, background: 'var(--border)', borderRadius: 2, flexShrink: 0,
                  }}>
                    <div style={{
                      height: '100%',
                      width: `${Math.round((count / (topCountries[0][1] as number)) * 100)}%`,
                      background: '#ef4444', borderRadius: 2,
                    }} />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              No victim location data yet — run ransomware connectors to populate.
            </div>
          )}

          <div style={{ marginTop: 14, display: 'flex', gap: 16 }}>
            <LegendDot color="#ef4444" label="Ransomware victim" />
          </div>
        </div>
      </div>

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

      {/* Pivot Search */}
      <div style={{ ...cardStyle, marginBottom: 16 }}>
        <h3 style={cardTitle}>Pivot Search</h3>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input
            value={pivotQuery}
            onChange={(e) => setPivotQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handlePivot()}
            placeholder="Search by IOC, actor name, malware, CVE-ID..."
            style={{
              flex: 1, background: 'var(--bg-primary)', border: '1px solid var(--border)',
              borderRadius: 4, color: 'var(--text-primary)', padding: '7px 12px', fontSize: 12,
            }}
          />
          <button
            onClick={handlePivot}
            disabled={pivotLoading}
            style={{
              background: 'var(--accent)', color: '#fff', border: 'none',
              borderRadius: 4, padding: '7px 16px', fontSize: 12, cursor: 'pointer', fontWeight: 600,
            }}
          >
            {pivotLoading ? '...' : 'Search'}
          </button>
        </div>
        {pivotResults && (
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8 }}>
              {pivotResults.total} results across {Object.keys(pivotResults.by_type).length} object types
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
              {Object.entries(pivotResults.by_type).map(([type, count]) => (
                <span key={type} style={{
                  fontSize: 10, padding: '2px 8px', borderRadius: 10,
                  background: 'rgba(59,130,246,0.15)', color: '#3b82f6',
                }}>
                  {type} ({count})
                </span>
              ))}
            </div>
            {(pivotResults.objects as { id: string; type: string; name?: string }[]).slice(0, 8).map((obj) => (
              <div
                key={obj.id}
                onClick={() => nav(`/intel/${obj.id}`)}
                style={{
                  padding: '6px 10px', border: '1px solid var(--border)', borderRadius: 4,
                  marginBottom: 4, cursor: 'pointer', display: 'flex', gap: 8, alignItems: 'center',
                  background: 'var(--bg-primary)',
                }}
              >
                <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 10, background: 'rgba(59,130,246,0.15)', color: '#3b82f6' }}>
                  {obj.type}
                </span>
                <span style={{ fontSize: 12 }}>{obj.name || obj.id}</span>
              </div>
            ))}
            {pivotResults.objects.length > 8 && (
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                +{pivotResults.objects.length - 8} more — use Intelligence search for full results
              </div>
            )}
          </div>
        )}
      </div>

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

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{ width: 8, height: 8, borderRadius: '50%', background: color, flexShrink: 0 }} />
      <span style={{ fontSize: 10, color: 'var(--text-secondary)' }}>{label}</span>
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
