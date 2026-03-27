import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { searchObjects } from '../api/client'

// MITRE ATT&CK Enterprise tactic order + display names
const TACTICS: { id: string; name: string; short: string }[] = [
  { id: 'reconnaissance',       name: 'Reconnaissance',       short: 'Recon' },
  { id: 'resource-development', name: 'Resource Development',  short: 'Resource Dev' },
  { id: 'initial-access',       name: 'Initial Access',        short: 'Initial Access' },
  { id: 'execution',            name: 'Execution',             short: 'Execution' },
  { id: 'persistence',          name: 'Persistence',           short: 'Persistence' },
  { id: 'privilege-escalation', name: 'Privilege Escalation',  short: 'Priv Esc' },
  { id: 'defense-evasion',      name: 'Defense Evasion',       short: 'Def Evasion' },
  { id: 'credential-access',    name: 'Credential Access',     short: 'Cred Access' },
  { id: 'discovery',            name: 'Discovery',             short: 'Discovery' },
  { id: 'lateral-movement',     name: 'Lateral Movement',      short: 'Lateral Move' },
  { id: 'collection',           name: 'Collection',            short: 'Collection' },
  { id: 'command-and-control',  name: 'Command & Control',     short: 'C2' },
  { id: 'exfiltration',         name: 'Exfiltration',          short: 'Exfil' },
  { id: 'impact',               name: 'Impact',                short: 'Impact' },
]

interface AttackPattern {
  id: string
  name: string
  description?: string
  kill_chain_phases?: { kill_chain_name: string; phase_name: string }[]
  external_references?: { source_name: string; external_id?: string; url?: string }[]
  x_mitre_is_subtechnique?: boolean
}

export default function AttackPage() {
  const navigate = useNavigate()
  const [selected, setSelected] = useState<AttackPattern | null>(null)
  const [showSubs, setShowSubs] = useState(true)

  const { data, isLoading } = useQuery({
    queryKey: ['attack-patterns'],
    queryFn: () =>
      searchObjects({ type: 'attack-pattern', size: 500 }).then((r) => r.data),
    staleTime: 5 * 60 * 1000,
  })

  const patterns: AttackPattern[] = data?.objects || []

  // Group by tactic phase_name
  const byTactic: Record<string, AttackPattern[]> = {}
  for (const p of patterns) {
    if (!showSubs && p.x_mitre_is_subtechnique) continue
    for (const kc of p.kill_chain_phases || []) {
      if (kc.kill_chain_name !== 'mitre-attack') continue
      const phase = kc.phase_name
      if (!byTactic[phase]) byTactic[phase] = []
      byTactic[phase].push(p)
    }
  }

  // Sort each tactic's techniques by technique ID
  for (const phase of Object.keys(byTactic)) {
    byTactic[phase].sort((a, b) => {
      const idA = _techniqueId(a) || ''
      const idB = _techniqueId(b) || ''
      return idA.localeCompare(idB)
    })
  }

  const totalCovered = patterns.filter(
    (p) => !p.x_mitre_is_subtechnique || showSubs
  ).length

  return (
    <div style={{ padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, margin: 0 }}>MITRE ATT&CK Navigator</h1>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
            {totalCovered.toLocaleString()} techniques in knowledge base
          </div>
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={showSubs}
            onChange={(e) => setShowSubs(e.target.checked)}
            style={{ accentColor: 'var(--accent)' }}
          />
          Show sub-techniques
        </label>
      </div>

      {isLoading && (
        <div style={{ color: 'var(--text-secondary)', fontSize: 13 }}>Loading ATT&CK data...</div>
      )}

      {/* Heatmap grid */}
      <div style={{ overflowX: 'auto' }}>
        <div style={{ display: 'flex', gap: 4, minWidth: 'max-content' }}>
          {TACTICS.map((tactic) => {
            const techs = byTactic[tactic.id] || []
            return (
              <div key={tactic.id} style={{ width: 110, flexShrink: 0 }}>
                {/* Tactic header */}
                <div style={{
                  background: '#1e3a5f',
                  color: '#60a5fa',
                  padding: '6px 6px',
                  fontSize: 10,
                  fontWeight: 700,
                  borderRadius: '4px 4px 0 0',
                  textAlign: 'center',
                  marginBottom: 2,
                  minHeight: 40,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}>
                  {tactic.short}
                  <span style={{
                    display: 'block', fontSize: 9,
                    color: 'rgba(96,165,250,0.6)', marginTop: 2,
                  }}>
                    ({techs.length})
                  </span>
                </div>

                {/* Technique cells */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  {techs.length === 0 ? (
                    <div style={{
                      height: 32, background: 'var(--bg-secondary)',
                      borderRadius: 3, opacity: 0.3,
                    }} />
                  ) : (
                    techs.map((tech) => (
                      <TechCell
                        key={tech.id}
                        tech={tech}
                        isSelected={selected?.id === tech.id}
                        onClick={() => setSelected(selected?.id === tech.id ? null : tech)}
                      />
                    ))
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Technique detail panel */}
      {selected && (
        <div style={{
          position: 'fixed', right: 0, top: 0, bottom: 0, width: 360,
          background: 'var(--bg-secondary)', borderLeft: '1px solid var(--border)',
          padding: 20, overflowY: 'auto', zIndex: 100,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
            <div>
              <div style={{
                fontSize: 10, color: '#f59e0b', fontFamily: 'monospace',
                marginBottom: 4,
              }}>
                {_techniqueId(selected)}
              </div>
              <div style={{ fontSize: 15, fontWeight: 700 }}>{selected.name}</div>
            </div>
            <button
              onClick={() => setSelected(null)}
              style={{
                background: 'none', border: 'none', color: 'var(--text-secondary)',
                cursor: 'pointer', fontSize: 18, padding: '0 4px',
              }}
            >×</button>
          </div>

          {selected.x_mitre_is_subtechnique && (
            <div style={{
              fontSize: 10, padding: '2px 8px', borderRadius: 8,
              background: 'rgba(245,158,11,0.1)', color: '#f59e0b',
              display: 'inline-block', marginBottom: 10,
            }}>
              Sub-technique
            </div>
          )}

          <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 16 }}>
            {(selected.description || '').slice(0, 500)}
            {(selected.description || '').length > 500 ? '...' : ''}
          </div>

          {_techniqueUrl(selected) && (
            <a
              href={_techniqueUrl(selected)!}
              target="_blank"
              rel="noopener noreferrer"
              style={{ fontSize: 12, color: 'var(--accent)' }}
            >
              View on MITRE ATT&CK ↗
            </a>
          )}

          <div style={{ marginTop: 16 }}>
            <button
              onClick={() => navigate(`/intel/${selected.id}`)}
              style={{
                width: '100%', padding: '8px 0',
                background: 'rgba(59,130,246,0.1)',
                border: '1px solid rgba(59,130,246,0.3)',
                borderRadius: 5, color: 'var(--accent)',
                cursor: 'pointer', fontSize: 12,
              }}
            >
              Open in Intelligence View →
            </button>
          </div>
        </div>
      )}

      {/* Legend */}
      <div style={{ marginTop: 20, display: 'flex', gap: 20, fontSize: 11, color: 'var(--text-secondary)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 14, height: 14, background: '#1e4d2b', borderRadius: 2 }} />
          In knowledge base
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 14, height: 14, background: 'rgba(245,158,11,0.3)', borderRadius: 2 }} />
          Sub-technique
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 14, height: 14, background: 'var(--bg-secondary)', borderRadius: 2, opacity: 0.5, border: '1px solid var(--border)' }} />
          Not in knowledge base
        </div>
      </div>
    </div>
  )
}

function TechCell({ tech, isSelected, onClick }: {
  tech: AttackPattern
  isSelected: boolean
  onClick: () => void
}) {
  const techId = _techniqueId(tech) || ''
  const isSub  = tech.x_mitre_is_subtechnique

  return (
    <div
      title={`${techId} — ${tech.name}`}
      onClick={onClick}
      style={{
        padding: '4px 5px',
        borderRadius: 3,
        cursor: 'pointer',
        fontSize: 9,
        lineHeight: 1.3,
        background: isSelected
          ? 'rgba(59,130,246,0.25)'
          : isSub
            ? 'rgba(245,158,11,0.18)'
            : '#1e4d2b',
        border: isSelected
          ? '1px solid #3b82f6'
          : '1px solid transparent',
        color: isSelected ? '#93c5fd' : isSub ? '#fcd34d' : '#6ee7b7',
        transition: 'all 0.1s',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      }}
    >
      <div style={{ fontFamily: 'monospace', fontSize: 8, opacity: 0.7 }}>{techId}</div>
      <div style={{ marginTop: 1 }}>{tech.name}</div>
    </div>
  )
}

function _techniqueId(tech: AttackPattern): string | undefined {
  return tech.external_references
    ?.find((r) => r.source_name === 'mitre-attack')
    ?.external_id
}

function _techniqueUrl(tech: AttackPattern): string | undefined {
  return tech.external_references
    ?.find((r) => r.source_name === 'mitre-attack')
    ?.url
}
