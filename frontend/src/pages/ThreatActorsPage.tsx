import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { getThreatActors, searchObjects } from '../api/client'

interface ThreatActor {
  id: string
  name: string
  description?: string
  threat_actor_types?: string[]
  aliases?: string[]
  first_seen?: string
  last_seen?: string
  sophistication?: string
  resource_level?: string
  primary_motivation?: string
  labels?: string[]
  x_clawint_source?: string
  tlp?: string
  confidence?: number
  created?: string
  modified?: string
}

const SOPHISTICATION_COLOR: Record<string, string> = {
  none:        '#6b7280',
  minimal:     '#6b7280',
  intermediate:'#f59e0b',
  advanced:    '#f97316',
  expert:      '#ef4444',
  innovator:   '#dc2626',
  strategic:   '#b91c1c',
}

const SEV_COLOR = (s: string) => SOPHISTICATION_COLOR[s?.toLowerCase()] || '#6b7280'

export default function ThreatActorsPage() {
  const nav = useNavigate()
  const [search, setSearch] = useState('')
  const [intrSearch, setIntrSearch] = useState('')

  const { data: actorsData, isLoading: actorsLoading } = useQuery({
    queryKey: ['threat-actors', search],
    queryFn: () => getThreatActors({ q: search || undefined, size: 100 }).then((r) => r.data),
    placeholderData: (prev: unknown) => prev,
  })

  const { data: intrusionData, isLoading: intrusionLoading } = useQuery({
    queryKey: ['intrusion-sets', intrSearch],
    queryFn: () =>
      searchObjects({ type: 'intrusion-set', q: intrSearch || undefined, size: 100 }).then((r) => r.data),
    placeholderData: (prev: unknown) => prev,
  })

  const actors: ThreatActor[] = actorsData?.objects || []
  const intrusions: ThreatActor[] = intrusionData?.objects || []

  return (
    <div style={{ padding: 16 }}>
      <h1 style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Threat Actors</h1>
      <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
        Nation-state actors, criminal groups, and hacktivists tracked in SOCINT
      </div>

      {/* Threat Actors */}
      <div style={sectionStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600 }}>
            Threat Actors{actorsData?.total != null && ` (${actorsData.total})`}
          </h2>
          <input
            placeholder="Search actors..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={inputStyle}
          />
        </div>

        {actorsLoading ? (
          <div style={emptyStyle}>Loading...</div>
        ) : actors.length === 0 ? (
          <div style={emptyStyle}>No threat actors found. Run the MITRE ATT&CK connector to populate.</div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 10 }}>
            {actors.map((a) => (
              <ActorCard key={a.id} actor={a} onClick={() => nav(`/intel/${a.id}`)} />
            ))}
          </div>
        )}
      </div>

      {/* Intrusion Sets */}
      <div style={sectionStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600 }}>
            Intrusion Sets{intrusionData?.total != null && ` (${intrusionData.total})`}
          </h2>
          <input
            placeholder="Search intrusion sets..."
            value={intrSearch}
            onChange={(e) => setIntrSearch(e.target.value)}
            style={inputStyle}
          />
        </div>

        {intrusionLoading ? (
          <div style={emptyStyle}>Loading...</div>
        ) : intrusions.length === 0 ? (
          <div style={emptyStyle}>No intrusion sets found.</div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 10 }}>
            {intrusions.map((a) => (
              <ActorCard key={a.id} actor={a} onClick={() => nav(`/intel/${a.id}`)} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function ActorCard({ actor, onClick }: { actor: ThreatActor; onClick: () => void }) {
  const soph = actor.sophistication?.toLowerCase() || ''
  const sophColor = SEV_COLOR(soph)
  const types = actor.threat_actor_types || []
  const aliases = actor.aliases || []

  return (
    <div
      onClick={onClick}
      style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${sophColor}`,
        borderRadius: 6,
        padding: '12px 14px',
        cursor: 'pointer',
        transition: 'border-color 0.15s',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', flex: 1 }}>
          {actor.name}
        </div>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', flexShrink: 0 }}>
          {types.slice(0, 2).map((t) => (
            <span key={t} style={tagStyle('#3b82f6')}>{t.replace('-', ' ')}</span>
          ))}
        </div>
      </div>

      {aliases.length > 0 && (
        <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 4 }}>
          aka {aliases.slice(0, 4).join(', ')}
        </div>
      )}

      {actor.description && (
        <div style={{
          fontSize: 11, color: 'var(--text-secondary)', marginTop: 6,
          overflow: 'hidden', textOverflow: 'ellipsis', display: '-webkit-box',
          WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
        }}>
          {actor.description}
        </div>
      )}

      <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
        {soph && (
          <span style={tagStyle(sophColor)}>sophistication: {soph}</span>
        )}
        {actor.primary_motivation && (
          <span style={tagStyle('#8b5cf6')}>{actor.primary_motivation}</span>
        )}
        {actor.resource_level && (
          <span style={tagStyle('#6b7280')}>{actor.resource_level}</span>
        )}
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
        <div style={{ fontSize: 10, color: '#4a5568' }}>
          {actor.x_clawint_source || 'unknown source'}
        </div>
        {actor.confidence != null && (
          <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>
            conf: {actor.confidence}
          </div>
        )}
      </div>
    </div>
  )
}

const sectionStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: 16,
  marginBottom: 16,
}

const inputStyle: React.CSSProperties = {
  background: 'var(--bg-primary)',
  border: '1px solid var(--border)',
  borderRadius: 4,
  color: 'var(--text-primary)',
  padding: '5px 10px',
  fontSize: 12,
  width: 200,
}

const emptyStyle: React.CSSProperties = {
  fontSize: 12,
  color: 'var(--text-secondary)',
  padding: '12px 0',
}

const tagStyle = (color: string): React.CSSProperties => ({
  fontSize: 9,
  padding: '2px 6px',
  borderRadius: 10,
  background: `${color}20`,
  color,
  whiteSpace: 'nowrap',
})
