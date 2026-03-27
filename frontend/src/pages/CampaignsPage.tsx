import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { searchObjects } from '../api/client'

interface Campaign {
  id: string
  name: string
  description?: string
  aliases?: string[]
  first_seen?: string
  last_seen?: string
  objective?: string
  labels?: string[]
  x_clawint_source?: string
  confidence?: number
  created?: string
  modified?: string
}

export default function CampaignsPage() {
  const nav = useNavigate()
  const [search, setSearch] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['campaigns', search],
    queryFn: () =>
      searchObjects({ type: 'campaign', q: search || undefined, size: 100 }).then((r) => r.data),
    placeholderData: (prev: unknown) => prev,
  })

  const campaigns: Campaign[] = data?.objects || []

  return (
    <div style={{ padding: 16 }}>
      <h1 style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Campaigns</h1>
      <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
        Tracked threat campaigns linked to actors, malware, and indicators
      </div>

      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div style={{ fontSize: 13, fontWeight: 600 }}>
            Campaigns{data?.total != null && ` (${data.total})`}
          </div>
          <input
            placeholder="Search campaigns..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={inputStyle}
          />
        </div>

        {isLoading ? (
          <div style={emptyStyle}>Loading...</div>
        ) : campaigns.length === 0 ? (
          <div style={emptyStyle}>
            No campaigns found. Create campaign objects via Intelligence → Create Object,
            or link them from threat actor profiles.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {campaigns.map((c) => (
              <CampaignRow key={c.id} campaign={c} onClick={() => nav(`/intel/${c.id}`)} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function CampaignRow({ campaign, onClick }: { campaign: Campaign; onClick: () => void }) {
  const aliases = campaign.aliases || []

  const firstSeen = campaign.first_seen
    ? new Date(campaign.first_seen).toLocaleDateString()
    : null
  const lastSeen = campaign.last_seen
    ? new Date(campaign.last_seen).toLocaleDateString()
    : null

  return (
    <div
      onClick={onClick}
      style={{
        background: 'var(--bg-primary)',
        border: '1px solid var(--border)',
        borderLeft: '3px solid #8b5cf6',
        borderRadius: 5,
        padding: '12px 14px',
        cursor: 'pointer',
        display: 'grid',
        gridTemplateColumns: '1fr auto',
        gap: 12,
        alignItems: 'start',
      }}
    >
      <div>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
          {campaign.name}
        </div>

        {aliases.length > 0 && (
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 3 }}>
            aka {aliases.slice(0, 4).join(', ')}
          </div>
        )}

        {campaign.description && (
          <div style={{
            fontSize: 11, color: 'var(--text-secondary)', marginTop: 6,
            overflow: 'hidden', textOverflow: 'ellipsis', display: '-webkit-box',
            WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
          }}>
            {campaign.description}
          </div>
        )}

        {campaign.objective && (
          <div style={{ fontSize: 11, color: '#8b5cf6', marginTop: 4 }}>
            Objective: {campaign.objective}
          </div>
        )}

        <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
          {(campaign.labels || []).slice(0, 4).map((l) => (
            <span key={l} style={{
              fontSize: 9, padding: '2px 6px', borderRadius: 10,
              background: 'rgba(139,92,246,0.15)', color: '#8b5cf6',
            }}>{l}</span>
          ))}
        </div>
      </div>

      <div style={{ textAlign: 'right', flexShrink: 0 }}>
        {firstSeen && (
          <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>
            First: {firstSeen}
          </div>
        )}
        {lastSeen && (
          <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>
            Last: {lastSeen}
          </div>
        )}
        {campaign.confidence != null && (
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 4 }}>
            conf: {campaign.confidence}
          </div>
        )}
        <div style={{ fontSize: 10, color: '#4a5568', marginTop: 4 }}>
          {campaign.x_clawint_source || 'manual'}
        </div>
      </div>
    </div>
  )
}

const cardStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: 16,
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
