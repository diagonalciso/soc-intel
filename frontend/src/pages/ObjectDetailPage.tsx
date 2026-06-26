import { useState, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import CytoscapeComponent from 'react-cytoscapejs'
import { getObject, getObjectRelationships, getObjectGraph, getSightings, createSighting } from '../api/client'

const NODE_COLORS: Record<string, string> = {
  'threat-actor':    '#ef4444',
  'intrusion-set':  '#f97316',
  'campaign':       '#f59e0b',
  'malware':        '#a855f7',
  'tool':           '#8b5cf6',
  'attack-pattern': '#3b82f6',
  'vulnerability':  '#06b6d4',
  'indicator':      '#10b981',
  'infrastructure': '#6366f1',
  'identity':       '#ec4899',
  'report':         '#84cc16',
}

function nodeColor(type: string, isRoot: boolean): string {
  if (isRoot) return '#3b82f6'
  return NODE_COLORS[type] || '#94a3b8'
}

const TLP_COLORS: Record<string, { bg: string; text: string }> = {
  'TLP:CLEAR':        { bg: '#166534', text: '#bbf7d0' },
  'TLP:GREEN':        { bg: '#166534', text: '#bbf7d0' },
  'TLP:AMBER':        { bg: '#92400e', text: '#fde68a' },
  'TLP:AMBER+STRICT': { bg: '#7c2d12', text: '#fed7aa' },
  'TLP:RED':          { bg: '#7f1d1d', text: '#fca5a5' },
}

export default function ObjectDetailPage() {
  const { stixId } = useParams<{ stixId: string }>()
  const navigate      = useNavigate()
  const queryClient   = useQueryClient()
  const [tab, setTab] = useState<'details' | 'graph'>('details')
  const cyRef = useRef<any>(null)

  const { data: obj, isLoading } = useQuery({
    queryKey: ['object', stixId],
    queryFn: () => getObject(stixId!).then((r) => r.data),
    enabled: !!stixId,
  })

  const { data: rels } = useQuery({
    queryKey: ['object-rels', stixId],
    queryFn: () => getObjectRelationships(stixId!).then((r) => r.data),
    enabled: !!stixId,
  })

  const { data: graph } = useQuery({
    queryKey: ['object-graph', stixId],
    queryFn: () => getObjectGraph(stixId!).then((r) => r.data),
    enabled: !!stixId && tab === 'graph',
  })

  const { data: sightingsData } = useQuery({
    queryKey: ['sightings', stixId],
    queryFn: () => getSightings(stixId!).then((r) => r.data),
    enabled: !!stixId && obj?.type === 'indicator',
  })

  const sightMutation = useMutation({
    mutationFn: () => createSighting({ sighting_of_ref: stixId!, count: 1, source: 'manual' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sightings', stixId] })
      queryClient.invalidateQueries({ queryKey: ['object', stixId] })
    },
  })

  if (isLoading) return <div style={{ padding: 40, color: 'var(--text-secondary)' }}>Loading...</div>
  if (!obj) return <div style={{ padding: 40, color: 'var(--text-secondary)' }}>Object not found</div>

  // Build Cytoscape elements
  const cyElements = [
    ...(graph?.nodes || []).map((n: any) => ({
      data: {
        id:    n.id,
        label: n.label?.slice(0, 28) || n.id.slice(0, 24),
        type:  n.type,
        root:  n.root,
        color: nodeColor(n.type, n.root),
      },
    })),
    ...(graph?.edges || []).map((e: any) => ({
      data: {
        id:     e.id,
        source: e.source,
        target: e.target,
        label:  e.label,
      },
    })),
  ]

  const cyLayout = {
    name: 'cose',
    animate: false,
    randomize: false,
    nodeRepulsion: 8000,
    idealEdgeLength: 120,
    gravity: 0.25,
  }

  const customFields = Object.entries(obj).filter(
    ([k]) => k.startsWith('x_clawint_') || k.startsWith('x_opencti_')
  )

  return (
    <div style={{ padding: 24, maxWidth: tab === 'graph' ? '100%' : 900 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
        <span style={{
          fontSize: 11, padding: '3px 9px', borderRadius: 8,
          background: '#1e3a5f', color: '#60a5fa', fontFamily: 'monospace',
        }}>
          {obj.type}
        </span>
        {obj.tlp && (() => {
          const c = TLP_COLORS[obj.tlp] || { bg: '#1e293b', text: '#94a3b8' }
          return (
            <span style={{
              fontSize: 10, padding: '3px 8px', borderRadius: 4, fontWeight: 700,
              background: c.bg, color: c.text, fontFamily: 'monospace', letterSpacing: 0.3,
            }}>
              {obj.tlp}
            </span>
          )
        })()}
        <h1 style={{ fontSize: 20, fontWeight: 700, flex: 1 }}>{obj.name || obj.id}</h1>
        {obj.type === 'indicator' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {(sightingsData?.total ?? obj.x_clawint_sighting_count ?? 0) > 0 && (
              <span style={{
                fontSize: 11, padding: '4px 10px', borderRadius: 12,
                background: '#064e3b', color: '#6ee7b7', fontWeight: 600,
              }}>
                👁 {sightingsData?.total ?? obj.x_clawint_sighting_count} sighting{(sightingsData?.total ?? 1) !== 1 ? 's' : ''}
              </span>
            )}
            <button
              onClick={() => sightMutation.mutate()}
              disabled={sightMutation.isPending}
              style={{
                padding: '6px 14px', fontSize: 12, fontWeight: 500,
                background: sightMutation.isPending ? '#1e293b' : '#1d4ed8',
                color: '#e2e8f0', border: 'none', borderRadius: 6, cursor: 'pointer',
              }}
            >
              {sightMutation.isPending ? 'Reporting…' : '+ Report Sighting'}
            </button>
          </div>
        )}
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 2, marginBottom: 20, borderBottom: '1px solid var(--border)' }}>
        {(['details', 'graph'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: '7px 16px', fontSize: 12, fontWeight: 500,
              background: 'none', border: 'none', cursor: 'pointer',
              color: tab === t ? 'var(--accent)' : 'var(--text-secondary)',
              borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
              marginBottom: -1,
              textTransform: 'capitalize',
            }}
          >
            {t === 'graph' ? `Graph (${(rels || []).length} rels)` : 'Details'}
          </button>
        ))}
      </div>

      {/* Graph tab */}
      {tab === 'graph' && (
        <div style={{ ...sectionStyle, padding: 0, overflow: 'hidden' }}>
          {!graph || cyElements.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-secondary)', fontSize: 13 }}>
              {!graph ? 'Loading graph...' : 'No relationships found for this object.'}
            </div>
          ) : (
            <>
              <div style={{
                padding: '8px 16px', borderBottom: '1px solid var(--border)',
                fontSize: 11, color: 'var(--text-secondary)',
                display: 'flex', gap: 16, flexWrap: 'wrap',
              }}>
                <span>{(graph?.nodes || []).length} nodes</span>
                <span>{(graph?.edges || []).length} relationships</span>
                <span style={{ marginLeft: 'auto', color: 'var(--text-secondary)' }}>
                  Click a node to navigate
                </span>
              </div>
              <CytoscapeComponent
                elements={cyElements}
                layout={cyLayout}
                style={{ width: '100%', height: 520 }}
                cy={(cy: any) => {
                  cyRef.current = cy
                  cy.on('tap', 'node', (evt: any) => {
                    const nodeId = evt.target.id()
                    if (nodeId !== stixId) {
                      navigate(`/intel/${nodeId}`)
                    }
                  })
                }}
                stylesheet={[
                  {
                    selector: 'node',
                    style: {
                      'background-color': 'data(color)',
                      'label': 'data(label)',
                      'color': '#e2e8f0',
                      'font-size': 9,
                      'text-valign': 'bottom',
                      'text-halign': 'center',
                      'text-margin-y': 4,
                      'width': 36,
                      'height': 36,
                      'border-width': 2,
                      'border-color': '#1a2030',
                      'text-max-width': 90,
                      'text-wrap': 'ellipsis',
                    },
                  },
                  {
                    selector: 'node[?root]',
                    style: {
                      'width': 48,
                      'height': 48,
                      'border-width': 3,
                      'border-color': '#93c5fd',
                    },
                  },
                  {
                    selector: 'edge',
                    style: {
                      'width': 1.5,
                      'line-color': '#374151',
                      'target-arrow-color': '#374151',
                      'target-arrow-shape': 'triangle',
                      'curve-style': 'bezier',
                      'label': 'data(label)',
                      'font-size': 8,
                      'color': '#6b7280',
                      'text-rotation': 'autorotate',
                    },
                  },
                  {
                    selector: 'node:selected',
                    style: {
                      'border-color': '#60a5fa',
                      'border-width': 3,
                    },
                  },
                ]}
              />
            </>
          )}
        </div>
      )}

      {/* Details tab */}
      {tab === 'details' && (() => {
        const customFields = Object.entries(obj).filter(
          ([k]) => (k.startsWith('x_clawint_') || k.startsWith('x_opencti_') || k.startsWith('x_cvss') || k.startsWith('x_epss') || k.startsWith('x_mitre'))
            && k !== 'x_clawint_tlp'  // shown in header badge
        )
        return (
          <>
            <div style={sectionStyle}>
              <h2 style={sectionTitle}>Details</h2>
              <Fields data={{
                ID: obj.id,
                'Spec Version': obj.spec_version,
                Created: obj.created?.slice(0, 19).replace('T', ' '),
                Modified: obj.modified?.slice(0, 19).replace('T', ' '),
                Confidence: obj.confidence,
                TLP: obj.tlp || (obj.object_marking_refs || []).join(', '),
                Description: obj.description,
                Labels: (obj.labels || []).join(', '),
                Pattern: obj.pattern,
                'Valid From': obj.valid_from?.slice(0, 10),
                Revoked: obj.revoked ? 'Yes' : undefined,
              }} />
            </div>

            {customFields.length > 0 && (
              <div style={sectionStyle}>
                <h2 style={sectionTitle}>Extended Attributes</h2>
                <Fields data={Object.fromEntries(
                  customFields.map(([k, v]) => [
                    k.replace('x_clawint_', '').replace('x_', '').replace(/_/g, ' '), v
                  ])
                )} />
              </div>
            )}

            {(obj.external_references || []).length > 0 && (
              <div style={sectionStyle}>
                <h2 style={sectionTitle}>External References</h2>
                {obj.external_references.map((ref: any, i: number) => (
                  <div key={i} style={{ marginBottom: 8, fontSize: 13 }}>
                    <strong style={{ color: 'var(--accent)' }}>{ref.source_name}</strong>
                    {ref.external_id && <span style={{ color: 'var(--text-secondary)', marginLeft: 8 }}>{ref.external_id}</span>}
                    {ref.url && (
                      <a href={ref.url} target="_blank" rel="noopener noreferrer" style={{ display: 'block', fontSize: 12, color: 'var(--accent)' }}>
                        {ref.url}
                      </a>
                    )}
                  </div>
                ))}
              </div>
            )}

            {(rels || []).length > 0 && (
              <div style={sectionStyle}>
                <h2 style={sectionTitle}>Relationships ({rels?.length})</h2>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr>
                      {['Relationship', 'Source', 'Target'].map((h) => (
                        <th key={h} style={{
                          textAlign: 'left', padding: '6px 8px', fontSize: 11,
                          color: 'var(--text-secondary)', borderBottom: '1px solid var(--border)',
                        }}>
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {(rels || []).map((rel: any) => (
                      <tr key={rel.id} style={{ borderBottom: '1px solid #1a2030' }}>
                        <td style={{ padding: '8px 8px', fontSize: 12, color: '#f59e0b' }}>
                          {rel.relationship_type}
                        </td>
                        <td
                          style={{ padding: '8px 8px', fontSize: 11, fontFamily: 'monospace', color: 'var(--accent)', cursor: 'pointer' }}
                          onClick={() => navigate(`/intel/${rel.source_ref}`)}
                        >
                          {rel.source_ref.slice(0, 48)}
                        </td>
                        <td
                          style={{ padding: '8px 8px', fontSize: 11, fontFamily: 'monospace', color: 'var(--accent)', cursor: 'pointer' }}
                          onClick={() => navigate(`/intel/${rel.target_ref}`)}
                        >
                          {rel.target_ref.slice(0, 48)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )
      })()}
    </div>
  )
}

function Fields({ data }: { data: Record<string, any> }) {
  const entries = Object.entries(data).filter(([, v]) => v != null && v !== '')
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '8px 16px' }}>
      {entries.map(([k, v]) => (
        <>
          <div key={k + '-k'} style={{ fontSize: 12, color: 'var(--text-secondary)', paddingTop: 2, whiteSpace: 'nowrap' }}>
            {k}
          </div>
          <div key={k + '-v'} style={{ fontSize: 13, wordBreak: 'break-all' }}>
            {typeof v === 'object' ? JSON.stringify(v) : String(v)}
          </div>
        </>
      ))}
    </div>
  )
}

const sectionStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)', border: '1px solid var(--border)',
  borderRadius: 6, padding: 20, marginBottom: 16,
}

const sectionTitle: React.CSSProperties = {
  fontSize: 13, fontWeight: 600, marginBottom: 16, color: 'var(--text-secondary)',
  textTransform: 'uppercase', letterSpacing: 1,
}
