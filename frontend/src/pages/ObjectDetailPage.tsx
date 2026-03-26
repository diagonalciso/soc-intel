import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getObject, getObjectRelationships } from '../api/client'

export default function ObjectDetailPage() {
  const { stixId } = useParams<{ stixId: string }>()

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

  if (isLoading) return <div style={{ padding: 40, color: 'var(--text-secondary)' }}>Loading...</div>
  if (!obj) return <div style={{ padding: 40, color: 'var(--text-secondary)' }}>Object not found</div>

  const customFields = Object.entries(obj).filter(
    ([k]) => k.startsWith('x_clawint_') || k.startsWith('x_opencti_')
  )

  return (
    <div style={{ padding: 24, maxWidth: 900 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <span style={{
          fontSize: 11, padding: '3px 9px', borderRadius: 8,
          background: '#1e3a5f', color: '#60a5fa', fontFamily: 'monospace',
        }}>
          {obj.type}
        </span>
        <h1 style={{ fontSize: 20, fontWeight: 700 }}>{obj.name || obj.id}</h1>
      </div>

      {/* Core fields */}
      <div style={sectionStyle}>
        <h2 style={sectionTitle}>Details</h2>
        <Fields data={{
          ID: obj.id,
          'Spec Version': obj.spec_version,
          Created: obj.created?.slice(0, 19).replace('T', ' '),
          Modified: obj.modified?.slice(0, 19).replace('T', ' '),
          Confidence: obj.confidence,
          TLP: (obj.object_marking_refs || []).join(', '),
          Description: obj.description,
          Labels: (obj.labels || []).join(', '),
          Pattern: obj.pattern,
          'Valid From': obj.valid_from?.slice(0, 10),
        }} />
      </div>

      {/* Custom fields */}
      {customFields.length > 0 && (
        <div style={sectionStyle}>
          <h2 style={sectionTitle}>Extended Attributes</h2>
          <Fields data={Object.fromEntries(customFields.map(([k, v]) => [k.replace('x_clawint_', ''), v]))} />
        </div>
      )}

      {/* External references */}
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

      {/* Relationships */}
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
                  <td style={{ padding: '8px 8px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                    {rel.source_ref}
                  </td>
                  <td style={{ padding: '8px 8px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                    {rel.target_ref}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
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
