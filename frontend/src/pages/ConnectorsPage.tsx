import { useQuery, useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { getConnectors, triggerConnector } from '../api/client'

export default function ConnectorsPage() {
  const { data: connectors, isLoading } = useQuery({
    queryKey: ['connectors'],
    queryFn: () => getConnectors().then((r) => r.data),
  })

  const trigger = useMutation({
    mutationFn: (name: string) => triggerConnector(name),
    onSuccess: (_, name) => toast.success(`Triggered ${name}`),
    onError: () => toast.error('Failed to trigger connector'),
  })

  const typeColors: Record<string, string> = {
    import_external: '#3b82f6',
    enrichment: '#10b981',
    stream: '#8b5cf6',
    export: '#f59e0b',
  }

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>Connectors</h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 24 }}>
        Data import and enrichment connectors. Trigger manually or let the scheduler run them.
      </p>

      {isLoading ? (
        <div style={{ color: 'var(--text-secondary)' }}>Loading...</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 16 }}>
          {(connectors || []).map((c: any) => (
            <div key={c.name} style={{
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderLeft: `3px solid ${typeColors[c.type] || '#6b7280'}`,
              borderRadius: 6,
              padding: 16,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600 }}>{c.display_name}</div>
                  <span style={{
                    fontSize: 10, padding: '2px 7px', borderRadius: 8, marginTop: 4, display: 'inline-block',
                    background: `${typeColors[c.type] || '#6b7280'}22`, color: typeColors[c.type] || '#6b7280',
                  }}>
                    {c.type}
                  </span>
                </div>
                <button
                  onClick={() => trigger.mutate(c.name)}
                  disabled={trigger.isPending}
                  style={{
                    padding: '5px 12px', background: 'var(--accent)', color: '#fff',
                    border: 'none', borderRadius: 5, cursor: 'pointer', fontSize: 12, fontWeight: 600,
                  }}
                >
                  Run Now
                </button>
              </div>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '8px 0', lineHeight: 1.5 }}>
                {c.description}
              </p>
              <div style={{ fontSize: 11, color: '#4a5568', marginTop: 8 }}>
                Schedule: <code style={{ color: 'var(--text-secondary)' }}>{c.schedule}</code>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
