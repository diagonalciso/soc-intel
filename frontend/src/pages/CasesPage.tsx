import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { getCases, createCase, updateCase } from '../api/client'

export default function CasesPage() {
  const qc = useQueryClient()
  const [showNew, setShowNew] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newSeverity, setNewSeverity] = useState('medium')
  const [filter, setFilter] = useState('')

  const { data } = useQuery({
    queryKey: ['cases', filter],
    queryFn: () => getCases(filter ? { status: filter } : {}).then((r) => r.data),
  })

  const create = useMutation({
    mutationFn: (d: any) => createCase(d).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cases'] })
      setShowNew(false)
      setNewTitle('')
      toast.success('Case created')
    },
  })

  const close = useMutation({
    mutationFn: ({ id }: { id: string }) => updateCase(id, { status: 'closed' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cases'] }),
  })

  const severityColors: Record<string, string> = {
    critical: '#dc2626', high: '#ef4444', medium: '#f59e0b', low: '#10b981',
  }
  const statusColors: Record<string, string> = {
    open: '#3b82f6', in_progress: '#f59e0b', resolved: '#10b981',
    closed: '#6b7280', pending: '#a855f7',
  }

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700 }}>Cases</h1>
        <button
          onClick={() => setShowNew(true)}
          style={{
            padding: '8px 16px', background: 'var(--accent)', color: '#fff',
            border: 'none', borderRadius: 6, cursor: 'pointer', fontSize: 13, fontWeight: 600,
          }}
        >
          + New Case
        </button>
      </div>

      {/* New case form */}
      {showNew && (
        <div style={{
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          borderRadius: 6, padding: 20, marginBottom: 16,
        }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>New Case</h3>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end' }}>
            <div style={{ flex: 1 }}>
              <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Title</label>
              <input
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                style={inputStyle}
                placeholder="Case title..."
              />
            </div>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Severity</label>
              <select
                value={newSeverity}
                onChange={(e) => setNewSeverity(e.target.value)}
                style={{ ...inputStyle, width: 130 }}
              >
                {['low', 'medium', 'high', 'critical'].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <button
              onClick={() => create.mutate({ title: newTitle, severity: newSeverity })}
              disabled={!newTitle.trim()}
              style={{
                padding: '8px 16px', background: 'var(--accent)', color: '#fff',
                border: 'none', borderRadius: 6, cursor: 'pointer', fontSize: 13,
              }}
            >
              Create
            </button>
            <button
              onClick={() => setShowNew(false)}
              style={{
                padding: '8px 12px', background: 'none', color: 'var(--text-secondary)',
                border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer', fontSize: 13,
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Filter */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        {['', 'open', 'in_progress', 'resolved', 'closed'].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            style={{
              padding: '4px 12px', background: filter === s ? 'var(--accent)' : 'var(--bg-secondary)',
              color: filter === s ? '#fff' : 'var(--text-secondary)',
              border: '1px solid var(--border)', borderRadius: 20, cursor: 'pointer', fontSize: 12,
            }}
          >
            {s || 'All'}
          </button>
        ))}
      </div>

      {/* Cases table */}
      <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['Title', 'Severity', 'Status', 'TLP', 'Tags', 'Created', 'Actions'].map((h) => (
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
            {(data || []).map((c: any) => (
              <tr key={c.id} style={{ borderBottom: '1px solid #1a2030' }}>
                <td style={{ padding: '10px 12px', fontSize: 13, fontWeight: 500 }}>{c.title}</td>
                <td style={{ padding: '10px 12px' }}>
                  <Badge label={c.severity} color={severityColors[c.severity] || '#6b7280'} />
                </td>
                <td style={{ padding: '10px 12px' }}>
                  <Badge label={c.status} color={statusColors[c.status] || '#6b7280'} />
                </td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-secondary)' }}>{c.tlp}</td>
                <td style={{ padding: '10px 12px', fontSize: 11 }}>
                  {(c.tags || []).map((t: string) => (
                    <span key={t} style={{
                      fontSize: 10, padding: '2px 6px', marginRight: 4,
                      background: '#1e3a5f', color: '#60a5fa', borderRadius: 8,
                    }}>{t}</span>
                  ))}
                </td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-secondary)' }}>
                  {c.created_at?.slice(0, 10)}
                </td>
                <td style={{ padding: '10px 12px' }}>
                  {c.status !== 'closed' && (
                    <button
                      onClick={() => close.mutate({ id: c.id })}
                      style={{
                        fontSize: 11, padding: '3px 8px',
                        background: 'none', border: '1px solid var(--border)',
                        color: 'var(--text-secondary)', borderRadius: 4, cursor: 'pointer',
                      }}
                    >
                      Close
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {!data?.length && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-secondary)', fontSize: 13 }}>
            No cases yet.
          </div>
        )}
      </div>
    </div>
  )
}

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      fontSize: 11, padding: '2px 8px', borderRadius: 10,
      background: `${color}22`, color, textTransform: 'capitalize',
    }}>
      {label}
    </span>
  )
}

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '8px 12px',
  background: 'var(--bg-tertiary)', border: '1px solid var(--border)',
  borderRadius: 6, color: 'var(--text-primary)', fontSize: 13, outline: 'none',
}
