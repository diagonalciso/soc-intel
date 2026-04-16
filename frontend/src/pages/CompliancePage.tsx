import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import api from '../api/client'

// ── API helpers ────────────────────────────────────────────────────

const getComplianceStats  = () => api.get('/compliance/stats').then(r => r.data)
const get80053Families    = () => api.get('/compliance/800-53/families').then(r => r.data)
const get80053Controls    = (family: string | null, q: string) =>
  api.get('/compliance/800-53/controls', { params: { family: family || undefined, q: q || undefined, size: 200 } }).then(r => r.data)
const getCsfElements      = () => api.get('/compliance/csf/elements').then(r => r.data)

// ── Colours ────────────────────────────────────────────────────────

const FUNCTION_COLORS: Record<string, string> = {
  GV: '#8b5cf6',
  ID: '#3b82f6',
  PR: '#10b981',
  DE: '#f59e0b',
  RS: '#ef4444',
  RC: '#06b6d4',
}

const BASELINE_COLORS: Record<string, string> = {
  LOW:      '#10b981',
  MODERATE: '#f59e0b',
  HIGH:     '#ef4444',
}

// ── Component ──────────────────────────────────────────────────────

export default function CompliancePage() {
  const [tab, setTab] = useState<'800-53' | 'csf'>('800-53')

  const { data: stats } = useQuery({ queryKey: ['compliance-stats'], queryFn: getComplianceStats })

  return (
    <div style={{ padding: 24 }}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 4 }}>Compliance</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
          NIST SP 800-53 Rev 5 security controls and NIST Cybersecurity Framework 2.0
        </p>
      </div>

      {/* Stats bar */}
      {stats && (
        <div style={{ display: 'flex', gap: 16, marginBottom: 24 }}>
          <StatCard label="SP 800-53 Controls" value={stats.nist_800_53?.controls ?? 0} color="#3b82f6" />
          <StatCard label="Rules Tagged" value={stats.nist_800_53?.rules_tagged ?? 0} color="#8b5cf6" />
          <StatCard label="Cases Tagged (800-53)" value={stats.nist_800_53?.cases_tagged ?? 0} color="#f59e0b" />
          <StatCard label="CSF Elements" value={stats.csf?.elements ?? 0} color="#10b981" />
          <StatCard label="Cases Tagged (CSF)" value={stats.csf?.cases_tagged ?? 0} color="#06b6d4" />
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 2, marginBottom: 20, borderBottom: '1px solid var(--border)' }}>
        {(['800-53', 'csf'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: '8px 20px',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              fontSize: 13,
              fontWeight: tab === t ? 600 : 400,
              color: tab === t ? 'var(--accent)' : 'var(--text-secondary)',
              borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
              marginBottom: -1,
            }}
          >
            {t === '800-53' ? 'NIST SP 800-53 Rev 5' : 'NIST CSF 2.0'}
          </button>
        ))}
      </div>

      {tab === '800-53' ? <Controls80053Panel /> : <CSF20Panel />}
    </div>
  )
}

// ── SP 800-53 panel ────────────────────────────────────────────────

function Controls80053Panel() {
  const [selectedFamily, setSelectedFamily] = useState<string | null>(null)
  const [q, setQ] = useState('')
  const [selectedControl, setSelectedControl] = useState<any>(null)

  const { data: families, isLoading: familiesLoading } = useQuery({
    queryKey: ['800-53-families'],
    queryFn: get80053Families,
  })

  const { data: controlsData, isLoading: controlsLoading } = useQuery({
    queryKey: ['800-53-controls', selectedFamily, q],
    queryFn: () => get80053Controls(selectedFamily, q),
  })

  const controls: any[] = controlsData?.controls ?? []
  const empty = !familiesLoading && (!families || families.length === 0)

  if (empty) {
    return (
      <div style={{ textAlign: 'center', padding: '60px 24px', color: 'var(--text-secondary)' }}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>◈</div>
        <div style={{ fontSize: 14, marginBottom: 8 }}>No controls loaded yet</div>
        <div style={{ fontSize: 12 }}>
          Trigger the <strong>NIST SP 800-53 Rev 5</strong> connector on the Connectors page to import the catalog.
        </div>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', gap: 0, height: 'calc(100vh - 260px)', overflow: 'hidden' }}>
      {/* Family sidebar */}
      <div style={{
        width: 200, flexShrink: 0, borderRight: '1px solid var(--border)',
        overflowY: 'auto', paddingRight: 0,
      }}>
        <button
          onClick={() => setSelectedFamily(null)}
          style={{
            display: 'block', width: '100%', textAlign: 'left', padding: '8px 12px',
            background: selectedFamily === null ? 'rgba(59,130,246,0.1)' : 'none',
            border: 'none', borderLeft: selectedFamily === null ? '2px solid var(--accent)' : '2px solid transparent',
            color: selectedFamily === null ? 'var(--accent)' : 'var(--text-secondary)',
            cursor: 'pointer', fontSize: 12, fontWeight: selectedFamily === null ? 600 : 400,
          }}
        >
          All Families
        </button>
        {(families ?? []).map((f: any) => (
          <button
            key={f.family}
            onClick={() => setSelectedFamily(f.family)}
            style={{
              display: 'block', width: '100%', textAlign: 'left', padding: '8px 12px',
              background: selectedFamily === f.family ? 'rgba(59,130,246,0.1)' : 'none',
              border: 'none', borderLeft: selectedFamily === f.family ? '2px solid var(--accent)' : '2px solid transparent',
              color: selectedFamily === f.family ? 'var(--accent)' : 'var(--text-secondary)',
              cursor: 'pointer', fontSize: 12,
              fontWeight: selectedFamily === f.family ? 600 : 400,
            }}
          >
            <span style={{ fontWeight: 700, marginRight: 6 }}>{f.family}</span>
            <span style={{ color: '#4a5568', fontSize: 11 }}>{f.count}</span>
            <div style={{ fontSize: 10, color: '#4a5568', marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {f.name}
            </div>
          </button>
        ))}
      </div>

      {/* Controls list */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 16px' }}>
        <input
          value={q}
          onChange={e => setQ(e.target.value)}
          placeholder="Search controls..."
          style={{
            width: '100%', padding: '8px 12px', background: 'var(--bg-secondary)',
            border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-primary)',
            fontSize: 13, marginBottom: 12, boxSizing: 'border-box',
          }}
        />
        {controlsLoading ? (
          <div style={{ color: 'var(--text-secondary)', fontSize: 13 }}>Loading...</div>
        ) : (
          controls.map((c: any) => (
            <div
              key={c.control_id}
              onClick={() => setSelectedControl(c)}
              style={{
                padding: '10px 12px', marginBottom: 6,
                background: selectedControl?.control_id === c.control_id ? 'rgba(59,130,246,0.08)' : 'var(--bg-secondary)',
                border: `1px solid ${selectedControl?.control_id === c.control_id ? 'var(--accent)' : 'var(--border)'}`,
                borderRadius: 6, cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                <code style={{ fontSize: 12, color: 'var(--accent)', fontWeight: 700 }}>{c.control_id}</code>
                {(c.baseline_impact || []).map((b: string) => (
                  <span key={b} style={{
                    fontSize: 9, padding: '1px 5px', borderRadius: 4,
                    background: `${BASELINE_COLORS[b] ?? '#6b7280'}22`,
                    color: BASELINE_COLORS[b] ?? '#6b7280', fontWeight: 700,
                  }}>{b[0]}</span>
                ))}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-primary)' }}>{c.title}</div>
            </div>
          ))
        )}
      </div>

      {/* Control detail */}
      {selectedControl && (
        <div style={{
          width: 340, flexShrink: 0, borderLeft: '1px solid var(--border)',
          overflowY: 'auto', padding: '0 16px',
        }}>
          <div style={{ position: 'sticky', top: 0, background: 'var(--bg-primary)', paddingTop: 12, paddingBottom: 8 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <code style={{ fontSize: 16, color: 'var(--accent)', fontWeight: 700 }}>{selectedControl.control_id}</code>
                <div style={{ fontSize: 13, fontWeight: 600, marginTop: 2 }}>{selectedControl.title}</div>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>{selectedControl.family_name}</div>
              </div>
              <button onClick={() => setSelectedControl(null)} style={{
                background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 18,
              }}>×</button>
            </div>
            {(selectedControl.baseline_impact || []).length > 0 && (
              <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                {selectedControl.baseline_impact.map((b: string) => (
                  <span key={b} style={{
                    fontSize: 10, padding: '2px 8px', borderRadius: 10,
                    background: `${BASELINE_COLORS[b] ?? '#6b7280'}22`,
                    color: BASELINE_COLORS[b] ?? '#6b7280', fontWeight: 700,
                  }}>{b}</span>
                ))}
              </div>
            )}
          </div>
          {selectedControl.description && (
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6, marginTop: 12, whiteSpace: 'pre-wrap' }}>
              {selectedControl.description}
            </div>
          )}
          {(selectedControl.related || []).length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: 11, color: '#4a5568', fontWeight: 600, marginBottom: 6 }}>RELATED CONTROLS</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {selectedControl.related.map((r: string) => (
                  <span key={r} style={{
                    fontSize: 11, padding: '2px 7px', borderRadius: 4,
                    background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-secondary)',
                  }}>{r}</span>
                ))}
              </div>
            </div>
          )}
          <ControlTaggedObjects controlId={selectedControl.control_id} />
        </div>
      )}
    </div>
  )
}

function ControlTaggedObjects({ controlId }: { controlId: string }) {
  const { data: rules } = useQuery({
    queryKey: ['control-rules', controlId],
    queryFn: () => api.get(`/compliance/800-53/controls/${controlId}/rules`).then(r => r.data),
  })
  const { data: cases } = useQuery({
    queryKey: ['control-cases', controlId],
    queryFn: () => api.get(`/compliance/800-53/controls/${controlId}/cases`).then(r => r.data),
  })

  if ((!rules || rules.length === 0) && (!cases || cases.length === 0)) return null

  return (
    <div style={{ marginTop: 20, borderTop: '1px solid var(--border)', paddingTop: 16 }}>
      {rules && rules.length > 0 && (
        <>
          <div style={{ fontSize: 11, color: '#4a5568', fontWeight: 600, marginBottom: 8 }}>TAGGED RULES ({rules.length})</div>
          {rules.map((r: any) => (
            <div key={r.id} style={{ fontSize: 12, padding: '4px 8px', marginBottom: 4, background: 'var(--bg-secondary)', borderRadius: 4 }}>
              <span style={{ color: 'var(--text-primary)' }}>{r.name}</span>
              <span style={{ color: '#4a5568', marginLeft: 8 }}>{r.rule_type}</span>
            </div>
          ))}
        </>
      )}
      {cases && cases.length > 0 && (
        <div style={{ marginTop: rules?.length ? 12 : 0 }}>
          <div style={{ fontSize: 11, color: '#4a5568', fontWeight: 600, marginBottom: 8 }}>TAGGED CASES ({cases.length})</div>
          {cases.map((c: any) => (
            <div key={c.id} style={{ fontSize: 12, padding: '4px 8px', marginBottom: 4, background: 'var(--bg-secondary)', borderRadius: 4 }}>
              {c.title}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── CSF 2.0 panel ─────────────────────────────────────────────────

function CSF20Panel() {
  const [selectedFunction, setSelectedFunction] = useState<string | null>(null)
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)

  const { data: elements, isLoading } = useQuery({
    queryKey: ['csf-elements'],
    queryFn: getCsfElements,
  })

  const empty = !isLoading && (!elements || elements.length === 0)

  if (empty) {
    return (
      <div style={{ textAlign: 'center', padding: '60px 24px', color: 'var(--text-secondary)' }}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>◈</div>
        <div style={{ fontSize: 14, marginBottom: 8 }}>No CSF data loaded yet</div>
        <div style={{ fontSize: 12 }}>
          Trigger the <strong>NIST CSF 2.0</strong> connector on the Connectors page to seed the framework.
        </div>
      </div>
    )
  }

  const functions = (elements ?? []).filter((e: any) => e.element_type === 'function')
  const categories = (elements ?? []).filter((e: any) => e.element_type === 'category')
  const subcategories = (elements ?? []).filter((e: any) => e.element_type === 'subcategory')

  const visibleCategories = selectedFunction
    ? categories.filter((c: any) => c.function_id === selectedFunction)
    : categories

  const visibleSubcats = selectedCategory
    ? subcategories.filter((s: any) => s.category_id === selectedCategory)
    : (selectedFunction ? subcategories.filter((s: any) => s.function_id === selectedFunction) : [])

  return (
    <div style={{ display: 'flex', gap: 0, height: 'calc(100vh - 260px)', overflow: 'hidden' }}>
      {/* Functions column */}
      <div style={{ width: 160, flexShrink: 0, borderRight: '1px solid var(--border)', overflowY: 'auto' }}>
        <div style={{ padding: '8px 12px', fontSize: 10, color: '#4a5568', fontWeight: 700, letterSpacing: 1 }}>FUNCTIONS</div>
        {functions.map((f: any) => {
          const color = FUNCTION_COLORS[f.function_id] ?? '#6b7280'
          const active = selectedFunction === f.function_id
          return (
            <button
              key={f.element_id}
              onClick={() => { setSelectedFunction(active ? null : f.function_id); setSelectedCategory(null) }}
              style={{
                display: 'block', width: '100%', textAlign: 'left', padding: '10px 12px',
                background: active ? `${color}15` : 'none',
                border: 'none', borderLeft: active ? `3px solid ${color}` : '3px solid transparent',
                cursor: 'pointer',
              }}
            >
              <div style={{ fontSize: 13, fontWeight: 700, color }}>
                {f.function_id}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 1 }}>{f.function_name}</div>
            </button>
          )
        })}
      </div>

      {/* Categories column */}
      <div style={{ width: 240, flexShrink: 0, borderRight: '1px solid var(--border)', overflowY: 'auto' }}>
        <div style={{ padding: '8px 12px', fontSize: 10, color: '#4a5568', fontWeight: 700, letterSpacing: 1 }}>CATEGORIES</div>
        {visibleCategories.map((cat: any) => {
          const color = FUNCTION_COLORS[cat.function_id] ?? '#6b7280'
          const active = selectedCategory === cat.element_id
          return (
            <button
              key={cat.element_id}
              onClick={() => setSelectedCategory(active ? null : cat.element_id)}
              style={{
                display: 'block', width: '100%', textAlign: 'left', padding: '10px 12px',
                background: active ? `${color}15` : 'none',
                border: 'none', borderLeft: active ? `3px solid ${color}` : '3px solid transparent',
                cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color, fontFamily: 'monospace' }}>{cat.element_id}</span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>{cat.category_name}</div>
            </button>
          )
        })}
        {visibleCategories.length === 0 && (
          <div style={{ padding: '12px', fontSize: 12, color: '#4a5568' }}>Select a function</div>
        )}
      </div>

      {/* Subcategories */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 16px' }}>
        <div style={{ padding: '8px 0 12px', fontSize: 10, color: '#4a5568', fontWeight: 700, letterSpacing: 1 }}>SUBCATEGORIES</div>
        {visibleSubcats.length === 0 && (
          <div style={{ fontSize: 12, color: '#4a5568' }}>
            {selectedFunction ? 'Select a category to see subcategories' : 'Select a function to begin'}
          </div>
        )}
        {visibleSubcats.map((sub: any) => {
          const color = FUNCTION_COLORS[sub.function_id] ?? '#6b7280'
          return (
            <div
              key={sub.element_id}
              style={{
                padding: '10px 12px', marginBottom: 6,
                background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                borderLeft: `3px solid ${color}`, borderRadius: 6,
              }}
            >
              <code style={{ fontSize: 11, color, fontWeight: 700 }}>{sub.element_id}</code>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '4px 0 0', lineHeight: 1.5 }}>
                {sub.description}
              </p>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Shared ─────────────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{
      background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8,
      padding: '12px 16px', minWidth: 130,
    }}>
      <div style={{ fontSize: 22, fontWeight: 700, color }}>{value.toLocaleString()}</div>
      <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>{label}</div>
    </div>
  )
}
