import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import {
  getAlertRules, createAlertRule, updateAlertRule, deleteAlertRule,
  getAlertRuleConditions,
} from '../api/client'

type Severity = 'low' | 'medium' | 'high' | 'critical'
type ConditionType =
  | 'new_ransomware_victim' | 'new_indicator' | 'new_malware'
  | 'new_threat_actor' | 'high_epss_cve' | 'cisa_kev_added'
  | 'credential_exposure' | 'iab_listing' | 'ioc_sighted'

interface AlertRule {
  id: string
  name: string
  description?: string
  condition_type: ConditionType
  condition_params: Record<string, unknown>
  severity: Severity
  enabled: boolean
  dedup_window_minutes: number
  matched_count: number
  last_matched_at?: string
  created_at: string
}

interface ConditionMeta {
  type: ConditionType
  label: string
  description: string
  params: Array<{ key: string; type: string; description: string; required: boolean; default?: unknown }>
}

const SEV_COLORS: Record<Severity, string> = {
  low: '#10b981', medium: '#f59e0b', high: '#f97316', critical: '#ef4444',
}

const EMPTY_FORM = {
  name: '',
  description: '',
  condition_type: 'new_ransomware_victim' as ConditionType,
  condition_params: {} as Record<string, string>,
  severity: 'medium' as Severity,
  enabled: true,
  dedup_window_minutes: 60,
}

export default function AlertRulesPage() {
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<AlertRule | null>(null)
  const [form, setForm] = useState(EMPTY_FORM)
  const [paramInputs, setParamInputs] = useState<Record<string, string>>({})

  const { data, isLoading } = useQuery({
    queryKey: ['alert-rules'],
    queryFn: () => getAlertRules().then((r) => r.data),
  })

  const { data: conditionsData } = useQuery({
    queryKey: ['alert-rule-conditions'],
    queryFn: () => getAlertRuleConditions().then((r) => r.data),
  })

  const conditions: ConditionMeta[] = conditionsData?.conditions || []
  const rules: AlertRule[] = data?.objects || []

  const createMut = useMutation({
    mutationFn: (d: Record<string, unknown>) => createAlertRule(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alert-rules'] })
      setCreating(false)
      setForm(EMPTY_FORM)
      setParamInputs({})
      toast.success('Alert rule created')
    },
    onError: () => toast.error('Failed to create rule'),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) =>
      updateAlertRule(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alert-rules'] })
      setEditing(null)
      toast.success('Alert rule updated')
    },
    onError: () => toast.error('Failed to update rule'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteAlertRule(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alert-rules'] })
      toast.success('Alert rule deleted')
    },
    onError: () => toast.error('Failed to delete rule'),
  })

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateAlertRule(id, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alert-rules'] }),
  })

  const selectedCondition = conditions.find((c) => c.type === form.condition_type)

  function handleSubmit() {
    // Build condition_params from paramInputs (only non-empty)
    const params: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(paramInputs)) {
      if (v !== '') params[k] = v
    }
    const payload = {
      name: form.name,
      description: form.description || undefined,
      condition_type: form.condition_type,
      condition_params: params,
      severity: form.severity,
      enabled: form.enabled,
      dedup_window_minutes: form.dedup_window_minutes,
    }
    if (editing) {
      updateMut.mutate({ id: editing.id, data: payload })
    } else {
      createMut.mutate(payload)
    }
  }

  function openEdit(rule: AlertRule) {
    setEditing(rule)
    setForm({
      name: rule.name,
      description: rule.description || '',
      condition_type: rule.condition_type,
      condition_params: rule.condition_params as Record<string, string>,
      severity: rule.severity,
      enabled: rule.enabled,
      dedup_window_minutes: rule.dedup_window_minutes,
    })
    const pi: Record<string, string> = {}
    for (const [k, v] of Object.entries(rule.condition_params || {})) {
      pi[k] = String(v)
    }
    setParamInputs(pi)
    setCreating(true)
  }

  function closeModal() {
    setCreating(false)
    setEditing(null)
    setForm(EMPTY_FORM)
    setParamInputs({})
  }

  return (
    <div style={{ padding: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, marginBottom: 2 }}>Alert Rules</h1>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            Auto-create alerts when conditions are matched (checked hourly)
          </div>
        </div>
        <button onClick={() => setCreating(true)} style={btnStyle}>
          + New Rule
        </button>
      </div>

      {/* Stats bar */}
      {rules.length > 0 && (
        <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
          {(['low', 'medium', 'high', 'critical'] as Severity[]).map((s) => {
            const count = rules.filter((r) => r.severity === s).length
            return count > 0 ? (
              <div key={s} style={{
                background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                borderLeft: `3px solid ${SEV_COLORS[s]}`, borderRadius: 4,
                padding: '6px 12px',
              }}>
                <div style={{ fontSize: 16, fontWeight: 700, color: SEV_COLORS[s] }}>{count}</div>
                <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>{s}</div>
              </div>
            ) : null
          })}
          <div style={{
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderLeft: '3px solid #10b981', borderRadius: 4, padding: '6px 12px',
          }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: '#10b981' }}>
              {rules.filter((r) => r.enabled).length}
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>enabled</div>
          </div>
        </div>
      )}

      {/* Rules table */}
      <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6 }}>
        {isLoading ? (
          <div style={{ padding: 16, fontSize: 12, color: 'var(--text-secondary)' }}>Loading...</div>
        ) : rules.length === 0 ? (
          <div style={{ padding: 24, textAlign: 'center', fontSize: 12, color: 'var(--text-secondary)' }}>
            No alert rules yet. Create a rule to start auto-alerting on threat intel events.
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Rule', 'Condition', 'Severity', 'Matched', 'Last Match', 'Enabled', ''].map((h) => (
                  <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600 }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ fontWeight: 500 }}>{r.name}</div>
                    {r.description && (
                      <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>{r.description}</div>
                    )}
                  </td>
                  <td style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>
                    {r.condition_type.replace(/_/g, ' ')}
                    {Object.keys(r.condition_params || {}).length > 0 && (
                      <div style={{ fontSize: 10, color: '#4a5568', marginTop: 2 }}>
                        {Object.entries(r.condition_params).map(([k, v]) => `${k}=${v}`).join(', ')}
                      </div>
                    )}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <span style={{
                      fontSize: 10, padding: '2px 7px', borderRadius: 10,
                      background: `${SEV_COLORS[r.severity]}20`, color: SEV_COLORS[r.severity],
                    }}>
                      {r.severity}
                    </span>
                  </td>
                  <td style={{ padding: '10px 12px', color: r.matched_count > 0 ? '#10b981' : 'var(--text-secondary)' }}>
                    {r.matched_count}
                  </td>
                  <td style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontSize: 11 }}>
                    {r.last_matched_at ? new Date(r.last_matched_at).toLocaleString() : '—'}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <button
                      onClick={() => toggleMut.mutate({ id: r.id, enabled: !r.enabled })}
                      style={{
                        background: r.enabled ? 'rgba(16,185,129,0.15)' : 'rgba(107,114,128,0.15)',
                        color: r.enabled ? '#10b981' : '#6b7280',
                        border: 'none', borderRadius: 10, padding: '2px 8px', fontSize: 10, cursor: 'pointer',
                      }}
                    >
                      {r.enabled ? 'ON' : 'OFF'}
                    </button>
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button onClick={() => openEdit(r)} style={actionBtnStyle}>edit</button>
                      <button
                        onClick={() => {
                          if (confirm('Delete this rule?')) deleteMut.mutate(r.id)
                        }}
                        style={{ ...actionBtnStyle, color: '#ef4444' }}
                      >
                        del
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Create / Edit Modal */}
      {creating && (
        <div style={overlayStyle} onClick={closeModal}>
          <div style={modalStyle} onClick={(e) => e.stopPropagation()}>
            <h3 style={{ fontSize: 15, fontWeight: 700, marginBottom: 16 }}>
              {editing ? 'Edit Alert Rule' : 'New Alert Rule'}
            </h3>

            <Field label="Name">
              <input
                value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="e.g. Healthcare Ransomware Alert"
                style={fieldInput}
              />
            </Field>

            <Field label="Description">
              <input
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="Optional description"
                style={fieldInput}
              />
            </Field>

            <Field label="Condition">
              <select
                value={form.condition_type}
                onChange={(e) => {
                  setForm({ ...form, condition_type: e.target.value as ConditionType })
                  setParamInputs({})
                }}
                style={fieldInput}
              >
                {conditions.map((c) => (
                  <option key={c.type} value={c.type}>{c.label}</option>
                ))}
              </select>
              {selectedCondition && (
                <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 4 }}>
                  {selectedCondition.description}
                </div>
              )}
            </Field>

            {/* Dynamic condition params */}
            {(selectedCondition?.params || []).map((p) => (
              <Field key={p.key} label={`${p.key}${p.required ? ' *' : ' (optional)'}`}>
                <input
                  value={paramInputs[p.key] || ''}
                  onChange={(e) => setParamInputs({ ...paramInputs, [p.key]: e.target.value })}
                  placeholder={p.description}
                  style={fieldInput}
                />
              </Field>
            ))}

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <Field label="Severity">
                <select
                  value={form.severity}
                  onChange={(e) => setForm({ ...form, severity: e.target.value as Severity })}
                  style={fieldInput}
                >
                  {(['low', 'medium', 'high', 'critical'] as Severity[]).map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </Field>

              <Field label="Dedup window (min)">
                <input
                  type="number"
                  value={form.dedup_window_minutes}
                  onChange={(e) => setForm({ ...form, dedup_window_minutes: Number(e.target.value) })}
                  style={fieldInput}
                />
              </Field>
            </div>

            <div style={{ display: 'flex', gap: 8, marginTop: 20 }}>
              <button
                onClick={handleSubmit}
                disabled={!form.name || !form.condition_type}
                style={btnStyle}
              >
                {editing ? 'Save' : 'Create Rule'}
              </button>
              <button onClick={closeModal} style={cancelBtnStyle}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <label style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>
        {label}
      </label>
      {children}
    </div>
  )
}

const btnStyle: React.CSSProperties = {
  background: 'var(--accent)', color: '#fff', border: 'none',
  borderRadius: 4, padding: '7px 14px', fontSize: 12, cursor: 'pointer', fontWeight: 600,
}
const cancelBtnStyle: React.CSSProperties = {
  background: 'transparent', color: 'var(--text-secondary)',
  border: '1px solid var(--border)', borderRadius: 4, padding: '7px 14px', fontSize: 12, cursor: 'pointer',
}
const actionBtnStyle: React.CSSProperties = {
  background: 'transparent', color: 'var(--text-secondary)',
  border: '1px solid var(--border)', borderRadius: 3, padding: '3px 8px', fontSize: 11, cursor: 'pointer',
}
const fieldInput: React.CSSProperties = {
  width: '100%', background: 'var(--bg-primary)', border: '1px solid var(--border)',
  borderRadius: 4, color: 'var(--text-primary)', padding: '6px 10px', fontSize: 12, boxSizing: 'border-box',
}
const overlayStyle: React.CSSProperties = {
  position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex',
  alignItems: 'center', justifyContent: 'center', zIndex: 100,
}
const modalStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)', border: '1px solid var(--border)',
  borderRadius: 8, padding: 24, width: 480, maxHeight: '85vh', overflowY: 'auto',
}
