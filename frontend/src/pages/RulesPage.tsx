import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getRules, createRule, updateRule, deleteRule, getRuleStats } from '../api/client'
import toast from 'react-hot-toast'

type RuleType     = 'yara' | 'sigma' | 'snort' | 'suricata' | 'stix-pattern'
type RuleStatus   = 'active' | 'testing' | 'deprecated'
type RuleSeverity = 'low' | 'medium' | 'high' | 'critical'

interface Rule {
  id: string
  name: string
  rule_type: RuleType
  content: string
  description?: string
  author?: string
  tags: string[]
  severity: RuleSeverity
  status: RuleStatus
  linked_stix_ids: string[]
  mitre_techniques: string[]
  created_at: string
  updated_at: string
}

const TYPE_COLORS: Record<RuleType, string> = {
  yara:         '#f59e0b',
  sigma:        '#3b82f6',
  snort:        '#ef4444',
  suricata:     '#8b5cf6',
  'stix-pattern': '#10b981',
}

const SEV_COLORS: Record<RuleSeverity, string> = {
  low:      '#10b981',
  medium:   '#f59e0b',
  high:     '#f97316',
  critical: '#ef4444',
}

const EMPTY_FORM = {
  name: '',
  rule_type: 'yara' as RuleType,
  content: '',
  description: '',
  author: '',
  severity: 'medium' as RuleSeverity,
  status: 'active' as RuleStatus,
  tags: '',
  mitre_techniques: '',
}

export default function RulesPage() {
  const qc = useQueryClient()
  const [filterType, setFilterType]   = useState<RuleType | ''>('')
  const [filterStatus, setFilterStatus] = useState<RuleStatus | ''>('')
  const [search, setSearch]           = useState('')
  const [editing, setEditing]         = useState<Rule | null>(null)
  const [creating, setCreating]       = useState(false)
  const [form, setForm]               = useState(EMPTY_FORM)
  const [viewing, setViewing]         = useState<Rule | null>(null)

  const { data: stats } = useQuery({
    queryKey: ['rule-stats'],
    queryFn: () => getRuleStats().then((r) => r.data),
  })

  const { data, isLoading } = useQuery({
    queryKey: ['rules', filterType, filterStatus, search],
    queryFn: () => getRules({
      rule_type: filterType || undefined,
      status:    filterStatus || undefined,
      q:         search || undefined,
      size:      200,
    }).then((r) => r.data),
  })

  const createMut = useMutation({
    mutationFn: (d: Record<string, unknown>) => createRule(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      qc.invalidateQueries({ queryKey: ['rule-stats'] })
      setCreating(false)
      setForm(EMPTY_FORM)
      toast.success('Rule created')
    },
    onError: () => toast.error('Failed to create rule'),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) =>
      updateRule(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      setEditing(null)
      toast.success('Rule updated')
    },
    onError: () => toast.error('Failed to update rule'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteRule(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      qc.invalidateQueries({ queryKey: ['rule-stats'] })
      toast.success('Rule deleted')
    },
    onError: () => toast.error('Failed to delete rule'),
  })

  const rules: Rule[] = data?.objects || []

  function openCreate() {
    setForm(EMPTY_FORM)
    setEditing(null)
    setCreating(true)
  }

  function openEdit(rule: Rule) {
    setForm({
      name:         rule.name,
      rule_type:    rule.rule_type,
      content:      rule.content,
      description:  rule.description || '',
      author:       rule.author || '',
      severity:     rule.severity,
      status:       rule.status,
      tags:         (rule.tags || []).join(', '),
      mitre_techniques: (rule.mitre_techniques || []).join(', '),
    })
    setEditing(rule)
    setCreating(false)
  }

  function submitForm() {
    const payload: Record<string, unknown> = {
      name:         form.name.trim(),
      rule_type:    form.rule_type,
      content:      form.content.trim(),
      description:  form.description.trim() || null,
      author:       form.author.trim() || null,
      severity:     form.severity,
      status:       form.status,
      tags:         form.tags.split(',').map((t) => t.trim()).filter(Boolean),
      mitre_techniques: form.mitre_techniques.split(',').map((t) => t.trim()).filter(Boolean),
      linked_stix_ids: [],
    }
    if (editing) {
      updateMut.mutate({ id: editing.id, data: payload })
    } else {
      createMut.mutate(payload)
    }
  }

  const showForm = creating || editing !== null

  return (
    <div style={{ padding: 16, display: 'flex', gap: 16, height: '100%', overflow: 'hidden' }}>
      {/* Left: list */}
      <div style={{ flex: 1, minWidth: 0, overflowY: 'auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div>
            <h1 style={{ fontSize: 18, fontWeight: 700, margin: 0 }}>Detection Rules</h1>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 3 }}>
              {stats?.total ?? 0} total — {stats?.by_status?.active ?? 0} active
            </div>
          </div>
          <button onClick={openCreate} style={btnPrimary}>+ New Rule</button>
        </div>

        {/* Stats row */}
        {stats && (
          <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
            {Object.entries(stats.by_type || {}).map(([t, n]) => (
              <div key={t} style={{
                padding: '4px 10px', borderRadius: 12, fontSize: 11,
                background: `${TYPE_COLORS[t as RuleType]}18`,
                color: TYPE_COLORS[t as RuleType] || '#94a3b8',
                border: `1px solid ${TYPE_COLORS[t as RuleType] || '#94a3b8'}40`,
              }}>
                {t.toUpperCase()} {String(n)}
              </div>
            ))}
          </div>
        )}

        {/* Filters */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rules..."
            style={inputStyle}
          />
          <select value={filterType} onChange={(e) => setFilterType(e.target.value as RuleType | '')} style={selectStyle}>
            <option value="">All types</option>
            {(['yara','sigma','snort','suricata','stix-pattern'] as RuleType[]).map((t) => (
              <option key={t} value={t}>{t.toUpperCase()}</option>
            ))}
          </select>
          <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value as RuleStatus | '')} style={selectStyle}>
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="testing">Testing</option>
            <option value="deprecated">Deprecated</option>
          </select>
        </div>

        {/* Rules table */}
        {isLoading ? (
          <div style={{ color: 'var(--text-secondary)', fontSize: 13 }}>Loading...</div>
        ) : rules.length === 0 ? (
          <div style={{ color: 'var(--text-secondary)', fontSize: 13, padding: 20, textAlign: 'center' }}>
            No rules found. Click "New Rule" to create one.
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['Type', 'Name', 'Severity', 'Status', 'MITRE', 'Actions'].map((h) => (
                  <th key={h} style={thStyle}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '8px 8px' }}>
                    <span style={{
                      fontSize: 10, padding: '2px 7px', borderRadius: 8,
                      background: `${TYPE_COLORS[rule.rule_type]}18`,
                      color: TYPE_COLORS[rule.rule_type],
                      fontWeight: 600,
                    }}>
                      {rule.rule_type.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ padding: '8px 8px', fontSize: 13 }}>
                    <div
                      style={{ cursor: 'pointer', color: 'var(--text-primary)' }}
                      onClick={() => setViewing(viewing?.id === rule.id ? null : rule)}
                    >
                      {rule.name}
                    </div>
                    {rule.description && (
                      <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                        {rule.description.slice(0, 80)}
                      </div>
                    )}
                    {(rule.tags || []).length > 0 && (
                      <div style={{ display: 'flex', gap: 4, marginTop: 4, flexWrap: 'wrap' }}>
                        {rule.tags.map((tag) => (
                          <span key={tag} style={{
                            fontSize: 9, padding: '1px 5px', borderRadius: 8,
                            background: 'rgba(148,163,184,0.1)', color: 'var(--text-secondary)',
                          }}>
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td style={{ padding: '8px 8px' }}>
                    <span style={{
                      fontSize: 10, padding: '2px 7px', borderRadius: 8,
                      background: `${SEV_COLORS[rule.severity]}18`,
                      color: SEV_COLORS[rule.severity],
                    }}>
                      {rule.severity}
                    </span>
                  </td>
                  <td style={{ padding: '8px 8px' }}>
                    <span style={{
                      fontSize: 10, padding: '2px 7px', borderRadius: 8,
                      background: rule.status === 'active'
                        ? 'rgba(16,185,129,0.1)' : rule.status === 'testing'
                        ? 'rgba(245,158,11,0.1)' : 'rgba(148,163,184,0.1)',
                      color: rule.status === 'active' ? '#10b981'
                        : rule.status === 'testing' ? '#f59e0b' : '#94a3b8',
                    }}>
                      {rule.status}
                    </span>
                  </td>
                  <td style={{ padding: '8px 8px', fontSize: 11, color: '#f59e0b', fontFamily: 'monospace' }}>
                    {(rule.mitre_techniques || []).slice(0, 3).join(' ')}
                    {(rule.mitre_techniques || []).length > 3 && ` +${rule.mitre_techniques.length - 3}`}
                  </td>
                  <td style={{ padding: '8px 8px', whiteSpace: 'nowrap' }}>
                    <button onClick={() => openEdit(rule)} style={btnSmall}>Edit</button>
                    <button
                      onClick={() => { if (confirm('Delete this rule?')) deleteMut.mutate(rule.id) }}
                      style={{ ...btnSmall, color: '#ef4444', marginLeft: 4 }}
                    >
                      Del
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Inline rule content viewer */}
        {viewing && (
          <div style={{ marginTop: 16, ...cardStyle }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{viewing.name}</div>
              <button
                onClick={() => setViewing(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
              >
                ×
              </button>
            </div>
            <pre style={{
              background: 'var(--bg-primary)', padding: 12, borderRadius: 4,
              fontSize: 11, color: '#a5f3fc', overflowX: 'auto',
              fontFamily: 'monospace', lineHeight: 1.5, margin: 0,
            }}>
              {viewing.content}
            </pre>
          </div>
        )}
      </div>

      {/* Right: form panel */}
      {showForm && (
        <div style={{
          width: 420, flexShrink: 0,
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: 6,
          padding: 20,
          overflowY: 'auto',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
            <h2 style={{ fontSize: 15, fontWeight: 700, margin: 0 }}>
              {editing ? 'Edit Rule' : 'New Rule'}
            </h2>
            <button
              onClick={() => { setCreating(false); setEditing(null) }}
              style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 18 }}
            >
              ×
            </button>
          </div>

          <FormField label="Name">
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} style={inputFull} />
          </FormField>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <FormField label="Type">
              <select value={form.rule_type} onChange={(e) => setForm({ ...form, rule_type: e.target.value as RuleType })} style={inputFull}>
                {(['yara','sigma','snort','suricata','stix-pattern'] as RuleType[]).map((t) => (
                  <option key={t} value={t}>{t.toUpperCase()}</option>
                ))}
              </select>
            </FormField>
            <FormField label="Severity">
              <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value as RuleSeverity })} style={inputFull}>
                {(['low','medium','high','critical'] as RuleSeverity[]).map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </FormField>
          </div>

          <FormField label="Status">
            <select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value as RuleStatus })} style={inputFull}>
              <option value="active">Active</option>
              <option value="testing">Testing</option>
              <option value="deprecated">Deprecated</option>
            </select>
          </FormField>

          <FormField label="Description">
            <textarea
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              rows={2}
              style={{ ...inputFull, resize: 'vertical' }}
            />
          </FormField>

          <FormField label="Author">
            <input value={form.author} onChange={(e) => setForm({ ...form, author: e.target.value })} style={inputFull} />
          </FormField>

          <FormField label="Tags (comma-separated)">
            <input value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} style={inputFull} placeholder="ransomware, lateral-movement" />
          </FormField>

          <FormField label="MITRE Techniques (comma-separated)">
            <input value={form.mitre_techniques} onChange={(e) => setForm({ ...form, mitre_techniques: e.target.value })} style={inputFull} placeholder="T1566, T1059.001" />
          </FormField>

          <FormField label="Rule Content">
            <textarea
              value={form.content}
              onChange={(e) => setForm({ ...form, content: e.target.value })}
              rows={12}
              style={{
                ...inputFull, resize: 'vertical',
                fontFamily: 'monospace', fontSize: 11,
                color: '#a5f3fc', background: 'var(--bg-primary)',
              }}
              placeholder={_placeholder(form.rule_type)}
            />
          </FormField>

          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button
              onClick={submitForm}
              disabled={!form.name.trim() || !form.content.trim()}
              style={{
                ...btnPrimary,
                opacity: !form.name.trim() || !form.content.trim() ? 0.5 : 1,
              }}
            >
              {editing ? 'Save Changes' : 'Create Rule'}
            </button>
            <button onClick={() => { setCreating(false); setEditing(null) }} style={btnSecondary}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function FormField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <label style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>
        {label}
      </label>
      {children}
    </div>
  )
}

function _placeholder(ruleType: RuleType): string {
  switch (ruleType) {
    case 'yara':
      return 'rule RansomwareSample {\n  meta:\n    description = "Detects ransomware by string patterns"\n  strings:\n    $s1 = "YOUR FILES ARE ENCRYPTED"\n  condition:\n    any of them\n}'
    case 'sigma':
      return 'title: Suspicious PowerShell Execution\nstatus: test\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: "-EncodedCommand"\n  condition: selection'
    case 'snort':
      return 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious outbound"; sid:1000001; rev:1;)'
    case 'suricata':
      return 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Cobalt Strike C2 Beacon"; content:"Content-Type|3a 20|application/octet-stream"; sid:2000001;)'
    case 'stix-pattern':
      return "[ipv4-addr:value = '192.168.1.1'] OR [domain-name:value = 'evil.example.com']"
    default:
      return ''
  }
}

const cardStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: 16,
}

const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '6px 8px', fontSize: 11,
  color: 'var(--text-secondary)', borderBottom: '1px solid var(--border)',
}

const inputStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)', border: '1px solid var(--border)',
  borderRadius: 5, padding: '7px 10px', color: 'var(--text-primary)',
  fontSize: 12, outline: 'none',
}

const inputFull: React.CSSProperties = {
  ...inputStyle, width: '100%', boxSizing: 'border-box',
}

const selectStyle: React.CSSProperties = {
  ...inputStyle,
}

const btnPrimary: React.CSSProperties = {
  padding: '7px 16px', background: 'rgba(59,130,246,0.15)',
  border: '1px solid rgba(59,130,246,0.4)', borderRadius: 5,
  color: '#60a5fa', cursor: 'pointer', fontSize: 12, fontWeight: 500,
}

const btnSecondary: React.CSSProperties = {
  padding: '7px 14px', background: 'transparent',
  border: '1px solid var(--border)', borderRadius: 5,
  color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12,
}

const btnSmall: React.CSSProperties = {
  padding: '3px 8px', background: 'transparent',
  border: '1px solid var(--border)', borderRadius: 4,
  color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 11,
}
