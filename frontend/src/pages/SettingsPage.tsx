import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { getMe, createApiKey, listApiKeys, revokeApiKey } from '../api/client'

interface ApiKey {
  id: string
  key_prefix: string
  created_at: string
  expires_at?: string
  label?: string
}

export default function SettingsPage() {
  const qc = useQueryClient()
  const [newKeyLabel, setNewKeyLabel] = useState('')
  const [createdKey, setCreatedKey] = useState<string | null>(null)

  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn: () => getMe().then((r) => r.data),
  })

  const { data: keysData } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => listApiKeys().then((r) => r.data),
  })

  const apiKeys: ApiKey[] = keysData?.api_keys || keysData || []

  const createKeyMut = useMutation({
    mutationFn: (label: string) => createApiKey({ label }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['api-keys'] })
      const key = res.data?.key || res.data?.api_key || ''
      if (key) {
        setCreatedKey(key)
      }
      setNewKeyLabel('')
      toast.success('API key created')
    },
    onError: () => toast.error('Failed to create API key'),
  })

  const revokeKeyMut = useMutation({
    mutationFn: (id: string) => revokeApiKey(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-keys'] })
      toast.success('API key revoked')
    },
    onError: () => toast.error('Failed to revoke key'),
  })

  const EXPORT_FORMATS = [
    { id: 'stix', label: 'STIX 2.1 Bundle', url: '/api/export/stix', desc: 'Full STIX bundle (JSON)' },
    { id: 'splunk', label: 'Splunk Lookup CSV', url: '/api/export/splunk', desc: 'Threat intel lookup for Splunk ES' },
    { id: 'elastic', label: 'Elastic NDJSON', url: '/api/export/elastic', desc: 'ECS-formatted NDJSON for Elasticsearch bulk API' },
    { id: 'csv', label: 'Generic CSV', url: '/api/export/csv', desc: 'Flat CSV of all STIX objects' },
  ]

  return (
    <div style={{ padding: 16 }}>
      <h1 style={{ fontSize: 18, fontWeight: 700, marginBottom: 16 }}>Settings</h1>

      {/* User profile */}
      <div style={sectionStyle}>
        <h2 style={sectionTitle}>User Profile</h2>
        {me ? (
          <div style={{ fontSize: 13 }}>
            <Row label="Username" value={me.username} />
            <Row label="Email" value={me.email} />
            <Row label="Role" value={me.role || 'analyst'} />
            {me.organization_name && <Row label="Organization" value={me.organization_name} />}
            <Row label="Account Created" value={me.created_at ? new Date(me.created_at).toLocaleDateString() : '—'} />
          </div>
        ) : (
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Loading profile...</div>
        )}
      </div>

      {/* API Keys */}
      <div style={sectionStyle}>
        <h2 style={sectionTitle}>API Keys</h2>
        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14 }}>
          API keys allow programmatic access to SOCINT. Pass as:{' '}
          <code style={codeStyle}>Authorization: Bearer &lt;key&gt;</code>
        </div>

        {/* Create new key */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <input
            value={newKeyLabel}
            onChange={(e) => setNewKeyLabel(e.target.value)}
            placeholder="Key label (e.g. splunk-integration)"
            style={inputStyle}
          />
          <button
            onClick={() => createKeyMut.mutate(newKeyLabel || 'unnamed')}
            disabled={createKeyMut.isPending}
            style={btnStyle}
          >
            Generate Key
          </button>
        </div>

        {/* Show newly created key */}
        {createdKey && (
          <div style={{
            background: 'rgba(16,185,129,0.1)', border: '1px solid #10b981',
            borderRadius: 4, padding: '10px 12px', marginBottom: 14, fontSize: 12,
          }}>
            <div style={{ color: '#10b981', fontWeight: 600, marginBottom: 4 }}>
              Key created — copy it now, it won't be shown again:
            </div>
            <div style={{ fontFamily: 'monospace', wordBreak: 'break-all', fontSize: 11, color: 'var(--text-primary)' }}>
              {createdKey}
            </div>
            <button
              onClick={() => {
                navigator.clipboard.writeText(createdKey)
                toast.success('Copied to clipboard')
              }}
              style={{ ...btnStyle, marginTop: 8, padding: '4px 10px', fontSize: 11 }}
            >
              Copy
            </button>
            <button
              onClick={() => setCreatedKey(null)}
              style={{ ...cancelBtnStyle, marginTop: 8, marginLeft: 6, padding: '4px 10px', fontSize: 11 }}
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Keys list */}
        {apiKeys.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>No API keys yet.</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Label', 'Key (prefix)', 'Created', ''].map((h) => (
                  <th key={h} style={{ padding: '6px 10px', textAlign: 'left', fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600 }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {apiKeys.map((k: ApiKey) => (
                <tr key={k.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '8px 10px' }}>{k.label || '—'}</td>
                  <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                    {k.key_prefix}...
                  </td>
                  <td style={{ padding: '8px 10px', color: 'var(--text-secondary)' }}>
                    {k.created_at ? new Date(k.created_at).toLocaleDateString() : '—'}
                  </td>
                  <td style={{ padding: '8px 10px' }}>
                    <button
                      onClick={() => {
                        if (confirm('Revoke this API key?')) revokeKeyMut.mutate(k.id)
                      }}
                      style={{ background: 'transparent', color: '#ef4444', border: '1px solid #ef4444', borderRadius: 3, padding: '3px 8px', fontSize: 11, cursor: 'pointer' }}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Export / SIEM Integration */}
      <div style={sectionStyle}>
        <h2 style={sectionTitle}>Export & SIEM Integration</h2>
        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14 }}>
          Download threat intelligence in various formats for SIEM integration or sharing.
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10 }}>
          {EXPORT_FORMATS.map((f) => (
            <div key={f.id} style={{
              background: 'var(--bg-primary)', border: '1px solid var(--border)',
              borderRadius: 5, padding: '12px 14px',
            }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{f.label}</div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 10 }}>{f.desc}</div>
              <a
                href={f.url}
                download
                style={{
                  display: 'inline-block', background: 'rgba(59,130,246,0.15)', color: 'var(--accent)',
                  border: '1px solid rgba(59,130,246,0.3)', borderRadius: 3,
                  padding: '4px 10px', fontSize: 11, textDecoration: 'none', cursor: 'pointer',
                }}
              >
                Download
              </a>
            </div>
          ))}
        </div>
      </div>

      {/* System info */}
      <div style={sectionStyle}>
        <h2 style={sectionTitle}>System</h2>
        <div style={{ fontSize: 13 }}>
          <Row label="Platform" value="SOCINT v0.1.0" />
          <Row label="API Docs" value={<a href="/api/docs" target="_blank" style={{ color: 'var(--accent)' }}>/api/docs</a>} />
          <Row label="OpenSearch Dashboards" value={<a href="http://localhost:5601" target="_blank" style={{ color: 'var(--accent)' }}>localhost:5601</a>} />
          <Row label="RabbitMQ Management" value={<a href="http://localhost:15672" target="_blank" style={{ color: 'var(--accent)' }}>localhost:15672</a>} />
          <Row label="MinIO Console" value={<a href="http://localhost:9001" target="_blank" style={{ color: 'var(--accent)' }}>localhost:9001</a>} />
        </div>
      </div>
    </div>
  )
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', gap: 12, padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
      <div style={{ width: 160, color: 'var(--text-secondary)', fontSize: 12, flexShrink: 0 }}>{label}</div>
      <div style={{ color: 'var(--text-primary)', fontSize: 12 }}>{value}</div>
    </div>
  )
}

const sectionStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)', border: '1px solid var(--border)',
  borderRadius: 6, padding: 16, marginBottom: 16,
}
const sectionTitle: React.CSSProperties = {
  fontSize: 14, fontWeight: 600, marginBottom: 14,
}
const inputStyle: React.CSSProperties = {
  flex: 1, background: 'var(--bg-primary)', border: '1px solid var(--border)',
  borderRadius: 4, color: 'var(--text-primary)', padding: '6px 10px', fontSize: 12,
}
const btnStyle: React.CSSProperties = {
  background: 'var(--accent)', color: '#fff', border: 'none',
  borderRadius: 4, padding: '7px 14px', fontSize: 12, cursor: 'pointer', fontWeight: 600,
}
const cancelBtnStyle: React.CSSProperties = {
  background: 'transparent', color: 'var(--text-secondary)',
  border: '1px solid var(--border)', borderRadius: 4, padding: '7px 14px', fontSize: 12, cursor: 'pointer',
}
const codeStyle: React.CSSProperties = {
  background: 'var(--bg-primary)', border: '1px solid var(--border)',
  borderRadius: 3, padding: '1px 5px', fontSize: 11, fontFamily: 'monospace',
}
