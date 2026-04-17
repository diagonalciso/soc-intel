import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.response.use(
  (res) => res,
  (err) => Promise.reject(err)
)

export default api

// ── Auth ──────────────────────────────────────────────────────
export const login = (email: string, password: string) =>
  api.post('/auth/login', { email, password })

export const register = (data: { email: string; username: string; password: string; organization_name?: string }) =>
  api.post('/auth/register', data)

export const getMe = () => api.get('/auth/me')

// ── Intelligence ──────────────────────────────────────────────
export const searchObjects = (params: Record<string, unknown>) =>
  api.get('/intel/objects', { params })

export const getObject = (id: string) => api.get(`/intel/objects/${id}`)

export const getObjectRelationships = (id: string) =>
  api.get(`/intel/objects/${id}/relationships`)

export const getThreatActors = (params?: Record<string, unknown>) =>
  api.get('/intel/threat-actors', { params })

export const getIndicators = (params?: Record<string, unknown>) =>
  api.get('/intel/indicators', { params })

export const getMalware = (params?: Record<string, unknown>) =>
  api.get('/intel/malware', { params })

export const getVulnerabilities = (params?: Record<string, unknown>) =>
  api.get('/intel/vulnerabilities', { params })

export const createObject = (type: string, data: Record<string, unknown>) =>
  api.post('/intel/objects', { type, data })

export const bulkIngest = (objects: unknown[]) =>
  api.post('/intel/bulk', objects)

// ── Cases ─────────────────────────────────────────────────────
export const getCases = (params?: Record<string, unknown>) =>
  api.get('/cases', { params })

export const getCase = (id: string) => api.get(`/cases/${id}`)

export const createCase = (data: Record<string, unknown>) =>
  api.post('/cases', data)

export const updateCase = (id: string, data: Record<string, unknown>) =>
  api.patch(`/cases/${id}`, data)

export const getCaseTasks = (id: string) => api.get(`/cases/${id}/tasks`)
export const addTask = (id: string, data: Record<string, unknown>) =>
  api.post(`/cases/${id}/tasks`, data)

export const getCaseObservables = (id: string) => api.get(`/cases/${id}/observables`)
export const addObservable = (id: string, data: Record<string, unknown>) =>
  api.post(`/cases/${id}/observables`, data)

export const addComment = (id: string, content: string) =>
  api.post(`/cases/${id}/comments`, { content })

// ── Alerts ────────────────────────────────────────────────────
export const getAlerts = (params?: Record<string, unknown>) =>
  api.get('/alerts', { params })

export const promoteAlert = (id: string) => api.post(`/alerts/${id}/promote`)

// ── Dark web ──────────────────────────────────────────────────
export const getDarkwebSummary = () => api.get('/darkweb/summary')
export const getRansomwareLeaks = (params?: Record<string, unknown>) =>
  api.get('/darkweb/ransomware', { params })
export const getRansomwareStats = () => api.get('/darkweb/ransomware/stats')
export const getCredentialExposures = (params?: Record<string, unknown>) =>
  api.get('/darkweb/credentials', { params })
export const getIABListings = (params?: Record<string, unknown>) =>
  api.get('/darkweb/iab', { params })
export const getStealerLogs = (params?: Record<string, unknown>) =>
  api.get('/darkweb/stealer-logs', { params })

// ── Enrichment ────────────────────────────────────────────────
export const enrichObservable = (type: string, value: string) =>
  api.post('/enrich', { type, value })

// ── Connectors ────────────────────────────────────────────────
export const getConnectors = () => api.get('/connectors')
export const triggerConnector = (name: string) =>
  api.post(`/connectors/${name}/trigger`)

// ── Intel stats ───────────────────────────────────────────────
export const getIntelStats = () => api.get('/intel/stats')

// ── Honeypot IPs ──────────────────────────────────────────────
export const getHoneypotIps = () => api.get('/intel/honeypot-ips')

// ── Object graph ──────────────────────────────────────────────
export const getObjectGraph = (id: string) => api.get(`/intel/objects/${id}/graph`)

// ── Detection rules ───────────────────────────────────────────
export const getRules = (params?: Record<string, unknown>) =>
  api.get('/rules', { params })

export const getRule = (id: string) => api.get(`/rules/${id}`)

export const createRule = (data: Record<string, unknown>) =>
  api.post('/rules', data)

export const updateRule = (id: string, data: Record<string, unknown>) =>
  api.patch(`/rules/${id}`, data)

export const deleteRule = (id: string) => api.delete(`/rules/${id}`)

export const getRuleStats = () => api.get('/rules/stats')

// ── Sightings ──────────────────────────────────────────────────
export const createSighting = (data: Record<string, unknown>) =>
  api.post('/sightings', data)

export const getSightings = (indicatorId?: string) =>
  api.get('/sightings', { params: indicatorId ? { indicator_id: indicatorId } : undefined })

// ── Pivot search ───────────────────────────────────────────────
export const pivotSearch = (value: string, size?: number) =>
  api.get('/intel/pivot', { params: { value, size } })

// ── Threat Hunting ──────────────────────────────────────────────
export const huntingPivot = (q: string, size: number = 20) =>
  api.get('/hunting/pivot', { params: { q, size } })

export const getMalwareFamilies = (q?: string, from: number = 0, size: number = 20) =>
  api.get('/hunting/malware-families', { params: { q, from, size } })

export const getMalwareFamilyProfile = (familyName: string) =>
  api.get(`/hunting/malware/${familyName}`)

// ── Campaigns + intrusion sets ────────────────────────────────
export const getCampaigns = (params?: Record<string, unknown>) =>
  api.get('/intel/campaigns', { params })

export const getIntrusionSets = (params?: Record<string, unknown>) =>
  api.get('/intel/intrusion-sets', { params })

// ── Alert rules ───────────────────────────────────────────────
export const getAlertRules = (params?: Record<string, unknown>) =>
  api.get('/alert-rules', { params })

export const getAlertRule = (id: string) => api.get(`/alert-rules/${id}`)

export const createAlertRule = (data: Record<string, unknown>) =>
  api.post('/alert-rules', data)

export const updateAlertRule = (id: string, data: Record<string, unknown>) =>
  api.patch(`/alert-rules/${id}`, data)

export const deleteAlertRule = (id: string) => api.delete(`/alert-rules/${id}`)

export const getAlertRuleConditions = () => api.get('/alert-rules/conditions')

export const testAlertRule = (id: string) => api.post(`/alert-rules/${id}/test`)

// ── API key management ────────────────────────────────────────
export const listApiKeys = () => api.get('/auth/api-keys')

export const createApiKey = (data: Record<string, unknown>) =>
  api.post('/auth/api-keys', data)

export const revokeApiKey = (id: string) => api.delete(`/auth/api-keys/${id}`)

// ── Export ────────────────────────────────────────────────────
export const exportStix = (params?: Record<string, unknown>) =>
  api.get('/export/stix', { params, responseType: 'blob' })

export const exportSplunkCsv = (params?: Record<string, unknown>) =>
  api.get('/export/splunk', { params, responseType: 'blob' })

export const exportElasticNdjson = (params?: Record<string, unknown>) =>
  api.get('/export/elastic', { params, responseType: 'blob' })

export const exportCsv = (params?: Record<string, unknown>) =>
  api.get('/export/csv', { params, responseType: 'blob' })
