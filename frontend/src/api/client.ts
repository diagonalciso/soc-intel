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
