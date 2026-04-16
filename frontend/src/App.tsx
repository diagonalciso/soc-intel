import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/ui/Layout'
import DashboardPage from './pages/DashboardPage'
import IntelPage from './pages/IntelPage'
import CasesPage from './pages/CasesPage'
import DarkWebPage from './pages/DarkWebPage'
import ConnectorsPage from './pages/ConnectorsPage'
import ObjectDetailPage from './pages/ObjectDetailPage'
import AttackPage from './pages/AttackPage'
import RulesPage from './pages/RulesPage'
import ThreatActorsPage from './pages/ThreatActorsPage'
import CampaignsPage from './pages/CampaignsPage'
import AlertRulesPage from './pages/AlertRulesPage'
import SettingsPage from './pages/SettingsPage'
import CompliancePage from './pages/CompliancePage'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="intel" element={<IntelPage />} />
        <Route path="intel/:stixId" element={<ObjectDetailPage />} />
        <Route path="actors" element={<ThreatActorsPage />} />
        <Route path="campaigns" element={<CampaignsPage />} />
        <Route path="attack" element={<AttackPage />} />
        <Route path="rules" element={<RulesPage />} />
        <Route path="alert-rules" element={<AlertRulesPage />} />
        <Route path="cases" element={<CasesPage />} />
        <Route path="darkweb" element={<DarkWebPage />} />
        <Route path="connectors" element={<ConnectorsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="compliance" element={<CompliancePage />} />
      </Route>
    </Routes>
  )
}
