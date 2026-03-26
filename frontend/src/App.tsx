import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/ui/Layout'
import DashboardPage from './pages/DashboardPage'
import IntelPage from './pages/IntelPage'
import CasesPage from './pages/CasesPage'
import DarkWebPage from './pages/DarkWebPage'
import ConnectorsPage from './pages/ConnectorsPage'
import ObjectDetailPage from './pages/ObjectDetailPage'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="intel" element={<IntelPage />} />
        <Route path="intel/:stixId" element={<ObjectDetailPage />} />
        <Route path="cases" element={<CasesPage />} />
        <Route path="darkweb" element={<DarkWebPage />} />
        <Route path="connectors" element={<ConnectorsPage />} />
      </Route>
    </Routes>
  )
}
