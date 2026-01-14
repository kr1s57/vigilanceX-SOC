import { Routes, Route } from 'react-router-dom'
import { Layout } from '@/components/layout/Layout'
import ProtectedRoute from '@/components/ProtectedRoute'
import AdminRoute from '@/components/AdminRoute'
import Login from '@/pages/Login'
import LicenseActivation from '@/pages/LicenseActivation'
import { Dashboard } from '@/pages/Dashboard'
import { AttackMap } from '@/pages/AttackMap'
import { WafExplorer } from '@/pages/WafExplorer'
import { AttacksAnalyzer } from '@/pages/AttacksAnalyzer'
import { AdvancedThreat } from '@/pages/AdvancedThreat'
import { VpnNetwork } from '@/pages/VpnNetwork'
import { ActiveBans } from '@/pages/ActiveBans'
import { Geoblocking } from '@/pages/Geoblocking'
import { SoftWhitelist } from '@/pages/SoftWhitelist'
import { RiskScoring } from '@/pages/RiskScoring'
import { NeuralSync } from '@/pages/NeuralSync'
import { CrowdSecBL } from '@/pages/CrowdSecBL'
import { VigimailChecker } from '@/pages/VigimailChecker'
import { Reports } from '@/pages/Reports'
import { Settings } from '@/pages/Settings'
import UserManagement from '@/pages/UserManagement'

function App() {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/login" element={<Login />} />
      <Route path="/license" element={<LicenseActivation />} />

      {/* Protected routes - All authenticated users */}
      <Route
        path="/*"
        element={
          <ProtectedRoute
            element={
              <Layout>
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/attack-map" element={<AttackMap />} />
                  <Route path="/waf" element={<WafExplorer />} />
                  <Route path="/attacks" element={<AttacksAnalyzer />} />
                  <Route path="/threats" element={<AdvancedThreat />} />
                  <Route path="/vpn" element={<VpnNetwork />} />
                  <Route path="/bans" element={<ActiveBans />} />
                  <Route path="/geoblocking" element={<Geoblocking />} />
                  <Route path="/whitelist" element={<SoftWhitelist />} />
                  <Route path="/scoring" element={<RiskScoring />} />
                  <Route path="/crowdsec-bl" element={<CrowdSecBL />} />
                  <Route path="/neural-sync" element={<NeuralSync />} />
                  <Route path="/vigimail" element={<VigimailChecker />} />
                  {/* Admin-only routes */}
                  <Route path="/reports" element={<AdminRoute><Reports /></AdminRoute>} />
                  <Route path="/settings" element={<AdminRoute><Settings /></AdminRoute>} />
                  <Route path="/users" element={<AdminRoute><UserManagement /></AdminRoute>} />
                </Routes>
              </Layout>
            }
          />
        }
      />
    </Routes>
  )
}

export default App
