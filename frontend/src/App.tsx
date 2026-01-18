import { Routes, Route } from 'react-router-dom'
import { Suspense, lazy } from 'react'
import { Layout } from '@/components/layout/Layout'
import ProtectedRoute from '@/components/ProtectedRoute'
import AdminRoute from '@/components/AdminRoute'
import { Loader2 } from 'lucide-react'

// v3.57.106: Lazy loading for improved initial bundle size and load times
// Login and LicenseActivation are not lazy loaded as they are entry points
import Login from '@/pages/Login'
import LicenseActivation from '@/pages/LicenseActivation'

// Lazy load all other pages - they will be loaded on-demand
const Dashboard = lazy(() => import('@/pages/Dashboard').then(m => ({ default: m.Dashboard })))
const AttackMap = lazy(() => import('@/pages/AttackMap').then(m => ({ default: m.AttackMap })))
const WafExplorer = lazy(() => import('@/pages/WafExplorer').then(m => ({ default: m.WafExplorer })))
const AttacksAnalyzer = lazy(() => import('@/pages/AttacksAnalyzer').then(m => ({ default: m.AttacksAnalyzer })))
const AdvancedThreat = lazy(() => import('@/pages/AdvancedThreat').then(m => ({ default: m.AdvancedThreat })))
const VpnNetwork = lazy(() => import('@/pages/VpnNetwork').then(m => ({ default: m.VpnNetwork })))
const ActiveBans = lazy(() => import('@/pages/ActiveBans').then(m => ({ default: m.ActiveBans })))
const Geoblocking = lazy(() => import('@/pages/Geoblocking').then(m => ({ default: m.Geoblocking })))
const SoftWhitelist = lazy(() => import('@/pages/SoftWhitelist').then(m => ({ default: m.SoftWhitelist })))
const RiskScoring = lazy(() => import('@/pages/RiskScoring').then(m => ({ default: m.RiskScoring })))
const NeuralSync = lazy(() => import('@/pages/NeuralSync').then(m => ({ default: m.NeuralSync })))
const CrowdSecBL = lazy(() => import('@/pages/CrowdSecBL').then(m => ({ default: m.CrowdSecBL })))
const VigimailChecker = lazy(() => import('@/pages/VigimailChecker').then(m => ({ default: m.VigimailChecker })))
const TrackIP = lazy(() => import('@/pages/TrackIP').then(m => ({ default: m.TrackIP })))
const Reports = lazy(() => import('@/pages/Reports').then(m => ({ default: m.Reports })))
const Settings = lazy(() => import('@/pages/Settings').then(m => ({ default: m.Settings })))
const UserManagement = lazy(() => import('@/pages/UserManagement'))

// Loading fallback component
const PageLoader = () => (
  <div className="flex items-center justify-center h-full min-h-[400px]">
    <div className="flex flex-col items-center gap-3">
      <Loader2 className="w-8 h-8 animate-spin text-primary" />
      <span className="text-sm text-muted-foreground">Loading...</span>
    </div>
  </div>
)

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
                <Suspense fallback={<PageLoader />}>
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
                    <Route path="/track-ip" element={<TrackIP />} />
                    {/* Admin-only routes */}
                    <Route path="/reports" element={<AdminRoute><Reports /></AdminRoute>} />
                    <Route path="/settings" element={<AdminRoute><Settings /></AdminRoute>} />
                    <Route path="/users" element={<AdminRoute><UserManagement /></AdminRoute>} />
                  </Routes>
                </Suspense>
              </Layout>
            }
          />
        }
      />
    </Routes>
  )
}

export default App
