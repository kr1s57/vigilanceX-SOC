import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { Suspense, lazy } from 'react'
import { AnimatePresence } from 'framer-motion'
import { Layout } from '@/components/layout/Layout'
import ProtectedRoute from '@/components/ProtectedRoute'
import AdminRoute from '@/components/AdminRoute'
import { PageTransition } from '@/components/ui/PageTransition'
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
// v3.57.117: UserManagement moved to Settings tab - import kept for lazy loading there

// Loading fallback component with animation
const PageLoader = () => (
  <PageTransition>
    <div className="flex items-center justify-center h-full min-h-[400px]">
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
        <span className="text-sm text-muted-foreground">Loading...</span>
      </div>
    </div>
  </PageTransition>
)

// Animated page wrapper
function AnimatedPage({ children }: { children: React.ReactNode }) {
  return <PageTransition>{children}</PageTransition>
}

function App() {
  const location = useLocation()

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
                  <AnimatePresence mode="wait">
                    <Routes location={location} key={location.pathname}>
                      <Route path="/" element={<AnimatedPage><Dashboard /></AnimatedPage>} />
                      <Route path="/attack-map" element={<AnimatedPage><AttackMap /></AnimatedPage>} />
                      <Route path="/waf" element={<AnimatedPage><WafExplorer /></AnimatedPage>} />
                      <Route path="/attacks" element={<AnimatedPage><AttacksAnalyzer /></AnimatedPage>} />
                      <Route path="/threats" element={<AnimatedPage><AdvancedThreat /></AnimatedPage>} />
                      <Route path="/vpn" element={<AnimatedPage><VpnNetwork /></AnimatedPage>} />
                      <Route path="/bans" element={<AnimatedPage><ActiveBans /></AnimatedPage>} />
                      <Route path="/geoblocking" element={<AnimatedPage><Geoblocking /></AnimatedPage>} />
                      <Route path="/whitelist" element={<AnimatedPage><SoftWhitelist /></AnimatedPage>} />
                      <Route path="/scoring" element={<AnimatedPage><RiskScoring /></AnimatedPage>} />
                      <Route path="/crowdsec-bl" element={<AnimatedPage><CrowdSecBL /></AnimatedPage>} />
                      <Route path="/neural-sync" element={<AnimatedPage><NeuralSync /></AnimatedPage>} />
                      <Route path="/vigimail" element={<AnimatedPage><VigimailChecker /></AnimatedPage>} />
                      <Route path="/track-ip" element={<AnimatedPage><TrackIP /></AnimatedPage>} />
                      {/* Admin-only routes */}
                      <Route path="/reports" element={<AdminRoute><AnimatedPage><Reports /></AnimatedPage></AdminRoute>} />
                      <Route path="/settings" element={<AdminRoute><AnimatedPage><Settings /></AnimatedPage></AdminRoute>} />
                      {/* v3.57.117: Redirect /users to Settings Users tab */}
                      <Route path="/users" element={<Navigate to="/settings?tab=users" replace />} />
                    </Routes>
                  </AnimatePresence>
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
