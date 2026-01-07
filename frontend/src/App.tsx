import { Routes, Route } from 'react-router-dom'
import { Layout } from '@/components/layout/Layout'
import { Dashboard } from '@/pages/Dashboard'
import { WafExplorer } from '@/pages/WafExplorer'
import { AttacksAnalyzer } from '@/pages/AttacksAnalyzer'
import { AdvancedThreat } from '@/pages/AdvancedThreat'
import { VpnNetwork } from '@/pages/VpnNetwork'
import { ActiveBans } from '@/pages/ActiveBans'
import { Geoblocking } from '@/pages/Geoblocking'
import { Reports } from '@/pages/Reports'
import { Settings } from '@/pages/Settings'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/waf" element={<WafExplorer />} />
        <Route path="/attacks" element={<AttacksAnalyzer />} />
        <Route path="/threats" element={<AdvancedThreat />} />
        <Route path="/vpn" element={<VpnNetwork />} />
        <Route path="/bans" element={<ActiveBans />} />
        <Route path="/geoblocking" element={<Geoblocking />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </Layout>
  )
}

export default App
