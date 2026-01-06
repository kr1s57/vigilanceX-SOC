import { Network } from 'lucide-react'

export function VpnNetwork() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-cyan-500/10 rounded-lg">
          <Network className="w-6 h-6 text-cyan-500" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">VPN & Network</h1>
          <p className="text-muted-foreground">VPN sessions and network monitoring</p>
        </div>
      </div>

      <div className="bg-card rounded-xl border p-8 text-center">
        <p className="text-muted-foreground">VPN and network analysis coming soon...</p>
      </div>
    </div>
  )
}
