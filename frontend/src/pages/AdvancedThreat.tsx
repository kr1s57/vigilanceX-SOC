import { AlertTriangle } from 'lucide-react'

export function AdvancedThreat() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-red-500/10 rounded-lg">
          <AlertTriangle className="w-6 h-6 text-red-500" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">Advanced Threat</h1>
          <p className="text-muted-foreground">ATP, APT and malware detection</p>
        </div>
      </div>

      <div className="bg-card rounded-xl border p-8 text-center">
        <p className="text-muted-foreground">Advanced threat analysis coming soon...</p>
      </div>
    </div>
  )
}
