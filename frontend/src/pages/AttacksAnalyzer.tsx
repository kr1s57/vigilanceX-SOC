import { Swords } from 'lucide-react'

export function AttacksAnalyzer() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-orange-500/10 rounded-lg">
          <Swords className="w-6 h-6 text-orange-500" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">Attacks Analyzer</h1>
          <p className="text-muted-foreground">IPS and intrusion detection analysis</p>
        </div>
      </div>

      <div className="bg-card rounded-xl border p-8 text-center">
        <p className="text-muted-foreground">IPS events and attack analysis coming soon...</p>
      </div>
    </div>
  )
}
