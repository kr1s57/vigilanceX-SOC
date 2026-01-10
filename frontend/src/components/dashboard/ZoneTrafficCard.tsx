import { useState, useEffect } from 'react'
import { ArrowRight, Network, ShieldAlert, RefreshCw } from 'lucide-react'
import { statsApi } from '@/lib/api'
import { formatNumber, formatPercent, cn } from '@/lib/utils'
import type { ZoneTrafficStats, ZoneTraffic } from '@/types'

interface ZoneTrafficCardProps {
  period: string
  refreshInterval?: number
}

export function ZoneTrafficCard({ period, refreshInterval = 0 }: ZoneTrafficCardProps) {
  const [data, setData] = useState<ZoneTrafficStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  async function fetchData() {
    try {
      setError(null)
      const result = await statsApi.zoneTraffic(period, 10)
      setData(result)
    } catch (err) {
      setError('Failed to load zone traffic data')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()

    if (refreshInterval > 0) {
      const interval = setInterval(fetchData, refreshInterval * 1000)
      return () => clearInterval(interval)
    }
  }, [period, refreshInterval])

  if (loading && !data) {
    return (
      <div className="bg-card rounded-xl border p-6">
        <div className="flex items-center gap-2 mb-4">
          <Network className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold">Zone Traffic Flow</h3>
        </div>
        <div className="flex items-center justify-center h-48">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
        </div>
      </div>
    )
  }

  if (error && !data) {
    return (
      <div className="bg-card rounded-xl border p-6">
        <div className="flex items-center gap-2 mb-4">
          <Network className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold">Zone Traffic Flow</h3>
        </div>
        <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
          <p className="text-sm">{error}</p>
          <button
            onClick={fetchData}
            className="mt-2 flex items-center gap-1 text-xs hover:text-foreground"
          >
            <RefreshCw className="w-3 h-3" />
            Retry
          </button>
        </div>
      </div>
    )
  }

  const flows = data?.flows || []
  const hasData = flows.length > 0

  return (
    <div className="bg-card rounded-xl border p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Network className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold">Zone Traffic Flow</h3>
        </div>
        {data && (
          <span className="text-xs text-muted-foreground">
            {data.unique_zones?.length || 0} zones
          </span>
        )}
      </div>

      {!hasData ? (
        <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
          <Network className="w-12 h-12 opacity-30 mb-2" />
          <p className="text-sm">No zone traffic data available</p>
          <p className="text-xs mt-1">Zone information is extracted from XGS logs</p>
        </div>
      ) : (
        <div className="space-y-2">
          {flows.slice(0, 8).map((flow, index) => (
            <ZoneFlowRow key={`${flow.src_zone}-${flow.dst_zone}-${index}`} flow={flow} />
          ))}
        </div>
      )}
    </div>
  )
}

function ZoneFlowRow({ flow }: { flow: ZoneTraffic }) {
  const hasCritical = flow.critical_count > 0
  const hasHigh = flow.high_count > 0
  const isHighRisk = hasCritical || hasHigh || flow.block_rate > 50

  // Color coding for zones
  const zoneColors: Record<string, string> = {
    WAN: 'bg-red-500/20 text-red-400 border-red-500/30',
    LAN: 'bg-green-500/20 text-green-400 border-green-500/30',
    DMZ: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    VPN: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    INTERNAL: 'bg-green-500/20 text-green-400 border-green-500/30',
    EXTERNAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  }

  const getZoneStyle = (zone: string) => {
    const upperZone = zone.toUpperCase()
    for (const [key, value] of Object.entries(zoneColors)) {
      if (upperZone.includes(key)) {
        return value
      }
    }
    return 'bg-gray-500/20 text-gray-400 border-gray-500/30'
  }

  return (
    <div
      className={cn(
        "flex items-center gap-2 p-2 rounded-lg transition-colors",
        isHighRisk ? "bg-red-500/5 hover:bg-red-500/10" : "bg-muted/50 hover:bg-muted"
      )}
    >
      {/* Source Zone */}
      <span
        className={cn(
          "px-2 py-1 text-xs font-medium rounded border min-w-[60px] text-center truncate",
          getZoneStyle(flow.src_zone)
        )}
        title={flow.src_zone}
      >
        {flow.src_zone.length > 8 ? flow.src_zone.slice(0, 8) + '...' : flow.src_zone}
      </span>

      {/* Flow Arrow */}
      <ArrowRight className={cn(
        "w-4 h-4 shrink-0",
        isHighRisk ? "text-red-400" : "text-muted-foreground"
      )} />

      {/* Destination Zone */}
      <span
        className={cn(
          "px-2 py-1 text-xs font-medium rounded border min-w-[60px] text-center truncate",
          getZoneStyle(flow.dst_zone)
        )}
        title={flow.dst_zone}
      >
        {flow.dst_zone.length > 8 ? flow.dst_zone.slice(0, 8) + '...' : flow.dst_zone}
      </span>

      {/* Stats */}
      <div className="flex-1 flex items-center justify-end gap-3 text-xs">
        <span className="text-muted-foreground">
          {formatNumber(flow.event_count)} events
        </span>

        {flow.blocked_count > 0 && (
          <span className="text-red-400 flex items-center gap-1">
            <ShieldAlert className="w-3 h-3" />
            {formatNumber(flow.blocked_count)}
          </span>
        )}

        {flow.block_rate > 0 && (
          <span
            className={cn(
              "px-1.5 py-0.5 rounded text-[10px] font-medium",
              flow.block_rate > 50
                ? "bg-red-500/20 text-red-400"
                : flow.block_rate > 20
                ? "bg-orange-500/20 text-orange-400"
                : "bg-muted text-muted-foreground"
            )}
          >
            {formatPercent(flow.block_rate)}
          </span>
        )}

        {(hasCritical || hasHigh) && (
          <span className="flex items-center gap-1">
            {hasCritical && (
              <span className="w-2 h-2 rounded-full bg-red-500" title={`${flow.critical_count} critical`} />
            )}
            {hasHigh && (
              <span className="w-2 h-2 rounded-full bg-orange-500" title={`${flow.high_count} high`} />
            )}
          </span>
        )}
      </div>
    </div>
  )
}
