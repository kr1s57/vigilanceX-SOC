import { useState, useEffect } from 'react'
import {
  Shield,
  ShieldAlert,
  Users,
  AlertTriangle,
  Activity,
} from 'lucide-react'
import { StatCard } from '@/components/dashboard/StatCard'
import { TimelineChart } from '@/components/charts/TimelineChart'
import { SeverityChart } from '@/components/charts/SeverityChart'
import { statsApi, eventsApi } from '@/lib/api'
import { formatNumber, formatPercent, getCountryFlag, getSeverityColor } from '@/lib/utils'
import type { OverviewResponse, TimelinePoint, TopAttacker } from '@/types'

export function Dashboard() {
  const [overview, setOverview] = useState<OverviewResponse | null>(null)
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const [period, setPeriod] = useState('24h')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchData() {
      setLoading(true)
      setError(null)
      try {
        const [overviewData, timelineData] = await Promise.all([
          statsApi.overview(period),
          eventsApi.timeline(period, period === '24h' ? 'hour' : 'day'),
        ])
        setOverview(overviewData)
        setTimeline(timelineData)
      } catch (err) {
        setError('Failed to load dashboard data')
        console.error(err)
      } finally {
        setLoading(false)
      }
    }

    fetchData()

    // Refresh every 30 seconds
    const interval = setInterval(fetchData, 30000)
    return () => clearInterval(interval)
  }, [period])

  if (loading && !overview) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (error && !overview) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <AlertTriangle className="w-12 h-12 text-destructive" />
        <p className="text-lg font-medium">{error}</p>
        <button
          onClick={() => window.location.reload()}
          className="px-4 py-2 bg-primary text-primary-foreground rounded-lg"
        >
          Retry
        </button>
      </div>
    )
  }

  const stats = overview?.stats

  return (
    <div className="space-y-6">
      {/* Header with period selector */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Security Dashboard</h1>
          <p className="text-muted-foreground">Real-time security overview</p>
        </div>
        <div className="flex items-center gap-2 bg-muted rounded-lg p-1">
          {['24h', '7d', '30d'].map((p) => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                period === p
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Events"
          value={formatNumber(stats?.total_events || 0)}
          subtitle={`Last ${period}`}
          icon={<Activity className="w-5 h-5 text-primary" />}
        />
        <StatCard
          title="Blocked Events"
          value={formatNumber(stats?.blocked_events || 0)}
          subtitle={`${formatPercent(stats?.block_rate || 0)} block rate`}
          icon={<Shield className="w-5 h-5 text-green-500" />}
          variant="success"
        />
        <StatCard
          title="Critical Alerts"
          value={formatNumber(stats?.critical_events || 0)}
          subtitle={`+ ${formatNumber(stats?.high_events || 0)} high`}
          icon={<ShieldAlert className="w-5 h-5 text-red-500" />}
          variant={stats?.critical_events && stats.critical_events > 0 ? 'critical' : 'default'}
        />
        <StatCard
          title="Unique Attackers"
          value={formatNumber(stats?.unique_ips || 0)}
          subtitle="Distinct source IPs"
          icon={<Users className="w-5 h-5 text-orange-500" />}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart */}
        <div className="lg:col-span-2 bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-4">Event Timeline</h3>
          <TimelineChart data={timeline} height={300} />
        </div>

        {/* Severity Distribution */}
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-4">Severity Distribution</h3>
          {stats && <SeverityChart stats={stats} height={300} />}
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Attackers */}
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-4">Top Attackers</h3>
          <div className="space-y-3">
            {overview?.top_attackers.slice(0, 5).map((attacker, index) => (
              <TopAttackerRow key={attacker.ip} attacker={attacker} rank={index + 1} />
            ))}
            {(!overview?.top_attackers || overview.top_attackers.length === 0) && (
              <p className="text-muted-foreground text-center py-4">No data available</p>
            )}
          </div>
        </div>

        {/* Log Type Distribution */}
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-4">Events by Type</h3>
          <div className="space-y-3">
            {overview?.by_log_type && Object.entries(overview.by_log_type)
              .sort(([, a], [, b]) => b - a)
              .map(([logType, count]) => (
                <LogTypeRow key={logType} logType={logType} count={count} total={stats?.total_events || 1} />
              ))}
            {(!overview?.by_log_type || Object.keys(overview.by_log_type).length === 0) && (
              <p className="text-muted-foreground text-center py-4">No data available</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function TopAttackerRow({ attacker, rank }: { attacker: TopAttacker; rank: number }) {
  const percentage = attacker.attack_count > 0
    ? (attacker.blocked_count / attacker.attack_count) * 100
    : 0

  return (
    <div className="flex items-center gap-4 p-3 rounded-lg bg-muted/50 hover:bg-muted transition-colors">
      <span className="w-6 h-6 rounded-full bg-muted flex items-center justify-center text-xs font-medium">
        {rank}
      </span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm">{attacker.ip}</span>
          {attacker.country && (
            <span className="text-lg">{getCountryFlag(attacker.country)}</span>
          )}
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>{formatNumber(attacker.attack_count)} attacks</span>
          <span>•</span>
          <span>{attacker.unique_rules} rules triggered</span>
        </div>
      </div>
      <div className="text-right">
        <div className="text-sm font-medium text-red-500">
          {formatNumber(attacker.blocked_count)} blocked
        </div>
        <div className="text-xs text-muted-foreground">
          {formatPercent(percentage)}
        </div>
      </div>
    </div>
  )
}

function LogTypeRow({ logType, count, total }: { logType: string; count: number; total: number }) {
  const percentage = (count / total) * 100
  const colorMap: Record<string, string> = {
    WAF: 'bg-blue-500',
    IPS: 'bg-orange-500',
    ATP: 'bg-red-500',
    'Anti-Virus': 'bg-purple-500',
    Firewall: 'bg-green-500',
    VPN: 'bg-cyan-500',
    Heartbeat: 'bg-gray-500',
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium">{logType}</span>
        <span className="text-muted-foreground">
          {formatNumber(count)} ({formatPercent(percentage)})
        </span>
      </div>
      <div className="h-2 bg-muted rounded-full overflow-hidden">
        <div
          className={`h-full ${colorMap[logType] || 'bg-primary'} rounded-full transition-all`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  )
}
