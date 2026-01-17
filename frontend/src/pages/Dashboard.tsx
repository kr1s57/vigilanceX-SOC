import { useState, useEffect } from 'react'
import {
  Shield,
  ShieldAlert,
  Users,
  AlertTriangle,
  Activity,
  X,
  Clock,
  ArrowUp,
  CheckCircle2,
} from 'lucide-react'
import { StatCard } from '@/components/dashboard/StatCard'
import { TimelineChart } from '@/components/charts/TimelineChart'
import { SeverityChart } from '@/components/charts/SeverityChart'
import { WAFServersCard } from '@/components/dashboard/WAFServersCard'
import { XGSLoginCard } from '@/components/dashboard/XGSLoginCard'
import { statsApi, eventsApi, alertsApi } from '@/lib/api'
import { formatNumber, formatPercent, getCountryFlag, cn } from '@/lib/utils'
import { useSettings } from '@/contexts/SettingsContext'
import { useLicense } from '@/contexts/LicenseContext'
import type { OverviewResponse, TimelinePoint, TopAttacker, CriticalAlert } from '@/types'

// v3.57.105: Current installed version
const INSTALLED_VERSION = '3.57.105'

type Period = '1h' | '24h' | '7d' | '30d'

export function Dashboard() {
  const { settings } = useSettings()
  const { status: licenseStatus } = useLicense()
  const [overview, setOverview] = useState<OverviewResponse | null>(null)
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const [criticalAlerts, setCriticalAlerts] = useState<CriticalAlert[]>([])
  // Persist time filter in sessionStorage (resets on new browser session)
  const [period, setPeriod] = useState<Period>(() => {
    const stored = sessionStorage.getItem('dashboard_timeRange')
    return (stored as Period) || settings.defaultPeriod
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showAlertsModal, setShowAlertsModal] = useState(false)

  // Save period to sessionStorage when it changes
  useEffect(() => {
    sessionStorage.setItem('dashboard_timeRange', period)
  }, [period])

  useEffect(() => {
    async function fetchData() {
      setLoading(true)
      setError(null)
      try {
        const [overviewData, timelineData, alertsData] = await Promise.all([
          statsApi.overview(period),
          eventsApi.timeline(period, period === '24h' || period === '1h' ? 'hour' : 'day'),
          alertsApi.critical(20, period),
        ])
        setOverview(overviewData)
        setTimeline(timelineData)
        setCriticalAlerts(alertsData.data || [])
      } catch (err) {
        setError('Failed to load dashboard data')
        console.error(err)
      } finally {
        setLoading(false)
      }
    }

    fetchData()

    // Refresh based on settings (0 = manual/disabled)
    if (settings.refreshInterval > 0) {
      const interval = setInterval(fetchData, settings.refreshInterval * 1000)
      return () => clearInterval(interval)
    }
  }, [period, settings.refreshInterval])

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
      {/* Header with period selector and clock */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold">Security Dashboard</h1>
            {/* v3.55.116: Version badge with update check */}
            {(() => {
              const latestVersion = licenseStatus?.latest_vgx_version
              const isUpToDate = !latestVersion || latestVersion === INSTALLED_VERSION
              return (
                <span
                  className={cn(
                    "px-2 py-0.5 rounded text-xs font-medium flex items-center gap-1",
                    isUpToDate
                      ? "bg-green-500/10 text-green-500"
                      : "bg-orange-500/10 text-orange-500"
                  )}
                  title={isUpToDate ? "Up to date" : `Update available: ${latestVersion}`}
                >
                  {isUpToDate ? (
                    <>
                      <CheckCircle2 className="w-3 h-3" />
                      v{INSTALLED_VERSION}
                    </>
                  ) : (
                    <>
                      <ArrowUp className="w-3 h-3" />
                      Update: v{latestVersion}
                    </>
                  )}
                </span>
              )
            })()}
          </div>
          <p className="text-muted-foreground">Real-time security overview</p>
        </div>
        <div className="flex items-center gap-4">
          <DashboardClock timezone={settings.timezone} show={settings.showDashboardClock} />
          <div className="flex items-center gap-2 bg-muted rounded-lg p-1">
            {(['1h', '24h', '7d', '30d'] as Period[]).map((p) => (
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
        <div
          onClick={() => setShowAlertsModal(true)}
          className="cursor-pointer transition-transform hover:scale-[1.02]"
        >
          <StatCard
            title="Critical & High"
            value={formatNumber((stats?.critical_events || 0) + (stats?.high_events || 0))}
            subtitle={`${formatNumber(stats?.critical_events || 0)} critical, ${formatNumber(stats?.high_events || 0)} high`}
            icon={<ShieldAlert className="w-5 h-5 text-red-500" />}
            variant={stats?.critical_events && stats.critical_events > 0 ? 'critical' : 'default'}
          />
        </div>
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

      {/* Bottom Row - 2x2 grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Top Attackers - 5 visible with scroll */}
        <div className="bg-card rounded-xl border p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Top Attackers</h3>
            {overview?.top_attackers && overview.top_attackers.length > 5 && (
              <span className="text-xs text-muted-foreground">
                {overview.top_attackers.length} total
              </span>
            )}
          </div>
          <div className="space-y-2 max-h-[320px] overflow-y-auto pr-2 scrollbar-thin">
            {overview?.top_attackers.slice(0, settings.topAttackersCount).map((attacker, index) => (
              <TopAttackerRow key={attacker.ip} attacker={attacker} rank={index + 1} />
            ))}
            {(!overview?.top_attackers || overview.top_attackers.length === 0) && (
              <p className="text-muted-foreground text-center py-4">No data available</p>
            )}
          </div>
        </div>

        {/* Log Type Distribution - very compact */}
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-3">Events by Type</h3>
          <div className="space-y-1.5 max-h-[100px] overflow-y-auto pr-2 scrollbar-thin">
            {overview?.by_log_type && Object.entries(overview.by_log_type)
              .sort(([, a], [, b]) => b - a)
              .map(([logType, count]) => (
                <LogTypeRowCompact key={logType} logType={logType} count={count} total={stats?.total_events || 1} />
              ))}
            {(!overview?.by_log_type || Object.keys(overview.by_log_type).length === 0) && (
              <p className="text-muted-foreground text-center py-2 text-sm">No data</p>
            )}
          </div>
        </div>

        {/* XGS Login Activity */}
        <XGSLoginCard refreshInterval={settings.refreshInterval} />

        {/* WAF Servers Status (v3.57.101) */}
        <WAFServersCard refreshInterval={settings.refreshInterval} />
      </div>

      {/* Critical Alerts Modal */}
      {showAlertsModal && (
        <CriticalAlertsModal
          alerts={criticalAlerts}
          onClose={() => setShowAlertsModal(false)}
        />
      )}
    </div>
  )
}

function CriticalAlertsModal({
  alerts,
  onClose
}: {
  alerts: CriticalAlert[]
  onClose: () => void
}) {
  const criticalCount = alerts.filter(a => a.severity === 'critical').length
  const highCount = alerts.filter(a => a.severity === 'high').length

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-card rounded-xl border shadow-xl w-full max-w-4xl max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <div>
            <h2 className="text-xl font-semibold flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-red-500" />
              Critical Security Alerts
            </h2>
            <p className="text-sm text-muted-foreground mt-1">
              {criticalCount} critical, {highCount} high severity alerts
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-muted rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-6">
          {alerts.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No critical or high severity alerts found</p>
            </div>
          ) : (
            <div className="space-y-3">
              {alerts.map((alert) => (
                <AlertRow key={alert.event_id} alert={alert} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function AlertRow({ alert }: { alert: CriticalAlert }) {
  const severityColors = {
    critical: 'border-l-red-500 bg-red-500/5',
    high: 'border-l-orange-500 bg-orange-500/5',
    medium: 'border-l-yellow-500 bg-yellow-500/5',
    low: 'border-l-blue-500 bg-blue-500/5',
  }

  return (
    <div className={cn(
      "p-4 rounded-lg border-l-4 hover:bg-muted/30 transition-colors",
      severityColors[alert.severity as keyof typeof severityColors] || 'border-l-gray-500'
    )}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2">
            <span className={cn(
              "text-xs font-bold px-2 py-0.5 rounded uppercase",
              alert.severity === 'critical' ? 'bg-red-500/20 text-red-500' :
              alert.severity === 'high' ? 'bg-orange-500/20 text-orange-500' :
              'bg-yellow-500/20 text-yellow-500'
            )}>
              {alert.severity}
            </span>
            <span className="text-xs bg-muted px-2 py-0.5 rounded">{alert.log_type}</span>
            <span className="text-xs text-muted-foreground">{alert.category}</span>
          </div>
          <p className="font-medium mb-1">
            {alert.rule_name || alert.message || `Rule ${alert.rule_id}`}
          </p>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
            <span className="font-mono">{alert.src_ip}</span>
            {alert.dst_ip && (
              <>
                <span>→</span>
                <span className="font-mono">{alert.dst_ip}</span>
              </>
            )}
            {alert.hostname && (
              <span className="truncate">Target: {alert.hostname}</span>
            )}
            {alert.country && (
              <span>{getCountryFlag(alert.country)} {alert.country}</span>
            )}
          </div>
          {alert.message && alert.message !== alert.rule_name && (
            <p className="text-sm text-muted-foreground mt-2 truncate">
              {alert.message}
            </p>
          )}
        </div>
        <div className="text-right shrink-0">
          <p className="text-sm font-medium">
            {new Date(alert.timestamp).toLocaleTimeString()}
          </p>
          <p className="text-xs text-muted-foreground">
            {new Date(alert.timestamp).toLocaleDateString()}
          </p>
          {alert.action && (
            <span className={cn(
              "text-xs px-2 py-0.5 rounded mt-1 inline-block",
              alert.action === 'drop' || alert.action === 'reject' || alert.action === 'blocked'
                ? 'bg-green-500/20 text-green-500'
                : 'bg-yellow-500/20 text-yellow-500'
            )}>
              {alert.action}
            </span>
          )}
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

// Compact version for dashboard
function LogTypeRowCompact({ logType, count, total }: { logType: string; count: number; total: number }) {
  const percentage = (count / total) * 100
  const colorMap: Record<string, string> = {
    WAF: 'bg-blue-500',
    IPS: 'bg-orange-500',
    ATP: 'bg-red-500',
    'Anti-Virus': 'bg-purple-500',
    Firewall: 'bg-green-500',
    VPN: 'bg-cyan-500',
    Heartbeat: 'bg-gray-500',
    Event: 'bg-yellow-500',
  }

  return (
    <div className="flex items-center gap-2">
      <div className={`w-2 h-2 rounded-full ${colorMap[logType] || 'bg-primary'}`} />
      <span className="text-xs font-medium flex-1">{logType}</span>
      <span className="text-xs text-muted-foreground">{formatNumber(count)}</span>
      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
        <div
          className={`h-full ${colorMap[logType] || 'bg-primary'} rounded-full`}
          style={{ width: `${Math.min(percentage, 100)}%` }}
        />
      </div>
    </div>
  )
}

// Clock component for dashboard header
function DashboardClock({ timezone, show }: { timezone: string; show: boolean }) {
  const [time, setTime] = useState(new Date())

  useEffect(() => {
    if (!show) return
    const timer = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(timer)
  }, [show])

  if (!show) return null

  const formattedTime = time.toLocaleTimeString('fr-FR', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone: timezone,
    hour12: false,
  })

  const formattedDate = time.toLocaleDateString('fr-FR', {
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    timeZone: timezone,
  })

  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground">
      <Clock className="w-4 h-4" />
      <span className="font-mono">{formattedTime}</span>
      <span className="text-xs hidden sm:inline">({formattedDate})</span>
    </div>
  )
}
