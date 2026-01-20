import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
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
  Search,
  ShieldCheck,
} from 'lucide-react'
import { StatCard } from '@/components/dashboard/StatCard'
import { TimelineChart } from '@/components/charts/TimelineChart'
import { SeverityChart } from '@/components/charts/SeverityChart'
import { WAFServersCard } from '@/components/dashboard/WAFServersCard'
import { XGSLoginCard } from '@/components/dashboard/XGSLoginCard'
import { IPThreatModal } from '@/components/IPThreatModal'
import { statsApi, eventsApi, alertsApi, pendingBansApi } from '@/lib/api'
import { formatNumber, formatPercent, getCountryFlag, cn } from '@/lib/utils'
import { useSettings } from '@/contexts/SettingsContext'
import { useLicense } from '@/contexts/LicenseContext'
import type { OverviewResponse, TimelinePoint, TopAttacker, CriticalAlert, PendingBanStats } from '@/types'

// v3.57.118: Current installed version
const INSTALLED_VERSION = '3.57.126'

// v3.57.125: Semantic version comparison (returns -1, 0, or 1)
function compareVersions(v1: string, v2: string): number {
  const parts1 = v1.split('.').map(Number)
  const parts2 = v2.split('.').map(Number)
  for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
    const p1 = parts1[i] || 0
    const p2 = parts2[i] || 0
    if (p1 < p2) return -1
    if (p1 > p2) return 1
  }
  return 0
}

// v3.57.117: Added 8h filter option
type Period = '1h' | '8h' | '24h' | '7d' | '30d'

export function Dashboard() {
  const navigate = useNavigate()
  const { settings } = useSettings()
  const { status: licenseStatus } = useLicense()
  const [overview, setOverview] = useState<OverviewResponse | null>(null)
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const [criticalAlerts, setCriticalAlerts] = useState<CriticalAlert[]>([])
  // v3.57.114: Pending approval stats for Authorized Countries
  const [pendingStats, setPendingStats] = useState<PendingBanStats | null>(null)
  // Persist time filter in sessionStorage (resets on new browser session)
  const [period, setPeriod] = useState<Period>(() => {
    const stored = sessionStorage.getItem('dashboard_timeRange')
    return (stored as Period) || settings.defaultPeriod
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showAlertsModal, setShowAlertsModal] = useState(false)
  // v3.57.108: IP Threat Modal state
  const [threatModalIP, setThreatModalIP] = useState<string | null>(null)
  // v3.57.121: Latest version from GitHub
  const [latestGitVersion, setLatestGitVersion] = useState<string | null>(null)

  // v3.57.121: Fetch latest version from GitHub releases
  useEffect(() => {
    async function fetchLatestVersion() {
      try {
        const response = await fetch('https://api.github.com/repos/kr1s57/vigilanceX-SOC/releases/latest')
        if (response.ok) {
          const data = await response.json()
          // tag_name format: "v3.57.121" -> extract "3.57.121"
          const version = data.tag_name?.replace(/^v/, '') || null
          setLatestGitVersion(version)
        }
      } catch {
        // Silent fail - version check is optional
        setLatestGitVersion(null)
      }
    }
    fetchLatestVersion()
  }, [])

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
          eventsApi.timeline(period, period === '24h' || period === '8h' || period === '1h' ? 'hour' : 'day'),
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

  // v3.57.114: Fetch pending approval stats (separate from main data)
  useEffect(() => {
    async function fetchPendingStats() {
      try {
        const stats = await pendingBansApi.stats()
        setPendingStats(stats)
      } catch {
        // Silent fail - pending stats are optional
        setPendingStats(null)
      }
    }

    fetchPendingStats()

    // Refresh pending stats on same interval
    if (settings.refreshInterval > 0) {
      const interval = setInterval(fetchPendingStats, settings.refreshInterval * 1000)
      return () => clearInterval(interval)
    }
  }, [settings.refreshInterval])

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
            {/* v3.57.121: Version badge with GitHub release check - v3.57.125: Semver comparison */}
            {(() => {
              // Use GitHub release version, fallback to license server version
              const latestVersion = latestGitVersion || licenseStatus?.latest_vgx_version
              // v3.57.125: Use semver comparison - up to date if installed >= latest
              const isUpToDate = latestVersion ? compareVersions(INSTALLED_VERSION, latestVersion) >= 0 : null
              const hasUpdate = isUpToDate === false

              const badgeContent = (
                <>
                  {isUpToDate === null ? (
                    <>
                      <Activity className="w-3 h-3 animate-pulse" />
                      v{INSTALLED_VERSION}
                    </>
                  ) : isUpToDate ? (
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
                </>
              )

              const badgeClasses = cn(
                "px-2 py-0.5 rounded text-xs font-medium flex items-center gap-1",
                isUpToDate === null
                  ? "bg-zinc-500/10 text-zinc-500" // Unknown state
                  : isUpToDate
                  ? "bg-green-500/10 text-green-500"
                  : "bg-orange-500/10 text-orange-500 cursor-pointer hover:bg-orange-500/20 transition-colors"
              )

              const badgeTitle = isUpToDate === null
                ? "Checking for updates..."
                : isUpToDate
                ? "Up to date"
                : `Update available: ${latestVersion} - Click to update`

              // Make clickable only when update is available - v3.57.123: Navigate to Settings System tab
              return hasUpdate ? (
                <button
                  onClick={() => navigate('/settings?tab=system')}
                  className={badgeClasses}
                  title={badgeTitle}
                >
                  {badgeContent}
                </button>
              ) : (
                <span className={badgeClasses} title={badgeTitle}>
                  {badgeContent}
                </span>
              )
            })()}
          </div>
          <p className="text-muted-foreground">Real-time security overview</p>
        </div>
        <div className="flex items-center gap-4">
          <DashboardClock timezone={settings.timezone} show={settings.showDashboardClock} />
          <div className="flex items-center gap-2 bg-muted rounded-lg p-1">
            {(['1h', '8h', '24h', '7d', '30d'] as Period[]).map((p) => (
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

      {/* v3.57.114: Pending Approvals Alert Banner (v3.57.118: Enhanced with FP + Country Policy) */}
      {pendingStats && pendingStats.total_pending > 0 && (
        <div
          onClick={() => navigate('/bans?status=pending')}
          className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 cursor-pointer hover:bg-amber-500/15 transition-colors"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-amber-500/20 rounded-lg">
                <ShieldCheck className="w-5 h-5 text-amber-500" />
              </div>
              <div>
                <h3 className="font-semibold text-amber-600 dark:text-amber-400">
                  WAF Ban - False Positive - Pending Approval
                </h3>
                <p className="text-sm text-muted-foreground">
                  {pendingStats.total_pending} IP{pendingStats.total_pending > 1 ? 's' : ''} require admin review before ban action
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="flex items-center gap-2 text-sm flex-wrap justify-end">
                  {/* v3.57.118: FP and Country Policy counts */}
                  {(pendingStats.false_positive_count ?? 0) > 0 && (
                    <span className="px-2 py-0.5 bg-purple-500/20 text-purple-500 rounded text-xs font-medium">
                      {pendingStats.false_positive_count} False Positive
                    </span>
                  )}
                  {(pendingStats.country_policy_count ?? 0) > 0 && (
                    <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-500 rounded text-xs font-medium">
                      {pendingStats.country_policy_count} Country Policy
                    </span>
                  )}
                  {pendingStats.high_threat > 0 && (
                    <span className="px-2 py-0.5 bg-red-500/20 text-red-500 rounded text-xs font-medium">
                      {pendingStats.high_threat} High
                    </span>
                  )}
                  {pendingStats.medium_threat > 0 && (
                    <span className="px-2 py-0.5 bg-orange-500/20 text-orange-500 rounded text-xs font-medium">
                      {pendingStats.medium_threat} Medium
                    </span>
                  )}
                  {pendingStats.low_threat > 0 && (
                    <span className="px-2 py-0.5 bg-blue-500/20 text-blue-500 rounded text-xs font-medium">
                      {pendingStats.low_threat} Low
                    </span>
                  )}
                </div>
              </div>
              <span className="text-amber-500 text-sm font-medium">Review &rarr;</span>
            </div>
          </div>
        </div>
      )}

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

      {/* Bottom Row - v3.57.107: Layout Top Attackers | WAF | Events | XGS Logins */}
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
              <TopAttackerRow
                key={attacker.ip}
                attacker={attacker}
                rank={index + 1}
                onViewThreat={setThreatModalIP}
              />
            ))}
            {(!overview?.top_attackers || overview.top_attackers.length === 0) && (
              <p className="text-muted-foreground text-center py-4">No data available</p>
            )}
          </div>
        </div>

        {/* WAF Servers Status - Position 2 */}
        <WAFServersCard refreshInterval={settings.refreshInterval} />

        {/* Log Type Distribution - v3.57.107: Increased height */}
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-3">Events by Type</h3>
          <div className="space-y-1.5 max-h-[180px] overflow-y-auto pr-2 scrollbar-thin">
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

        {/* XGS Login Activity - Position 4 */}
        <XGSLoginCard refreshInterval={settings.refreshInterval} />
      </div>

      {/* Critical Alerts Modal */}
      {showAlertsModal && (
        <CriticalAlertsModal
          alerts={criticalAlerts}
          onClose={() => setShowAlertsModal(false)}
          onViewThreat={setThreatModalIP}
        />
      )}

      {/* v3.57.108: IP Threat Modal - key forces remount on IP change */}
      <IPThreatModal
        key={threatModalIP || 'closed'}
        ip={threatModalIP}
        isOpen={threatModalIP !== null}
        onClose={() => setThreatModalIP(null)}
      />
    </div>
  )
}

function CriticalAlertsModal({
  alerts,
  onClose,
  onViewThreat,
}: {
  alerts: CriticalAlert[]
  onClose: () => void
  onViewThreat: (ip: string) => void
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
                <AlertRow key={alert.event_id} alert={alert} onViewThreat={onViewThreat} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function AlertRow({ alert, onViewThreat }: { alert: CriticalAlert; onViewThreat: (ip: string) => void }) {
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
            {/* v3.57.108: Add magnifying glass to view IP threat details */}
            <span className="flex items-center gap-1">
              <span className="font-mono">{alert.src_ip}</span>
              <button
                onClick={() => onViewThreat(alert.src_ip)}
                className="p-0.5 hover:bg-muted rounded transition-colors"
                title="View threat details"
              >
                <Search className="w-3.5 h-3.5 text-muted-foreground hover:text-primary" />
              </button>
            </span>
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

function TopAttackerRow({
  attacker,
  rank,
  onViewThreat,
}: {
  attacker: TopAttacker
  rank: number
  onViewThreat: (ip: string) => void
}) {
  const detectedCount = attacker.attack_count - attacker.blocked_count

  return (
    <div className="flex items-center gap-4 p-3 rounded-lg bg-muted/50 hover:bg-muted transition-colors">
      <span className="w-6 h-6 rounded-full bg-muted flex items-center justify-center text-xs font-medium">
        {rank}
      </span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm">{attacker.ip}</span>
          {/* v3.57.108: Magnifying glass to view threat details */}
          <button
            onClick={() => onViewThreat(attacker.ip)}
            className="p-0.5 hover:bg-background rounded transition-colors"
            title="View threat details"
          >
            <Search className="w-3.5 h-3.5 text-muted-foreground hover:text-primary" />
          </button>
          {attacker.country && (
            <span className="text-lg">{getCountryFlag(attacker.country)}</span>
          )}
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>{attacker.unique_rules} rules triggered</span>
        </div>
      </div>
      {/* v3.57.108: Show blocked (red) and detected (orange) counts */}
      <div className="text-right flex items-center gap-3">
        <div>
          <div className="text-sm font-medium text-red-500">
            {formatNumber(attacker.blocked_count)}
          </div>
          <div className="text-xs text-muted-foreground">blocked</div>
        </div>
        <div>
          <div className="text-sm font-medium text-orange-500">
            {formatNumber(detectedCount)}
          </div>
          <div className="text-xs text-muted-foreground">detected</div>
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
