// v3.57.101: WAF Servers overview card for Dashboard with detail modal
import { useState, useEffect } from 'react'
import {
  Server,
  ShieldCheck,
  ShieldOff,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Activity,
  RefreshCw,
  Globe,
  X,
  Clock,
  Target,
  Users,
  Zap,
  TrendingUp,
  Shield,
  Loader2
} from 'lucide-react'
import { wafServersApi, modsecApi, type WAFMonitoredServer } from '@/lib/api'
import type { ModSecRequestGroup } from '@/types'
import { cn, getCountryFlag, formatNumber } from '@/lib/utils'

interface WAFServersCardProps {
  refreshInterval?: number
}

interface ServerWithStats extends WAFMonitoredServer {
  recent_attacks: number
  recent_blocks: number
  last_attack_time?: string
}

interface ServerDetailData {
  server: ServerWithStats
  topAttackTypes: { type: string; count: number }[]
  topAttackerIPs: { ip: string; count: number; blocked: number; country?: string }[]
  recentLogs: ModSecRequestGroup[]
  totalBlocked: number
  blockRate: number
}

export function WAFServersCard({ refreshInterval = 0 }: WAFServersCardProps) {
  const [servers, setServers] = useState<ServerWithStats[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedServer, setSelectedServer] = useState<ServerWithStats | null>(null)

  async function fetchData() {
    try {
      setError(null)

      // Fetch WAF servers
      const serversResponse = await wafServersApi.list()
      const serverList = serversResponse.data || []

      // Fetch recent attack stats per hostname (last 24h)
      // Use getGroupedLogs to get unique attack requests (matches WAF Explorer)
      const now = new Date()
      const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)
      const statsPromises = serverList.map(async (server) => {
        try {
          const logsResponse = await modsecApi.getGroupedLogs({
            hostname: server.hostname,
            start_time: dayAgo.toISOString(),
            limit: 500,
            offset: 0
          })
          const requests = logsResponse.data || []
          const blockCount = requests.filter((r) => r.is_blocked === true).length
          return {
            ...server,
            recent_attacks: logsResponse.pagination?.total || requests.length,
            recent_blocks: blockCount,
            last_attack_time: requests[0]?.timestamp
          }
        } catch {
          return {
            ...server,
            recent_attacks: 0,
            recent_blocks: 0
          }
        }
      })

      const serversWithStats = await Promise.all(statsPromises)
      setServers(serversWithStats)
    } catch (err) {
      setError('Failed to load WAF servers')
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
  }, [refreshInterval])

  if (loading && servers.length === 0) {
    return (
      <div className="bg-card rounded-xl border p-6">
        <div className="flex items-center gap-2 mb-4">
          <Server className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold">WAF Servers</h3>
        </div>
        <div className="flex items-center justify-center h-48">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
        </div>
      </div>
    )
  }

  if (error && servers.length === 0) {
    return (
      <div className="bg-card rounded-xl border p-6">
        <div className="flex items-center gap-2 mb-4">
          <Server className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold">WAF Servers</h3>
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

  const hasServers = servers.length > 0
  const totalAttacks = servers.reduce((acc, s) => acc + s.recent_attacks, 0)
  const activeServers = servers.filter(s => s.enabled).length

  return (
    <>
      <div className="bg-card rounded-xl border p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Server className="w-5 h-5 text-primary" />
            <h3 className="text-lg font-semibold">WAF Servers</h3>
          </div>
          {hasServers && (
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3 text-green-500" />
                {activeServers} active
              </span>
              {totalAttacks > 0 && (
                <span className="flex items-center gap-1 text-orange-500">
                  <Activity className="w-3 h-3" />
                  {totalAttacks} attacks (24h)
                </span>
              )}
            </div>
          )}
        </div>

        {!hasServers ? (
          <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
            <Server className="w-12 h-12 opacity-30 mb-2" />
            <p className="text-sm">No WAF servers configured</p>
            <p className="text-xs mt-1">Configure servers in WAF Explorer</p>
          </div>
        ) : (
          <div className="space-y-2">
            {servers.slice(0, 6).map((server) => (
              <ServerRow
                key={server.id}
                server={server}
                onClick={() => setSelectedServer(server)}
              />
            ))}
            {servers.length > 6 && (
              <p className="text-xs text-center text-muted-foreground pt-2">
                +{servers.length - 6} more servers
              </p>
            )}
          </div>
        )}
      </div>

      {/* Server Detail Modal */}
      {selectedServer && (
        <ServerDetailModal
          server={selectedServer}
          onClose={() => setSelectedServer(null)}
        />
      )}
    </>
  )
}

function ServerRow({ server, onClick }: { server: ServerWithStats; onClick: () => void }) {
  const isActive = server.enabled
  const hasRecentActivity = server.recent_attacks > 0
  const isUnderAttack = server.recent_attacks > 10

  // Get policy info
  const getPolicyInfo = () => {
    if (!server.policy_enabled) return null

    if (server.policy_mode === 'whitecountry') {
      return {
        icon: <ShieldCheck className="w-3.5 h-3.5" />,
        label: 'Authorized',
        countries: server.white_countries || [],
        color: 'text-green-500 bg-green-500/10'
      }
    }
    if (server.policy_mode === 'blockcountry') {
      return {
        icon: <ShieldOff className="w-3.5 h-3.5" />,
        label: 'Hostile',
        countries: server.block_countries || [],
        color: 'text-red-500 bg-red-500/10'
      }
    }
    return null
  }

  const policy = getPolicyInfo()

  return (
    <div
      onClick={onClick}
      className={cn(
        "flex items-center gap-3 p-2.5 rounded-lg transition-colors cursor-pointer",
        isUnderAttack
          ? "bg-red-500/10 border border-red-500/20 hover:bg-red-500/15"
          : hasRecentActivity
            ? "bg-orange-500/5 border border-orange-500/10 hover:bg-orange-500/10"
            : "bg-muted/50 hover:bg-muted border border-transparent"
      )}
    >
      {/* Status indicator */}
      <div className="relative">
        <Server className={cn(
          "w-4 h-4",
          isUnderAttack ? "text-red-500" : isActive ? "text-green-500" : "text-muted-foreground"
        )} />
        {isUnderAttack && (
          <span className="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full animate-pulse" />
        )}
      </div>

      {/* Server info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={cn(
            "font-medium text-sm truncate",
            !isActive && "text-muted-foreground"
          )}>
            {server.display_name || server.hostname}
          </span>

          {/* Policy badge */}
          {policy && (
            <span className={cn(
              "flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium",
              policy.color
            )}>
              {policy.icon}
              {policy.label}
            </span>
          )}
        </div>

        {/* Hostname and country flags */}
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span className="truncate font-mono">{server.hostname}</span>
          {policy && policy.countries.length > 0 && (
            <span className="flex items-center gap-0.5">
              <Globe className="w-3 h-3" />
              {policy.countries.slice(0, 3).map(c => (
                <span key={c} title={c}>{getCountryFlag(c)}</span>
              ))}
              {policy.countries.length > 3 && (
                <span className="text-[10px]">+{policy.countries.length - 3}</span>
              )}
            </span>
          )}
        </div>
      </div>

      {/* Activity stats */}
      <div className="text-right shrink-0">
        {hasRecentActivity ? (
          <div className="flex items-center gap-2">
            {isUnderAttack ? (
              <AlertTriangle className="w-4 h-4 text-red-500 animate-pulse" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-orange-500" />
            )}
            <span className={cn(
              "text-xs font-medium",
              isUnderAttack ? "text-red-500" : "text-orange-500"
            )}>
              {server.recent_attacks}
            </span>
          </div>
        ) : (
          <span className="flex items-center gap-1 text-xs text-green-500">
            <CheckCircle2 className="w-3.5 h-3.5" />
            Quiet
          </span>
        )}
      </div>
    </div>
  )
}

function ServerDetailModal({ server, onClose }: { server: ServerWithStats; onClose: () => void }) {
  const [loading, setLoading] = useState(true)
  const [data, setData] = useState<ServerDetailData | null>(null)

  useEffect(() => {
    async function fetchDetails() {
      try {
        const now = new Date()
        const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)

        // Fetch grouped logs for this server
        const logsResponse = await modsecApi.getGroupedLogs({
          hostname: server.hostname,
          start_time: dayAgo.toISOString(),
          limit: 500,
          offset: 0
        })

        const logs = logsResponse.data || []
        const totalBlocked = logs.filter(l => l.is_blocked).length
        const blockRate = logs.length > 0 ? (totalBlocked / logs.length) * 100 : 0

        // Calculate top attack types
        const attackTypeCounts: Record<string, number> = {}
        logs.forEach(log => {
          log.rules?.forEach(rule => {
            const type = rule.attack_type || 'Unknown'
            attackTypeCounts[type] = (attackTypeCounts[type] || 0) + 1
          })
        })
        const topAttackTypes = Object.entries(attackTypeCounts)
          .map(([type, count]) => ({ type, count }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 10)

        // Calculate top attacker IPs
        const ipCounts: Record<string, { count: number; blocked: number; country?: string }> = {}
        logs.forEach(log => {
          const ip = log.src_ip
          if (!ipCounts[ip]) {
            ipCounts[ip] = { count: 0, blocked: 0, country: log.geo_country }
          }
          ipCounts[ip].count++
          if (log.is_blocked) ipCounts[ip].blocked++
        })
        const topAttackerIPs = Object.entries(ipCounts)
          .map(([ip, data]) => ({ ip, ...data }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 10)

        setData({
          server,
          topAttackTypes,
          topAttackerIPs,
          recentLogs: logs.slice(0, 10),
          totalBlocked,
          blockRate
        })
      } catch (err) {
        console.error('Failed to load server details:', err)
      } finally {
        setLoading(false)
      }
    }

    fetchDetails()
  }, [server])

  const isUnderAttack = server.recent_attacks > 10

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-card rounded-xl border shadow-xl w-full max-w-4xl max-h-[85vh] flex flex-col">
        {/* Header */}
        <div className={cn(
          "flex items-center justify-between px-6 py-4 border-b rounded-t-xl",
          isUnderAttack ? "bg-red-500/10 border-red-500/20" : "border-border"
        )}>
          <div className="flex items-center gap-3">
            <div className="relative">
              <Server className={cn(
                "w-6 h-6",
                isUnderAttack ? "text-red-500" : "text-primary"
              )} />
              {isUnderAttack && (
                <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-red-500 rounded-full animate-pulse" />
              )}
            </div>
            <div>
              <h2 className="text-xl font-semibold flex items-center gap-2">
                {server.display_name || server.hostname}
                {isUnderAttack && (
                  <span className="px-2 py-0.5 bg-red-500/20 text-red-500 text-xs rounded-full animate-pulse">
                    Under Attack
                  </span>
                )}
              </h2>
              <p className="text-sm text-muted-foreground font-mono">{server.hostname}</p>
            </div>
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
          {loading ? (
            <div className="flex items-center justify-center h-64">
              <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
            </div>
          ) : data ? (
            <div className="space-y-6">
              {/* Stats Row */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatBox
                  icon={<Zap className="w-5 h-5 text-orange-500" />}
                  label="Attacks (24h)"
                  value={formatNumber(server.recent_attacks)}
                  color="orange"
                />
                <StatBox
                  icon={<Shield className="w-5 h-5 text-green-500" />}
                  label="Blocked"
                  value={formatNumber(data.totalBlocked)}
                  color="green"
                />
                <StatBox
                  icon={<TrendingUp className="w-5 h-5 text-blue-500" />}
                  label="Block Rate"
                  value={`${data.blockRate.toFixed(1)}%`}
                  color="blue"
                />
                <StatBox
                  icon={<Users className="w-5 h-5 text-purple-500" />}
                  label="Unique IPs"
                  value={formatNumber(data.topAttackerIPs.length)}
                  color="purple"
                />
              </div>

              {/* Two Column Layout */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Top Attack Types */}
                <div className="bg-muted/30 rounded-lg p-4">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <Target className="w-4 h-4 text-red-500" />
                    Top Attack Types
                  </h3>
                  {data.topAttackTypes.length > 0 ? (
                    <div className="space-y-2">
                      {data.topAttackTypes.map((attack, i) => (
                        <div key={attack.type} className="flex items-center gap-2">
                          <span className="w-5 text-xs text-muted-foreground">{i + 1}.</span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between">
                              <span className="text-sm truncate">{attack.type}</span>
                              <span className="text-sm font-medium text-orange-500">{attack.count}</span>
                            </div>
                            <div className="h-1.5 bg-muted rounded-full mt-1">
                              <div
                                className="h-full bg-orange-500/50 rounded-full"
                                style={{ width: `${(attack.count / data.topAttackTypes[0].count) * 100}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground text-center py-4">No attacks detected</p>
                  )}
                </div>

                {/* Top Attacker IPs */}
                <div className="bg-muted/30 rounded-lg p-4">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <Users className="w-4 h-4 text-red-500" />
                    Top Attacker IPs
                  </h3>
                  {data.topAttackerIPs.length > 0 ? (
                    <div className="space-y-2">
                      {data.topAttackerIPs.map((attacker, i) => (
                        <div key={attacker.ip} className="flex items-center gap-2">
                          <span className="w-5 text-xs text-muted-foreground">{i + 1}.</span>
                          <div className="flex-1 flex items-center justify-between min-w-0">
                            <div className="flex items-center gap-2 min-w-0">
                              {attacker.country && (
                                <span className="text-base">{getCountryFlag(attacker.country)}</span>
                              )}
                              <span className="font-mono text-sm truncate">{attacker.ip}</span>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <span className="text-sm">{attacker.count}</span>
                              {attacker.blocked > 0 && (
                                <span className="text-xs px-1.5 py-0.5 bg-green-500/20 text-green-500 rounded">
                                  {attacker.blocked} blocked
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground text-center py-4">No attackers detected</p>
                  )}
                </div>
              </div>

              {/* Recent Activity */}
              <div className="bg-muted/30 rounded-lg p-4">
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-blue-500" />
                  Recent Activity
                </h3>
                {data.recentLogs.length > 0 ? (
                  <div className="space-y-2 max-h-48 overflow-auto">
                    {data.recentLogs.map((log) => (
                      <div
                        key={log.unique_id}
                        className={cn(
                          "flex items-center gap-3 p-2 rounded text-sm",
                          log.is_blocked ? "bg-green-500/10" : "bg-orange-500/10"
                        )}
                      >
                        {log.is_blocked ? (
                          <Shield className="w-4 h-4 text-green-500 shrink-0" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-orange-500 shrink-0" />
                        )}
                        <span className="font-mono text-xs text-muted-foreground shrink-0">
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </span>
                        <span className="font-mono text-xs shrink-0">
                          {log.geo_country && getCountryFlag(log.geo_country)} {log.src_ip}
                        </span>
                        <span className="truncate text-muted-foreground" title={log.uri}>
                          {log.uri}
                        </span>
                        <span className={cn(
                          "ml-auto shrink-0 text-xs px-1.5 py-0.5 rounded",
                          log.is_blocked ? "bg-green-500/20 text-green-500" : "bg-orange-500/20 text-orange-500"
                        )}>
                          {log.is_blocked ? 'Blocked' : 'Detected'}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground text-center py-4">No recent activity</p>
                )}
              </div>
            </div>
          ) : (
            <div className="text-center py-12 text-muted-foreground">
              <AlertTriangle className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>Failed to load server details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function StatBox({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string; color: string }) {
  const colorClasses: Record<string, string> = {
    orange: 'bg-orange-500/10 border-orange-500/20',
    green: 'bg-green-500/10 border-green-500/20',
    blue: 'bg-blue-500/10 border-blue-500/20',
    purple: 'bg-purple-500/10 border-purple-500/20',
    red: 'bg-red-500/10 border-red-500/20',
  }

  return (
    <div className={cn("p-4 rounded-lg border", colorClasses[color] || colorClasses.blue)}>
      <div className="flex items-center gap-2 mb-1">
        {icon}
        <span className="text-xs text-muted-foreground">{label}</span>
      </div>
      <p className="text-2xl font-bold">{value}</p>
    </div>
  )
}
