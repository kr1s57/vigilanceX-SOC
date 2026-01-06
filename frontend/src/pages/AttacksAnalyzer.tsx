import { useState, useEffect, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Swords,
  AlertTriangle,
  Target,
  TrendingUp,
  Users,
  FileWarning,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Search,
  X,
  Shield,
  ShieldOff,
  Clock,
  Ban,
  Loader2,
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts'
import { modsecApi, statsApi, bansApi } from '@/lib/api'
import { StatCard } from '@/components/dashboard/StatCard'
import { IPThreatModal } from '@/components/IPThreatModal'
import { formatNumber, getCountryFlag, cn, formatDateTime } from '@/lib/utils'
import type { TopAttacker, BanStatus } from '@/types'

interface RuleStats {
  rule_id: string
  rule_msg: string
  trigger_count: number
  unique_ips: number
  unique_targets: number
}

interface AttackTypeStats {
  attack_type: string
  count: number
  unique_ips: number
}

// Attack type colors for charts
const attackTypeColors: Record<string, string> = {
  sqli: '#ef4444',
  xss: '#f97316',
  lfi: '#eab308',
  rfi: '#84cc16',
  rce: '#dc2626',
  protocol: '#3b82f6',
  scanner: '#8b5cf6',
  generic: '#64748b',
  'session-fixation': '#ec4899',
  'php-injection': '#f43f5e',
  'java-injection': '#a855f7',
  dos: '#6366f1',
  'request-smuggling': '#14b8a6',
  default: '#6b7280',
}

// Mapping attack types to readable names
const attackTypeNames: Record<string, string> = {
  sqli: 'SQL Injection',
  xss: 'Cross-Site Scripting',
  lfi: 'Local File Inclusion',
  rfi: 'Remote File Inclusion',
  rce: 'Remote Code Execution',
  protocol: 'Protocol Violations',
  scanner: 'Scanner Detection',
  generic: 'Generic Anomaly',
  'session-fixation': 'Session Fixation',
  'php-injection': 'PHP Injection',
  'java-injection': 'Java Injection',
  dos: 'Denial of Service',
  'request-smuggling': 'Request Smuggling',
}

// Attackers Modal Component
function AttackersModal({
  isOpen,
  onClose,
  attackers,
  period,
  onIPLookup,
}: {
  isOpen: boolean
  onClose: () => void
  attackers: TopAttacker[]
  period: string
  onIPLookup: (ip: string) => void
}) {
  const [bans, setBans] = useState<BanStatus[]>([])
  const [loadingBans, setLoadingBans] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    if (isOpen) {
      setLoadingBans(true)
      bansApi.list()
        .then(data => setBans(data))
        .catch(err => console.error('Failed to fetch bans:', err))
        .finally(() => setLoadingBans(false))
    }
  }, [isOpen])

  const bansByIP = useMemo(() => {
    const map = new Map<string, BanStatus>()
    bans.forEach(ban => map.set(ban.ip, ban))
    return map
  }, [bans])

  const filteredAttackers = useMemo(() => {
    if (!searchTerm) return attackers
    const term = searchTerm.toLowerCase()
    return attackers.filter(a =>
      a.ip.toLowerCase().includes(term) ||
      a.country?.toLowerCase().includes(term) ||
      a.categories.some(c => c.toLowerCase().includes(term))
    )
  }, [attackers, searchTerm])

  if (!isOpen) return null

  const getBanStatusBadge = (ip: string) => {
    const ban = bansByIP.get(ip)
    if (!ban) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-1 text-xs rounded-full bg-green-500/10 text-green-500">
          <Shield className="w-3 h-3" />
          Clean
        </span>
      )
    }

    switch (ban.status) {
      case 'permanent':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 text-xs rounded-full bg-red-500/10 text-red-500">
            <Ban className="w-3 h-3" />
            Permanent Ban
          </span>
        )
      case 'active':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 text-xs rounded-full bg-orange-500/10 text-orange-500">
            <ShieldOff className="w-3 h-3" />
            Banned
          </span>
        )
      case 'expired':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 text-xs rounded-full bg-yellow-500/10 text-yellow-500">
            <Clock className="w-3 h-3" />
            Grace Period
          </span>
        )
      default:
        return null
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-card border rounded-xl shadow-2xl w-full max-w-4xl max-h-[85vh] overflow-hidden m-4">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/10 rounded-lg">
              <Users className="w-5 h-5 text-purple-500" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">Unique Attackers</h2>
              <p className="text-sm text-muted-foreground">
                {attackers.length} distinct IPs in the last {period}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-muted rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Search */}
        <div className="p-4 border-b">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search by IP, country, or category..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto max-h-[calc(85vh-180px)]">
          {loadingBans ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-card border-b">
                <tr>
                  <th className="text-left py-3 px-4 font-medium">IP Address</th>
                  <th className="text-left py-3 px-4 font-medium">Country</th>
                  <th className="text-center py-3 px-4 font-medium">Status</th>
                  <th className="text-right py-3 px-4 font-medium">Attacks</th>
                  <th className="text-right py-3 px-4 font-medium">Blocked</th>
                  <th className="text-right py-3 px-4 font-medium">Rules</th>
                  <th className="text-left py-3 px-4 font-medium">Categories</th>
                </tr>
              </thead>
              <tbody>
                {filteredAttackers.map((attacker) => {
                  const ban = bansByIP.get(attacker.ip)
                  const blockRate = attacker.attack_count > 0
                    ? (attacker.blocked_count / attacker.attack_count) * 100
                    : 0

                  return (
                    <tr
                      key={attacker.ip}
                      className="border-b last:border-0 hover:bg-muted/50 transition-colors cursor-pointer"
                      onClick={() => onIPLookup(attacker.ip)}
                    >
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <span className="font-mono">{attacker.ip}</span>
                          {attacker.threat_score && attacker.threat_score > 50 && (
                            <span className="text-xs px-1.5 py-0.5 bg-red-500/20 text-red-500 rounded">
                              Risk
                            </span>
                          )}
                        </div>
                        {ban && (
                          <div className="text-xs text-muted-foreground mt-1">
                            {ban.reason && <span>{ban.reason}</span>}
                            {ban.last_ban && (
                              <span className="ml-2">
                                Last: {formatDateTime(ban.last_ban)}
                              </span>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {attacker.country ? (
                          <div className="flex items-center gap-2">
                            <span className="text-lg">{getCountryFlag(attacker.country)}</span>
                            <span className="text-muted-foreground">{attacker.country}</span>
                          </div>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center">
                        {getBanStatusBadge(attacker.ip)}
                      </td>
                      <td className="py-3 px-4 text-right font-mono">
                        {formatNumber(attacker.attack_count)}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <span className={cn(
                            'font-mono',
                            attacker.blocked_count > 0 ? 'text-red-500' : 'text-green-500'
                          )}>
                            {formatNumber(attacker.blocked_count)}
                          </span>
                          <span className="text-xs text-muted-foreground">
                            ({blockRate.toFixed(0)}%)
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-right font-mono text-muted-foreground">
                        {attacker.unique_rules}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {attacker.categories.slice(0, 3).map((cat, i) => (
                            <span
                              key={i}
                              className="text-xs px-2 py-0.5 bg-muted rounded-full"
                            >
                              {cat}
                            </span>
                          ))}
                          {attacker.categories.length > 3 && (
                            <span className="text-xs text-muted-foreground">
                              +{attacker.categories.length - 3}
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
                {filteredAttackers.length === 0 && (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-muted-foreground">
                      {searchTerm ? 'No matching attackers found' : 'No attacker data available'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>

        {/* Footer with stats */}
        <div className="flex items-center justify-between p-4 border-t bg-muted/30 text-sm">
          <div className="flex items-center gap-4">
            <span className="text-muted-foreground">
              {filteredAttackers.length} of {attackers.length} IPs shown
            </span>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-muted-foreground">
                {bans.filter(b => b.status === 'permanent').length} permanent bans
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-orange-500" />
              <span className="text-muted-foreground">
                {bans.filter(b => b.status === 'active').length} active bans
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export function AttacksAnalyzer() {
  const [searchParams] = useSearchParams()
  const [period, setPeriod] = useState('24h')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [ruleStats, setRuleStats] = useState<RuleStats[]>([])
  const [attackTypeStats, setAttackTypeStats] = useState<AttackTypeStats[]>([])
  const [topAttackers, setTopAttackers] = useState<TopAttacker[]>([])
  const [expandedRules, setExpandedRules] = useState<Set<string>>(new Set())
  const [showAttackersModal, setShowAttackersModal] = useState(false)
  const [selectedIP, setSelectedIP] = useState<string | null>(searchParams.get('src_ip'))
  const [showThreatModal, setShowThreatModal] = useState(!!searchParams.get('src_ip'))

  const handleIPLookup = (ip: string) => {
    setSelectedIP(ip)
    setShowThreatModal(true)
  }

  useEffect(() => {
    async function fetchData() {
      setLoading(true)
      setError(null)
      try {
        const [rules, attacks, attackersData] = await Promise.all([
          modsecApi.getRuleStats(period),
          modsecApi.getAttackTypeStats(period),
          statsApi.topAttackers(period, 100), // Fetch more for the modal
        ])
        setRuleStats(rules)
        setAttackTypeStats(attacks)
        setTopAttackers(attackersData)
      } catch (err) {
        setError('Failed to load attack data')
        console.error(err)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 60000) // Refresh every minute
    return () => clearInterval(interval)
  }, [period])

  // Calculate summary stats
  const summaryStats = useMemo(() => {
    const totalTriggers = ruleStats.reduce((sum, r) => sum + r.trigger_count, 0)
    const uniqueRules = ruleStats.length
    const totalAttackTypes = attackTypeStats.length
    const topAttackType = attackTypeStats.length > 0 ? attackTypeStats[0] : null
    const totalUniqueIPs = new Set(topAttackers.map(a => a.ip)).size

    return {
      totalTriggers,
      uniqueRules,
      totalAttackTypes,
      topAttackType,
      totalUniqueIPs,
    }
  }, [ruleStats, attackTypeStats, topAttackers])

  // Prepare chart data
  const pieChartData = useMemo(() => {
    return attackTypeStats.slice(0, 8).map(item => ({
      name: attackTypeNames[item.attack_type] || item.attack_type,
      value: item.count,
      attackType: item.attack_type,
    }))
  }, [attackTypeStats])

  const barChartData = useMemo(() => {
    return ruleStats.slice(0, 10).map(item => ({
      rule_id: item.rule_id,
      rule_msg: item.rule_msg.length > 30 ? item.rule_msg.slice(0, 30) + '...' : item.rule_msg,
      full_msg: item.rule_msg,
      trigger_count: item.trigger_count,
      unique_ips: item.unique_ips,
    }))
  }, [ruleStats])

  const toggleRuleExpanded = (ruleId: string) => {
    setExpandedRules(prev => {
      const next = new Set(prev)
      if (next.has(ruleId)) {
        next.delete(ruleId)
      } else {
        next.add(ruleId)
      }
      return next
    })
  }

  if (loading && ruleStats.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (error && ruleStats.length === 0) {
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-orange-500/10 rounded-lg">
            <Swords className="w-6 h-6 text-orange-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Attacks Analyzer</h1>
            <p className="text-muted-foreground">ModSecurity CRS attack patterns and rule analysis</p>
          </div>
        </div>
        <div className="flex items-center gap-2 bg-muted rounded-lg p-1">
          {['24h', '7d', '30d'].map((p) => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={cn(
                'px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
                period === p
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Rule Triggers"
          value={formatNumber(summaryStats.totalTriggers)}
          subtitle={`${summaryStats.uniqueRules} unique rules`}
          icon={<FileWarning className="w-5 h-5 text-orange-500" />}
        />
        <StatCard
          title="Attack Categories"
          value={summaryStats.totalAttackTypes.toString()}
          subtitle="Detected types"
          icon={<Target className="w-5 h-5 text-red-500" />}
        />
        <StatCard
          title="Top Attack"
          value={summaryStats.topAttackType
            ? (attackTypeNames[summaryStats.topAttackType.attack_type] || summaryStats.topAttackType.attack_type)
            : 'N/A'}
          subtitle={summaryStats.topAttackType
            ? `${formatNumber(summaryStats.topAttackType.count)} occurrences`
            : 'No data'}
          icon={<TrendingUp className="w-5 h-5 text-yellow-500" />}
          variant={summaryStats.topAttackType ? 'warning' : 'default'}
        />
        {/* Unique Attackers with search button */}
        <div className="rounded-xl border p-6 bg-card transition-all hover:shadow-lg relative group">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <p className="text-sm font-medium text-muted-foreground">Unique Attackers</p>
              <p className="text-3xl font-bold">{formatNumber(summaryStats.totalUniqueIPs)}</p>
              <p className="text-sm text-muted-foreground">Distinct source IPs</p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowAttackersModal(true)}
                className="p-2 bg-muted hover:bg-primary/10 hover:text-primary rounded-lg transition-colors"
                title="View all attackers"
              >
                <Search className="w-5 h-5" />
              </button>
              <div className="p-2 bg-muted rounded-lg">
                <Users className="w-5 h-5 text-purple-500" />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Attack Type Distribution */}
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-4">Attack Type Distribution</h3>
          {pieChartData.length > 0 ? (
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    labelLine={false}
                  >
                    {pieChartData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={attackTypeColors[entry.attackType] || attackTypeColors.default}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '8px',
                    }}
                    formatter={(value: number) => [formatNumber(value), 'Count']}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-[300px] flex items-center justify-center text-muted-foreground">
              No attack data available
            </div>
          )}
        </div>

        {/* Top Triggered Rules Chart */}
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-4">Top Triggered Rules</h3>
          {barChartData.length > 0 ? (
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={barChartData}
                  layout="vertical"
                  margin={{ top: 5, right: 30, left: 80, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis type="number" stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <YAxis
                    type="category"
                    dataKey="rule_id"
                    stroke="hsl(var(--muted-foreground))"
                    fontSize={11}
                    width={75}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '8px',
                    }}
                    formatter={(value: number, name: string) => [
                      formatNumber(value),
                      name === 'trigger_count' ? 'Triggers' : 'Unique IPs'
                    ]}
                    labelFormatter={(label) => {
                      const rule = barChartData.find(r => r.rule_id === label)
                      return rule?.full_msg || label
                    }}
                  />
                  <Legend />
                  <Bar dataKey="trigger_count" name="Triggers" fill="#f97316" radius={[0, 4, 4, 0]} />
                  <Bar dataKey="unique_ips" name="Unique IPs" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-[300px] flex items-center justify-center text-muted-foreground">
              No rule data available
            </div>
          )}
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Detailed Rules List */}
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-4">Rule Details</h3>
          <div className="space-y-2 max-h-[400px] overflow-y-auto">
            {ruleStats.slice(0, 15).map((rule) => (
              <div key={rule.rule_id} className="border rounded-lg overflow-hidden">
                <button
                  onClick={() => toggleRuleExpanded(rule.rule_id)}
                  className="w-full flex items-center gap-3 p-3 hover:bg-muted/50 transition-colors text-left"
                >
                  {expandedRules.has(rule.rule_id) ? (
                    <ChevronDown className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm text-orange-500">{rule.rule_id}</span>
                      <span className="text-xs px-2 py-0.5 bg-muted rounded-full">
                        {formatNumber(rule.trigger_count)} triggers
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground truncate">{rule.rule_msg}</p>
                  </div>
                </button>
                {expandedRules.has(rule.rule_id) && (
                  <div className="px-10 pb-3 space-y-2 border-t bg-muted/30">
                    <div className="pt-3">
                      <p className="text-sm">{rule.rule_msg}</p>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-muted-foreground">
                      <span>{rule.unique_ips} unique IPs</span>
                      <span>{rule.unique_targets} targets</span>
                    </div>
                    <a
                      href={`https://coreruleset.org/docs/rules/${rule.rule_id}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                    >
                      View CRS documentation
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                )}
              </div>
            ))}
            {ruleStats.length === 0 && (
              <p className="text-muted-foreground text-center py-4">No rules triggered</p>
            )}
          </div>
        </div>

        {/* Top Attackers */}
        <div className="bg-card rounded-xl border p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Top Attackers</h3>
            <button
              onClick={() => setShowAttackersModal(true)}
              className="text-sm text-primary hover:underline flex items-center gap-1"
            >
              View all
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>
          <div className="space-y-3 max-h-[400px] overflow-y-auto">
            {topAttackers.slice(0, 10).map((attacker, index) => (
              <div
                key={attacker.ip}
                className="flex items-center gap-4 p-3 rounded-lg bg-muted/50 hover:bg-muted transition-colors cursor-pointer"
                onClick={() => handleIPLookup(attacker.ip)}
              >
                <span className="w-6 h-6 rounded-full bg-muted flex items-center justify-center text-xs font-medium">
                  {index + 1}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm">{attacker.ip}</span>
                    {attacker.country && (
                      <span className="text-lg" title={attacker.country}>
                        {getCountryFlag(attacker.country)}
                      </span>
                    )}
                    {attacker.threat_score && attacker.threat_score > 50 && (
                      <span className="text-xs px-1.5 py-0.5 bg-red-500/20 text-red-500 rounded">
                        High Risk
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span>{formatNumber(attacker.attack_count)} attacks</span>
                    <span>•</span>
                    <span>{attacker.unique_rules} rules</span>
                    {attacker.categories.length > 0 && (
                      <>
                        <span>•</span>
                        <span className="truncate">{attacker.categories.slice(0, 2).join(', ')}</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="text-right">
                  <div className={cn(
                    'text-sm font-medium',
                    attacker.blocked_count > 0 ? 'text-red-500' : 'text-green-500'
                  )}>
                    {formatNumber(attacker.blocked_count)} blocked
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {attacker.attack_count > 0
                      ? ((attacker.blocked_count / attacker.attack_count) * 100).toFixed(0)
                      : 0}% blocked
                  </div>
                </div>
              </div>
            ))}
            {topAttackers.length === 0 && (
              <p className="text-muted-foreground text-center py-4">No attacker data available</p>
            )}
          </div>
        </div>
      </div>

      {/* Attack Types Summary Table */}
      <div className="bg-card rounded-xl border p-6">
        <h3 className="text-lg font-semibold mb-4">Attack Categories Summary</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-3 px-4 font-medium">Attack Type</th>
                <th className="text-right py-3 px-4 font-medium">Count</th>
                <th className="text-right py-3 px-4 font-medium">Unique IPs</th>
                <th className="text-left py-3 px-4 font-medium">Distribution</th>
              </tr>
            </thead>
            <tbody>
              {attackTypeStats.map((attack) => {
                const maxCount = attackTypeStats[0]?.count || 1
                const percentage = (attack.count / maxCount) * 100
                return (
                  <tr key={attack.attack_type} className="border-b last:border-0 hover:bg-muted/50">
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div
                          className="w-3 h-3 rounded-full"
                          style={{
                            backgroundColor: attackTypeColors[attack.attack_type] || attackTypeColors.default
                          }}
                        />
                        <span className="font-medium">
                          {attackTypeNames[attack.attack_type] || attack.attack_type}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-right font-mono">
                      {formatNumber(attack.count)}
                    </td>
                    <td className="py-3 px-4 text-right font-mono text-muted-foreground">
                      {formatNumber(attack.unique_ips)}
                    </td>
                    <td className="py-3 px-4">
                      <div className="w-full max-w-[200px]">
                        <div className="h-2 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all"
                            style={{
                              width: `${percentage}%`,
                              backgroundColor: attackTypeColors[attack.attack_type] || attackTypeColors.default
                            }}
                          />
                        </div>
                      </div>
                    </td>
                  </tr>
                )
              })}
              {attackTypeStats.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-muted-foreground">
                    No attack data available for this period
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Attackers Modal */}
      <AttackersModal
        isOpen={showAttackersModal}
        onClose={() => setShowAttackersModal(false)}
        attackers={topAttackers}
        period={period}
        onIPLookup={handleIPLookup}
      />

      {/* IP Threat Modal */}
      <IPThreatModal
        ip={selectedIP}
        isOpen={showThreatModal}
        onClose={() => {
          setShowThreatModal(false)
          setSelectedIP(null)
        }}
      />
    </div>
  )
}
