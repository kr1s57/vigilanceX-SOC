import { useState, useEffect, useMemo } from 'react'
import {
  Network,
  Shield,
  Wifi,
  WifiOff,
  Users,
  Globe,
  Activity,
  Server,
  Lock,
  Unlock,
  AlertTriangle,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Search,
} from 'lucide-react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { StatCard } from '@/components/dashboard/StatCard'
import { eventsApi, statsApi, geoApi } from '@/lib/api'
import type { Event, OverviewResponse, PaginatedResponse } from '@/types'

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899']
const LOG_TYPE_COLORS: Record<string, string> = {
  WAF: '#3b82f6',
  IPS: '#ef4444',
  VPN: '#10b981',
  Firewall: '#f59e0b',
  ATP: '#8b5cf6',
  'Anti-Virus': '#ec4899',
}

type Period = '1h' | '24h' | '7d' | '30d'

interface VPNSession {
  user: string
  src_ip: string
  status: 'connected' | 'disconnected' | 'failed'
  start_time: string
  country: string
  message: string
  category: string
}

interface GeoHeatmapEntry {
  country: string
  count: number
  unique_ips: number
}

export function VpnNetwork() {
  const [period, setPeriod] = useState<Period>('24h')
  const [expandedSection, setExpandedSection] = useState<string | null>(null)
  const [vpnFilter, setVpnFilter] = useState('')
  const [networkFilter, setNetworkFilter] = useState('')
  const [loading, setLoading] = useState(true)

  // Data states
  const [overview, setOverview] = useState<OverviewResponse | null>(null)
  const [vpnEvents, setVpnEvents] = useState<PaginatedResponse<Event> | null>(null)
  const [firewallEvents, setFirewallEvents] = useState<PaginatedResponse<Event> | null>(null)
  const [ipsEvents, setIpsEvents] = useState<PaginatedResponse<Event> | null>(null)
  const [geoData, setGeoData] = useState<GeoHeatmapEntry[]>([])

  // Fetch data
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true)
      try {
        const [overviewRes, vpnRes, firewallRes, ipsRes, geoRes] = await Promise.all([
          statsApi.overview(period),
          eventsApi.list({ log_type: 'VPN', limit: 100 }),
          eventsApi.list({ log_type: 'Firewall', limit: 100 }),
          eventsApi.list({ log_type: 'IPS', limit: 50 }),
          geoApi.heatmap(period),
        ])
        setOverview(overviewRes)
        setVpnEvents(vpnRes)
        setFirewallEvents(firewallRes)
        setIpsEvents(ipsRes)
        setGeoData(geoRes)
      } catch (error) {
        console.error('Failed to fetch data:', error)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 30000)
    return () => clearInterval(interval)
  }, [period])

  // Calculate log type distribution
  const logTypeDistribution = useMemo(() => {
    if (!overview?.by_log_type) return []
    return Object.entries(overview.by_log_type)
      .map(([name, value]) => ({
        name,
        value: value as number,
        color: LOG_TYPE_COLORS[name] || '#6b7280',
      }))
      .filter(item => item.value > 0)
      .sort((a, b) => b.value - a.value)
  }, [overview])

  // Calculate protocol distribution from events
  const protocolDistribution = useMemo(() => {
    const protocols: Record<string, number> = {}
    const allEvents = [
      ...(vpnEvents?.data || []),
      ...(firewallEvents?.data || []),
      ...(ipsEvents?.data || []),
    ]

    allEvents.forEach((event: Event) => {
      const proto = event.protocol || 'Unknown'
      protocols[proto] = (protocols[proto] || 0) + 1
    })

    return Object.entries(protocols)
      .map(([name, value], index) => ({
        name,
        value,
        color: COLORS[index % COLORS.length],
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 7)
  }, [vpnEvents, firewallEvents, ipsEvents])

  // Parse VPN sessions from events
  const vpnSessions = useMemo((): VPNSession[] => {
    if (!vpnEvents?.data?.length) return []

    return vpnEvents.data.map((event: Event) => {
      // Determine status based on category (more reliable than action for auth events)
      let status: 'connected' | 'disconnected' | 'failed' = 'disconnected'
      const categoryLower = event.category?.toLowerCase() || ''
      const actionLower = event.action?.toLowerCase() || ''

      if (categoryLower.includes('failure') || categoryLower.includes('fail') || actionLower === 'drop') {
        status = 'failed'
      } else if (categoryLower.includes('connection') || categoryLower.includes('success') || actionLower === 'allow') {
        status = 'connected'
      } else if (categoryLower.includes('disconnect') || categoryLower.includes('terminated')) {
        status = 'disconnected'
      }

      return {
        user: event.user_name || 'Unknown',
        src_ip: event.src_ip,
        status,
        start_time: event.timestamp,
        country: event.geo_country || 'Unknown',
        message: event.message || event.reason || '',
        category: event.category || '',
      }
    })
  }, [vpnEvents])

  // Filter VPN sessions
  const filteredVPNSessions = useMemo(() => {
    if (!vpnFilter) return vpnSessions
    const lower = vpnFilter.toLowerCase()
    return vpnSessions.filter(s =>
      s.user.toLowerCase().includes(lower) ||
      s.src_ip.includes(lower) ||
      s.country.toLowerCase().includes(lower)
    )
  }, [vpnSessions, vpnFilter])

  // Filter network events (Firewall + IPS)
  const networkEvents = useMemo(() => {
    const events = [
      ...(firewallEvents?.data || []),
      ...(ipsEvents?.data || []),
    ].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())

    if (!networkFilter) return events.slice(0, 50)
    const lower = networkFilter.toLowerCase()
    return events.filter((e: Event) =>
      e.src_ip.includes(lower) ||
      e.dst_ip.includes(lower) ||
      e.rule_name?.toLowerCase().includes(lower) ||
      e.action?.toLowerCase().includes(lower)
    ).slice(0, 50)
  }, [firewallEvents, ipsEvents, networkFilter])

  // Stats calculations
  const stats = useMemo(() => {
    const vpnCount = vpnEvents?.pagination?.total || 0
    const firewallCount = firewallEvents?.pagination?.total || 0
    const ipsCount = ipsEvents?.pagination?.total || 0
    const uniqueVPNUsers = new Set(vpnEvents?.data?.map((e: Event) => e.user_name).filter(Boolean)).size
    const blockedNetwork = [...(firewallEvents?.data || []), ...(ipsEvents?.data || [])]
      .filter((e: Event) => e.action === 'drop' || e.action === 'reject').length

    return {
      vpnSessions: vpnCount,
      firewallEvents: firewallCount,
      ipsEvents: ipsCount,
      uniqueVPNUsers,
      blockedNetwork,
      totalNetworkEvents: firewallCount + ipsCount,
    }
  }, [vpnEvents, firewallEvents, ipsEvents])

  const formatNumber = (n: number) => n.toLocaleString()

  const formatTime = (ts: string) => {
    const date = new Date(ts)
    return date.toLocaleString('fr-FR', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      connected: 'bg-green-500/10 text-green-500',
      disconnected: 'bg-gray-500/10 text-gray-400',
      failed: 'bg-red-500/10 text-red-500',
    }
    const icons: Record<string, React.ReactNode> = {
      connected: <Wifi className="w-3 h-3" />,
      disconnected: <WifiOff className="w-3 h-3" />,
      failed: <AlertTriangle className="w-3 h-3" />,
    }
    return (
      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${styles[status] || styles.disconnected}`}>
        {icons[status]}
        {status}
      </span>
    )
  }

  const getActionBadge = (action: string) => {
    const styles: Record<string, string> = {
      allow: 'bg-green-500/10 text-green-500',
      drop: 'bg-red-500/10 text-red-500',
      reject: 'bg-orange-500/10 text-orange-500',
    }
    return (
      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${styles[action] || 'bg-gray-500/10 text-gray-400'}`}>
        {action}
      </span>
    )
  }

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/10 rounded-lg">
            <Network className="w-6 h-6 text-cyan-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">VPN & Network</h1>
            <p className="text-muted-foreground">VPN sessions and network monitoring</p>
          </div>
        </div>

        {/* Period selector */}
        <div className="flex items-center gap-2">
          {(['1h', '24h', '7d', '30d'] as Period[]).map((p) => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`px-3 py-1.5 text-sm font-medium rounded-lg transition-colors ${
                period === p
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-muted hover:bg-muted/80'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="VPN Sessions"
          value={formatNumber(stats.vpnSessions)}
          subtitle="Total connections"
          icon={<Lock className="w-5 h-5 text-green-500" />}
          variant={stats.vpnSessions > 0 ? 'success' : 'default'}
        />
        <StatCard
          title="VPN Users"
          value={formatNumber(stats.uniqueVPNUsers)}
          subtitle="Unique users"
          icon={<Users className="w-5 h-5 text-blue-500" />}
        />
        <StatCard
          title="Firewall Events"
          value={formatNumber(stats.firewallEvents)}
          subtitle="Rule matches"
          icon={<Shield className="w-5 h-5 text-orange-500" />}
        />
        <StatCard
          title="IPS Events"
          value={formatNumber(stats.ipsEvents)}
          subtitle="Intrusion prevention"
          icon={<Activity className="w-5 h-5 text-red-500" />}
          variant={stats.ipsEvents > 0 ? 'warning' : 'default'}
        />
        <StatCard
          title="Blocked"
          value={formatNumber(stats.blockedNetwork)}
          subtitle="Network blocks"
          icon={<Unlock className="w-5 h-5 text-purple-500" />}
          variant={stats.blockedNetwork > 0 ? 'critical' : 'default'}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Log Type Distribution */}
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-4">Event Distribution by Type</h3>
          {logTypeDistribution.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={logTypeDistribution}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {logTypeDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    formatter={(value: number) => [formatNumber(value), 'Events']}
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '8px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-muted-foreground">
              No event data available
            </div>
          )}
        </div>

        {/* Geographic Distribution */}
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-4">Traffic by Country</h3>
          {geoData && geoData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={geoData.slice(0, 8)} layout="vertical">
                  <XAxis type="number" />
                  <YAxis type="category" dataKey="country" width={50} tick={{ fontSize: 12 }} />
                  <Tooltip
                    formatter={(value: number) => [formatNumber(value), 'Events']}
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-muted-foreground">
              No geographic data available
            </div>
          )}
        </div>
      </div>

      {/* VPN Sessions Section */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <button
          onClick={() => toggleSection('vpn')}
          className="w-full flex items-center justify-between p-4 hover:bg-muted/50 transition-colors"
        >
          <div className="flex items-center gap-3">
            <Lock className="w-5 h-5 text-green-500" />
            <span className="font-semibold">VPN Sessions</span>
            <span className="text-sm text-muted-foreground">
              ({stats.vpnSessions} sessions)
            </span>
          </div>
          {expandedSection === 'vpn' ? (
            <ChevronUp className="w-5 h-5" />
          ) : (
            <ChevronDown className="w-5 h-5" />
          )}
        </button>

        {expandedSection === 'vpn' && (
          <div className="border-t p-4">
            {stats.vpnSessions > 0 ? (
              <>
                {/* Search */}
                <div className="mb-4">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <input
                      type="text"
                      placeholder="Search by user, IP, or country..."
                      value={vpnFilter}
                      onChange={(e) => setVpnFilter(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 bg-muted rounded-lg border-0 focus:ring-2 focus:ring-primary"
                    />
                  </div>
                </div>

                {/* Sessions Table */}
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="text-left text-sm text-muted-foreground border-b">
                        <th className="pb-2 font-medium">User</th>
                        <th className="pb-2 font-medium">Source IP</th>
                        <th className="pb-2 font-medium">Status</th>
                        <th className="pb-2 font-medium">Category</th>
                        <th className="pb-2 font-medium">Country</th>
                        <th className="pb-2 font-medium">Time</th>
                        <th className="pb-2 font-medium">Message</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y">
                      {filteredVPNSessions.slice(0, 20).map((session, idx) => (
                        <tr key={idx} className="hover:bg-muted/50">
                          <td className="py-3">
                            <div className="flex items-center gap-2">
                              <Users className="w-4 h-4 text-muted-foreground" />
                              <span className="font-mono text-sm">{session.user}</span>
                            </div>
                          </td>
                          <td className="py-3 font-mono text-sm">{session.src_ip}</td>
                          <td className="py-3">{getStatusBadge(session.status)}</td>
                          <td className="py-3">
                            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                              session.category.includes('Failure') ? 'bg-red-500/10 text-red-500' :
                              session.category.includes('Success') || session.category.includes('Connection') ? 'bg-green-500/10 text-green-500' :
                              'bg-gray-500/10 text-gray-400'
                            }`}>
                              {session.category || '-'}
                            </span>
                          </td>
                          <td className="py-3">
                            <span className="inline-flex items-center gap-1">
                              <Globe className="w-3 h-3 text-muted-foreground" />
                              {session.country}
                            </span>
                          </td>
                          <td className="py-3 text-sm text-muted-foreground whitespace-nowrap">
                            {formatTime(session.start_time)}
                          </td>
                          <td className="py-3 text-sm text-muted-foreground max-w-xs truncate" title={session.message}>
                            {session.message || '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              <div className="text-center py-12">
                <WifiOff className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                <h4 className="text-lg font-medium mb-2">No VPN Sessions</h4>
                <p className="text-muted-foreground max-w-md mx-auto">
                  VPN logging is not configured or no VPN connections have been recorded.
                  Configure Sophos XGS to forward VPN logs to see session data.
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Network Events Section */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <button
          onClick={() => toggleSection('network')}
          className="w-full flex items-center justify-between p-4 hover:bg-muted/50 transition-colors"
        >
          <div className="flex items-center gap-3">
            <Server className="w-5 h-5 text-orange-500" />
            <span className="font-semibold">Network Events</span>
            <span className="text-sm text-muted-foreground">
              (Firewall + IPS: {stats.totalNetworkEvents} events)
            </span>
          </div>
          {expandedSection === 'network' ? (
            <ChevronUp className="w-5 h-5" />
          ) : (
            <ChevronDown className="w-5 h-5" />
          )}
        </button>

        {expandedSection === 'network' && (
          <div className="border-t p-4">
            {stats.totalNetworkEvents > 0 ? (
              <>
                {/* Search */}
                <div className="mb-4">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <input
                      type="text"
                      placeholder="Search by IP, rule, or action..."
                      value={networkFilter}
                      onChange={(e) => setNetworkFilter(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 bg-muted rounded-lg border-0 focus:ring-2 focus:ring-primary"
                    />
                  </div>
                </div>

                {/* Events Table */}
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="text-left text-sm text-muted-foreground border-b">
                        <th className="pb-2 font-medium">Time</th>
                        <th className="pb-2 font-medium">Type</th>
                        <th className="pb-2 font-medium">Source</th>
                        <th className="pb-2 font-medium">Destination</th>
                        <th className="pb-2 font-medium">Rule</th>
                        <th className="pb-2 font-medium">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y">
                      {networkEvents.map((event, idx) => (
                        <tr key={idx} className="hover:bg-muted/50">
                          <td className="py-3 text-sm text-muted-foreground whitespace-nowrap">
                            {formatTime(event.timestamp)}
                          </td>
                          <td className="py-3">
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                              event.log_type === 'IPS'
                                ? 'bg-red-500/10 text-red-500'
                                : 'bg-orange-500/10 text-orange-500'
                            }`}>
                              {event.log_type}
                            </span>
                          </td>
                          <td className="py-3">
                            <div className="font-mono text-sm">
                              {event.src_ip}
                              {event.src_port > 0 && <span className="text-muted-foreground">:{event.src_port}</span>}
                            </div>
                          </td>
                          <td className="py-3">
                            <div className="font-mono text-sm">
                              {event.dst_ip}
                              {event.dst_port > 0 && <span className="text-muted-foreground">:{event.dst_port}</span>}
                            </div>
                          </td>
                          <td className="py-3 text-sm max-w-xs truncate" title={event.rule_name}>
                            {event.rule_name || event.rule_id || '-'}
                          </td>
                          <td className="py-3">
                            {getActionBadge(event.action)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              <div className="text-center py-12">
                <Shield className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                <h4 className="text-lg font-medium mb-2">No Network Events</h4>
                <p className="text-muted-foreground max-w-md mx-auto">
                  No Firewall or IPS events have been recorded.
                  Configure Sophos XGS to forward network logs to see traffic data.
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Protocol Distribution (if we have protocol data) */}
      {protocolDistribution.length > 0 && (
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-4">Protocol Distribution</h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={protocolDistribution}>
                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                <YAxis />
                <Tooltip
                  formatter={(value: number) => [formatNumber(value), 'Events']}
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '8px',
                  }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {protocolDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Quick Actions / Info */}
      <div className="bg-card rounded-xl border p-6">
        <h3 className="text-lg font-semibold mb-4">Network Security Overview</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="space-y-2">
            <h4 className="font-medium flex items-center gap-2">
              <Lock className="w-4 h-4 text-green-500" />
              VPN Security
            </h4>
            <p className="text-sm text-muted-foreground">
              {stats.vpnSessions > 0
                ? `${stats.uniqueVPNUsers} unique users connected via VPN`
                : 'No active VPN sessions monitored'}
            </p>
          </div>
          <div className="space-y-2">
            <h4 className="font-medium flex items-center gap-2">
              <Shield className="w-4 h-4 text-orange-500" />
              Firewall Protection
            </h4>
            <p className="text-sm text-muted-foreground">
              {stats.firewallEvents > 0
                ? `${formatNumber(stats.firewallEvents)} firewall rule matches`
                : 'No firewall events recorded'}
            </p>
          </div>
          <div className="space-y-2">
            <h4 className="font-medium flex items-center gap-2">
              <Activity className="w-4 h-4 text-red-500" />
              Intrusion Prevention
            </h4>
            <p className="text-sm text-muted-foreground">
              {stats.ipsEvents > 0
                ? `${formatNumber(stats.ipsEvents)} IPS alerts detected`
                : 'No IPS events recorded'}
            </p>
          </div>
        </div>
      </div>

      {/* Loading overlay */}
      {loading && (
        <div className="fixed inset-0 bg-background/50 flex items-center justify-center z-50">
          <div className="flex items-center gap-2 bg-card px-4 py-2 rounded-lg shadow-lg">
            <RefreshCw className="w-4 h-4 animate-spin" />
            <span>Loading...</span>
          </div>
        </div>
      )}
    </div>
  )
}
