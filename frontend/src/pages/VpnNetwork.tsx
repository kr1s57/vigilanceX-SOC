import { useState, useEffect, useMemo } from 'react'
import {
  Network,
  Wifi,
  WifiOff,
  Users,
  Globe,
  Lock,
  AlertTriangle,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Search,
  X,
  Calendar,
} from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { StatCard } from '@/components/dashboard/StatCard'
import { eventsApi, geoApi } from '@/lib/api'
import type { Event, PaginatedResponse } from '@/types'

type Period = '1h' | '24h' | '7d' | '30d'

// Helper to convert period to start_time ISO string
function getStartTimeFromPeriod(period: Period): string {
  const now = new Date()
  switch (period) {
    case '1h':
      return new Date(now.getTime() - 60 * 60 * 1000).toISOString()
    case '24h':
      return new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString()
    case '7d':
      return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString()
    case '30d':
      return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString()
    default:
      return new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString()
  }
}

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

// Modal for detailed events
function EventsDetailModal({
  isOpen,
  onClose,
  title,
  icon: Icon,
  iconColor,
  events,
}: {
  isOpen: boolean
  onClose: () => void
  title: string
  icon: React.ElementType
  iconColor: string
  events: Event[]
}) {
  const [searchTerm, setSearchTerm] = useState('')

  const filteredEvents = useMemo(() => {
    if (!searchTerm) return events
    const term = searchTerm.toLowerCase()
    return events.filter(e =>
      e.src_ip.toLowerCase().includes(term) ||
      e.dst_ip?.toLowerCase().includes(term) ||
      e.rule_name?.toLowerCase().includes(term) ||
      e.action?.toLowerCase().includes(term) ||
      e.category?.toLowerCase().includes(term)
    )
  }, [events, searchTerm])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-card border rounded-xl shadow-2xl w-full max-w-5xl max-h-[85vh] overflow-hidden m-4">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b">
          <div className="flex items-center gap-3">
            <div className={`p-2 ${iconColor} rounded-lg`}>
              <Icon className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">{title}</h2>
              <p className="text-sm text-muted-foreground">
                {events.length} events total
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-muted rounded-lg transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Search */}
        <div className="p-4 border-b">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search by IP, rule, action, category..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto max-h-[calc(85vh-180px)]">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-card border-b">
              <tr>
                <th className="text-left py-3 px-4 font-medium">Time</th>
                <th className="text-left py-3 px-4 font-medium">Type</th>
                <th className="text-left py-3 px-4 font-medium">Source</th>
                <th className="text-left py-3 px-4 font-medium">Destination</th>
                <th className="text-left py-3 px-4 font-medium">Category</th>
                <th className="text-left py-3 px-4 font-medium">Rule</th>
                <th className="text-center py-3 px-4 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((event, idx) => (
                <tr key={idx} className="border-b last:border-0 hover:bg-muted/50 transition-colors">
                  <td className="py-3 px-4 text-muted-foreground whitespace-nowrap">
                    {new Date(event.timestamp).toLocaleString('fr-FR', {
                      day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
                    })}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      event.log_type === 'IPS' ? 'bg-red-500/10 text-red-500' :
                      event.log_type === 'Firewall' ? 'bg-orange-500/10 text-orange-500' :
                      event.log_type === 'VPN' ? 'bg-green-500/10 text-green-500' :
                      'bg-gray-500/10 text-gray-400'
                    }`}>
                      {event.log_type}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-sm">
                    {event.src_ip}
                    {event.src_port > 0 && <span className="text-muted-foreground">:{event.src_port}</span>}
                  </td>
                  <td className="py-3 px-4 font-mono text-sm">
                    {event.dst_ip}
                    {event.dst_port > 0 && <span className="text-muted-foreground">:{event.dst_port}</span>}
                  </td>
                  <td className="py-3 px-4 text-muted-foreground max-w-[150px] truncate" title={event.category}>
                    {event.category || '-'}
                  </td>
                  <td className="py-3 px-4 max-w-[200px] truncate" title={event.rule_name || event.rule_id}>
                    {event.rule_name || event.rule_id || '-'}
                  </td>
                  <td className="py-3 px-4 text-center">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                      event.action === 'allow' ? 'bg-green-500/10 text-green-500' :
                      event.action === 'drop' ? 'bg-red-500/10 text-red-500' :
                      event.action === 'reject' ? 'bg-orange-500/10 text-orange-500' :
                      'bg-gray-500/10 text-gray-400'
                    }`}>
                      {event.action || '-'}
                    </span>
                  </td>
                </tr>
              ))}
              {filteredEvents.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-muted-foreground">
                    {searchTerm ? 'No matching events found' : 'No events available'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div className="p-4 border-t bg-muted/30 text-sm text-muted-foreground">
          Showing {filteredEvents.length} of {events.length} events
        </div>
      </div>
    </div>
  )
}

export function VpnNetwork() {
  const [period, setPeriod] = useState<Period>('24h')
  const [expandedSection, setExpandedSection] = useState<string | null>(null)
  const [vpnFilter, setVpnFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [expandedDays, setExpandedDays] = useState<Set<string>>(new Set())
  const [detailModal, setDetailModal] = useState<{
    type: 'vpn' | null
    title: string
    icon: React.ElementType
    iconColor: string
    events: Event[]
  }>({ type: null, title: '', icon: Lock, iconColor: '', events: [] })

  // Data states - VPN only
  const [vpnEvents, setVpnEvents] = useState<PaginatedResponse<Event> | null>(null)
  const [geoData, setGeoData] = useState<GeoHeatmapEntry[]>([])

  // Fetch VPN data only
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true)
      const startTime = getStartTimeFromPeriod(period)
      try {
        const [vpnRes, geoRes] = await Promise.all([
          eventsApi.list({ log_type: 'VPN', limit: 100, start_time: startTime }),
          geoApi.heatmap(period),
        ])
        setVpnEvents(vpnRes)
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

  // Group VPN sessions by day
  const vpnSessionsByDay = useMemo(() => {
    const grouped: Record<string, VPNSession[]> = {}
    filteredVPNSessions.forEach(session => {
      const date = new Date(session.start_time)
      const dayKey = date.toISOString().split('T')[0] // YYYY-MM-DD
      if (!grouped[dayKey]) {
        grouped[dayKey] = []
      }
      grouped[dayKey].push(session)
    })
    // Sort days descending (most recent first)
    return Object.entries(grouped)
      .sort(([a], [b]) => b.localeCompare(a))
      .map(([date, sessions]) => ({
        date,
        sessions,
        label: new Date(date).toLocaleDateString('fr-FR', {
          weekday: 'long',
          day: 'numeric',
          month: 'long',
          year: 'numeric'
        })
      }))
  }, [filteredVPNSessions])

  // Toggle day expansion
  const toggleDay = (date: string) => {
    setExpandedDays(prev => {
      const next = new Set(prev)
      if (next.has(date)) {
        next.delete(date)
      } else {
        next.add(date)
      }
      return next
    })
  }

  // Stats calculations - VPN only
  const stats = useMemo(() => {
    const vpnCount = vpnEvents?.pagination?.total || 0
    // Live users = unique users with connected status (active sessions)
    const connectedSessions = vpnSessions.filter(s => s.status === 'connected')
    const liveUsers = new Set(connectedSessions.map(s => s.user).filter(Boolean)).size

    return {
      vpnSessions: vpnCount,
      liveUsers,
    }
  }, [vpnEvents, vpnSessions])

  const formatNumber = (n: number) => n.toLocaleString()

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

      {/* Stats Cards - VPN only */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div
          onClick={() => setDetailModal({
            type: 'vpn',
            title: 'VPN Sessions',
            icon: Lock,
            iconColor: 'bg-green-500/10 text-green-500',
            events: vpnEvents?.data || []
          })}
          className="cursor-pointer hover:scale-[1.02] transition-transform"
        >
          <StatCard
            title="VPN Sessions"
            value={formatNumber(stats.vpnSessions)}
            subtitle="Click to view details"
            icon={<Lock className="w-5 h-5 text-green-500" />}
            variant={stats.vpnSessions > 0 ? 'success' : 'default'}
          />
        </div>
        <div
          onClick={() => setDetailModal({
            type: 'vpn',
            title: 'Live Connected Users',
            icon: Users,
            iconColor: 'bg-blue-500/10 text-blue-500',
            events: (vpnEvents?.data || []).filter(e =>
              e.category?.toLowerCase().includes('connection') ||
              e.category?.toLowerCase().includes('success') ||
              e.action === 'allow'
            )
          })}
          className="cursor-pointer hover:scale-[1.02] transition-transform"
        >
          <StatCard
            title="Live Users"
            value={formatNumber(stats.liveUsers)}
            subtitle="Currently connected"
            icon={<Users className="w-5 h-5 text-blue-500" />}
            variant={stats.liveUsers > 0 ? 'success' : 'default'}
          />
        </div>
        <div
          onClick={() => setDetailModal({
            type: 'vpn',
            title: 'Connected Sessions',
            icon: Wifi,
            iconColor: 'bg-cyan-500/10 text-cyan-500',
            events: (vpnEvents?.data || []).filter(e =>
              e.category?.toLowerCase().includes('connection') ||
              e.category?.toLowerCase().includes('success') ||
              e.action === 'allow'
            )
          })}
          className="cursor-pointer hover:scale-[1.02] transition-transform"
        >
          <StatCard
            title="Connected"
            value={formatNumber(vpnSessions.filter(s => s.status === 'connected').length)}
            subtitle="Click to view active sessions"
            icon={<Wifi className="w-5 h-5 text-cyan-500" />}
            variant="success"
          />
        </div>
        <div
          onClick={() => setDetailModal({
            type: 'vpn',
            title: 'Authentication Failures',
            icon: AlertTriangle,
            iconColor: 'bg-red-500/10 text-red-500',
            events: (vpnEvents?.data || []).filter(e =>
              e.category?.toLowerCase().includes('failure') ||
              e.category?.toLowerCase().includes('fail') ||
              e.action === 'drop'
            )
          })}
          className="cursor-pointer hover:scale-[1.02] transition-transform"
        >
          <StatCard
            title="Failed"
            value={formatNumber(vpnSessions.filter(s => s.status === 'failed').length)}
            subtitle="Click to view failures"
            icon={<AlertTriangle className="w-5 h-5 text-red-500" />}
            variant={vpnSessions.filter(s => s.status === 'failed').length > 0 ? 'critical' : 'default'}
          />
        </div>
      </div>

      {/* VPN Geographic Distribution */}
      {geoData && geoData.length > 0 && (
        <div className="bg-card rounded-xl border p-6">
          <h3 className="text-lg font-semibold mb-4">VPN Connections by Country</h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={geoData.slice(0, 8)} layout="vertical">
                <XAxis type="number" />
                <YAxis type="category" dataKey="country" width={50} tick={{ fontSize: 12 }} />
                <Tooltip
                  formatter={(value: number) => [formatNumber(value), 'Connections']}
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '8px',
                  }}
                />
                <Bar dataKey="count" fill="#10b981" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

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
          <div className="border-t">
            {stats.vpnSessions > 0 ? (
              <>
                {/* Search */}
                <div className="p-4 border-b">
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

                {/* Sessions grouped by day */}
                <div className="divide-y max-h-[600px] overflow-y-auto">
                  {vpnSessionsByDay.map(({ date, sessions, label }) => (
                    <div key={date}>
                      {/* Day Header - Clickable */}
                      <button
                        onClick={() => toggleDay(date)}
                        className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <Calendar className="w-4 h-4 text-green-500" />
                          <span className="font-medium capitalize">{label}</span>
                          <span className="text-sm text-muted-foreground">
                            ({sessions.length} sessions)
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          {/* Quick stats for the day */}
                          <span className="text-xs px-2 py-0.5 bg-green-500/10 text-green-500 rounded-full">
                            {sessions.filter(s => s.status === 'connected').length} connected
                          </span>
                          <span className="text-xs px-2 py-0.5 bg-red-500/10 text-red-500 rounded-full">
                            {sessions.filter(s => s.status === 'failed').length} failed
                          </span>
                          {expandedDays.has(date) ? (
                            <ChevronUp className="w-4 h-4 text-muted-foreground" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-muted-foreground" />
                          )}
                        </div>
                      </button>

                      {/* Sessions for this day */}
                      {expandedDays.has(date) && (
                        <div className="bg-muted/30">
                          <table className="w-full text-sm">
                            <thead className="bg-muted/50">
                              <tr className="text-left text-muted-foreground">
                                <th className="py-2 px-4 font-medium">User</th>
                                <th className="py-2 px-4 font-medium">Source IP</th>
                                <th className="py-2 px-4 font-medium">Status</th>
                                <th className="py-2 px-4 font-medium">Category</th>
                                <th className="py-2 px-4 font-medium">Country</th>
                                <th className="py-2 px-4 font-medium">Time</th>
                                <th className="py-2 px-4 font-medium">Message</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-muted">
                              {sessions.map((session, idx) => (
                                <tr key={idx} className="hover:bg-muted/50">
                                  <td className="py-2 px-4">
                                    <div className="flex items-center gap-2">
                                      <Users className="w-4 h-4 text-muted-foreground" />
                                      <span className="font-mono">{session.user}</span>
                                    </div>
                                  </td>
                                  <td className="py-2 px-4 font-mono">{session.src_ip}</td>
                                  <td className="py-2 px-4">{getStatusBadge(session.status)}</td>
                                  <td className="py-2 px-4">
                                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                                      session.category.includes('Failure') ? 'bg-red-500/10 text-red-500' :
                                      session.category.includes('Success') || session.category.includes('Connection') ? 'bg-green-500/10 text-green-500' :
                                      'bg-gray-500/10 text-gray-400'
                                    }`}>
                                      {session.category || '-'}
                                    </span>
                                  </td>
                                  <td className="py-2 px-4">
                                    <span className="inline-flex items-center gap-1">
                                      <Globe className="w-3 h-3 text-muted-foreground" />
                                      {session.country}
                                    </span>
                                  </td>
                                  <td className="py-2 px-4 text-muted-foreground whitespace-nowrap">
                                    {new Date(session.start_time).toLocaleTimeString('fr-FR', {
                                      hour: '2-digit',
                                      minute: '2-digit',
                                      second: '2-digit'
                                    })}
                                  </td>
                                  <td className="py-2 px-4 text-muted-foreground max-w-xs truncate" title={session.message}>
                                    {session.message || '-'}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  ))}
                  {vpnSessionsByDay.length === 0 && vpnFilter && (
                    <div className="text-center py-8 text-muted-foreground">
                      No sessions matching "{vpnFilter}"
                    </div>
                  )}
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


      {/* Events Detail Modal */}
      <EventsDetailModal
        isOpen={detailModal.type !== null}
        onClose={() => setDetailModal({ type: null, title: '', icon: Lock, iconColor: '', events: [] })}
        title={detailModal.title}
        icon={detailModal.icon}
        iconColor={detailModal.iconColor}
        events={detailModal.events}
      />

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
