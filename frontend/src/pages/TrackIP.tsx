import { useState, useMemo } from 'react'
import {
  Search,
  RefreshCw,
  Globe,
  Clock,
  Activity,
  AlertTriangle,
  Shield,
  ShieldAlert,
  Lock,
  Bug,
  HeartPulse,
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  X,
  MapPin,
  Building,
  Hash,
} from 'lucide-react'
import { trackIPApi } from '@/lib/api'
import type {
  TrackIPResponse,
  TrackIPWAFEvent,
  TrackIPVPNEvent,
  TrackIPATPEvent,
  TrackIPAntivirusEvent,
  TrackIPHeartbeatEvent,
} from '@/types'

type Period = '1h' | '24h' | '7d' | '30d' | 'custom'

// Country code to flag emoji
function getFlagEmoji(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return ''
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map((char) => 127397 + char.charCodeAt(0))
  return String.fromCodePoint(...codePoints)
}

// Format bytes to human readable
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

// Format duration
function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  const hours = Math.floor(seconds / 3600)
  const mins = Math.floor((seconds % 3600) / 60)
  return `${hours}h ${mins}m`
}

// Severity badge component
function SeverityBadge({ severity }: { severity: string }) {
  const colorClass = {
    critical: 'bg-red-500/10 text-red-500',
    high: 'bg-orange-500/10 text-orange-500',
    medium: 'bg-yellow-500/10 text-yellow-500',
    low: 'bg-blue-500/10 text-blue-500',
    info: 'bg-gray-500/10 text-gray-400',
  }[severity.toLowerCase()] || 'bg-gray-500/10 text-gray-400'

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${colorClass}`}>
      {severity}
    </span>
  )
}

// Action badge component
function ActionBadge({ action }: { action: string }) {
  const isBlock = action?.toLowerCase().includes('block') || action?.toLowerCase().includes('drop')
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
      isBlock ? 'bg-red-500/10 text-red-500' : 'bg-green-500/10 text-green-500'
    }`}>
      {action || 'N/A'}
    </span>
  )
}

// Items per page for pagination
const PAGE_SIZE = 25

// Category section component with pagination
function CategorySection<T>({
  name,
  icon: Icon,
  iconColor,
  count,
  events,
  renderTable,
}: {
  name: string
  icon: React.ElementType
  iconColor: string
  count: number
  events: T[]
  renderTable: (paginatedEvents: T[]) => React.ReactNode
}) {
  const [isOpen, setIsOpen] = useState(count > 0)
  const [currentPage, setCurrentPage] = useState(1)

  const totalPages = Math.ceil(events.length / PAGE_SIZE)
  const startIndex = (currentPage - 1) * PAGE_SIZE
  const endIndex = startIndex + PAGE_SIZE
  const paginatedEvents = events.slice(startIndex, endIndex)

  const goToPage = (page: number) => {
    if (page >= 1 && page <= totalPages) {
      setCurrentPage(page)
    }
  }

  return (
    <div className="bg-card rounded-xl border overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`w-full flex items-center justify-between p-4 transition-colors ${
          count > 0 ? 'hover:bg-muted/50' : 'opacity-50 cursor-default'
        }`}
        disabled={count === 0}
      >
        <div className="flex items-center gap-3">
          <div className={`p-2 ${iconColor} rounded-lg`}>
            <Icon className="w-5 h-5" />
          </div>
          <div className="text-left">
            <h3 className="font-semibold">{name}</h3>
            <p className="text-sm text-muted-foreground">
              {count === 0 ? 'No events found' : `${count.toLocaleString()} event${count !== 1 ? 's' : ''}`}
            </p>
          </div>
        </div>
        {count > 0 && (
          isOpen ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />
        )}
      </button>
      {isOpen && count > 0 && (
        <div className="border-t">
          <div className="overflow-x-auto">
            {renderTable(paginatedEvents)}
          </div>
          {/* Pagination controls */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between p-3 border-t bg-muted/30">
              <div className="text-sm text-muted-foreground">
                Showing {startIndex + 1}-{Math.min(endIndex, events.length)} of {events.length}
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => goToPage(currentPage - 1)}
                  disabled={currentPage === 1}
                  className="p-1.5 rounded hover:bg-muted disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                {/* Page numbers */}
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  let pageNum: number
                  if (totalPages <= 5) {
                    pageNum = i + 1
                  } else if (currentPage <= 3) {
                    pageNum = i + 1
                  } else if (currentPage >= totalPages - 2) {
                    pageNum = totalPages - 4 + i
                  } else {
                    pageNum = currentPage - 2 + i
                  }
                  return (
                    <button
                      key={pageNum}
                      onClick={() => goToPage(pageNum)}
                      className={`w-8 h-8 rounded text-sm font-medium transition-colors ${
                        currentPage === pageNum
                          ? 'bg-primary text-primary-foreground'
                          : 'hover:bg-muted'
                      }`}
                    >
                      {pageNum}
                    </button>
                  )
                })}
                <button
                  onClick={() => goToPage(currentPage + 1)}
                  disabled={currentPage === totalPages}
                  className="p-1.5 rounded hover:bg-muted disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// Modal for showing full list of items
function ListModal({
  isOpen,
  onClose,
  title,
  items,
}: {
  isOpen: boolean
  onClose: () => void
  title: string
  items: string[]
}) {
  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-card border rounded-xl shadow-2xl w-full max-w-md max-h-[70vh] overflow-hidden m-4">
        <div className="flex items-center justify-between p-4 border-b">
          <h3 className="font-semibold">{title}</h3>
          <button onClick={onClose} className="p-1 hover:bg-muted rounded transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4 overflow-y-auto max-h-[calc(70vh-60px)]">
          <div className="flex flex-wrap gap-2">
            {items.map((item, i) => (
              <span key={i} className="px-3 py-1 bg-muted rounded text-sm font-mono">
                {item}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export function TrackIP() {
  const [query, setQuery] = useState('')
  const [period, setPeriod] = useState<Period>('7d')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [listModal, setListModal] = useState<{ title: string; items: string[] } | null>(null)
  const [result, setResult] = useState<TrackIPResponse | null>(null)

  const handleSearch = async () => {
    if (!query.trim()) {
      setError('Please enter an IP address or hostname')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await trackIPApi.search({
        query: query.trim(),
        period: period === 'custom' ? undefined : period,
        limit: 500, // Get all events for client-side pagination
      })
      setResult(response)
    } catch (err: unknown) {
      const apiError = err as { response?: { data?: { error?: string } } }
      setError(apiError.response?.data?.error || 'Search failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch()
    }
  }

  // Calculate total events across categories
  const totalEvents = useMemo(() => {
    if (!result?.categories) return 0
    return Object.values(result.categories).reduce((sum, cat) => sum + (cat?.count || 0), 0)
  }, [result])

  // Calculate categories with data
  const categoriesWithData = useMemo(() => {
    if (!result?.categories) return 0
    return Object.values(result.categories).filter((cat) => cat?.count > 0).length
  }, [result])

  return (
    <div className="p-6 space-y-6 max-w-full overflow-x-hidden">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <Search className="w-7 h-7 text-blue-500" />
            Track IP / Hostname
          </h1>
          <p className="text-muted-foreground mt-1">
            Search for IP or hostname activity across all log sources
          </p>
        </div>
      </div>

      {/* Search Form */}
      <div className="bg-card rounded-xl border p-4">
        <div className="flex flex-col md:flex-row gap-4">
          {/* Search Input */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyPress}
              placeholder="Enter IP address (e.g., 192.168.1.1) or hostname (e.g., www.example.com)"
              className="w-full pl-11 pr-4 py-3 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>

          {/* Period Selector */}
          <div className="flex items-center gap-2">
            {(['1h', '24h', '7d', '30d'] as Period[]).map((p) => (
              <button
                key={p}
                onClick={() => setPeriod(p)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  period === p
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-muted hover:bg-muted/80 text-muted-foreground'
                }`}
              >
                {p}
              </button>
            ))}
          </div>

          {/* Search Button */}
          <button
            onClick={handleSearch}
            disabled={loading || !query.trim()}
            className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Search className="w-4 h-4" />
            )}
            Search
          </button>
        </div>

        {/* Error Message */}
        {error && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center gap-2 text-red-500">
            <AlertTriangle className="w-4 h-4" />
            <span className="text-sm">{error}</span>
            <button onClick={() => setError(null)} className="ml-auto p-1 hover:bg-red-500/10 rounded">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Query Info */}
            <div className="bg-card rounded-xl border p-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 bg-blue-500/10 text-blue-500 rounded-lg">
                  <Search className="w-5 h-5" />
                </div>
                <span className="text-sm text-muted-foreground">Query</span>
              </div>
              <div className="font-mono text-lg font-semibold truncate" title={result.query}>
                {result.query}
              </div>
              <div className="flex items-center gap-2 mt-2 text-sm text-muted-foreground">
                <span className="px-2 py-0.5 bg-muted rounded text-xs uppercase">
                  {result.query_type}
                </span>
                {result.geo_info && (
                  <>
                    <span>{getFlagEmoji(result.geo_info.country_code)}</span>
                    <span>{result.geo_info.country_name}</span>
                  </>
                )}
              </div>
            </div>

            {/* Total Events */}
            <div className="bg-card rounded-xl border p-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 bg-purple-500/10 text-purple-500 rounded-lg">
                  <Activity className="w-5 h-5" />
                </div>
                <span className="text-sm text-muted-foreground">Total Events</span>
              </div>
              <div className="text-3xl font-bold">{totalEvents.toLocaleString()}</div>
              <div className="text-sm text-muted-foreground mt-1">
                across {categoriesWithData} categor{categoriesWithData !== 1 ? 'ies' : 'y'}
              </div>
            </div>

            {/* Time Range */}
            <div className="bg-card rounded-xl border p-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 bg-emerald-500/10 text-emerald-500 rounded-lg">
                  <Clock className="w-5 h-5" />
                </div>
                <span className="text-sm text-muted-foreground">Time Range</span>
              </div>
              <div className="text-sm space-y-1">
                <div>
                  <span className="text-muted-foreground">From: </span>
                  {new Date(result.time_range.start).toLocaleString()}
                </div>
                <div>
                  <span className="text-muted-foreground">To: </span>
                  {new Date(result.time_range.end).toLocaleString()}
                </div>
              </div>
            </div>

            {/* Severity Breakdown */}
            <div className="bg-card rounded-xl border p-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 bg-red-500/10 text-red-500 rounded-lg">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <span className="text-sm text-muted-foreground">Severity</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {Object.entries(result.summary.severity_breakdown || {}).map(([sev, count]) => (
                  <div key={sev} className="flex items-center gap-1">
                    <SeverityBadge severity={sev} />
                    <span className="text-xs font-medium">{count}</span>
                  </div>
                ))}
                {Object.keys(result.summary.severity_breakdown || {}).length === 0 && (
                  <span className="text-sm text-muted-foreground">No severity data</span>
                )}
              </div>
            </div>
          </div>

          {/* GeoIP Info */}
          {result.geo_info && (
            <div className="bg-card rounded-xl border p-4">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Globe className="w-5 h-5 text-cyan-500" />
                GeoIP Information
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="flex items-center gap-2">
                  <MapPin className="w-4 h-4 text-muted-foreground" />
                  <div>
                    <div className="text-xs text-muted-foreground">Location</div>
                    <div className="font-medium">
                      {getFlagEmoji(result.geo_info.country_code)} {result.geo_info.country_name}
                      {result.geo_info.city && `, ${result.geo_info.city}`}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Hash className="w-4 h-4 text-muted-foreground" />
                  <div>
                    <div className="text-xs text-muted-foreground">ASN</div>
                    <div className="font-medium">AS{result.geo_info.asn}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2 col-span-2">
                  <Building className="w-4 h-4 text-muted-foreground" />
                  <div>
                    <div className="text-xs text-muted-foreground">Organization</div>
                    <div className="font-medium truncate">{result.geo_info.org || 'Unknown'}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Additional Summary Info */}
          {(result.summary.unique_hostnames?.length > 0 ||
            result.summary.unique_dst_ips?.length > 0 ||
            result.summary.top_ports?.length > 0) && (
            <div className="bg-card rounded-xl border p-4">
              <h3 className="font-semibold mb-3">Additional Context</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {result.summary.unique_hostnames?.length > 0 && (
                  <div>
                    <div className="text-xs text-muted-foreground mb-2">Unique Hostnames ({result.summary.unique_hostnames.length})</div>
                    <div className="flex flex-wrap gap-1 items-center">
                      {result.summary.unique_hostnames.slice(0, 5).map((hostname, i) => (
                        <span key={i} className="px-2 py-0.5 bg-muted rounded text-xs font-mono">
                          {hostname}
                        </span>
                      ))}
                      {result.summary.unique_hostnames.length > 5 && (
                        <button
                          onClick={() => setListModal({
                            title: `Unique Hostnames (${result.summary.unique_hostnames.length})`,
                            items: result.summary.unique_hostnames
                          })}
                          className="px-2 py-0.5 bg-primary/10 text-primary rounded text-xs font-medium hover:bg-primary/20 transition-colors"
                        >
                          +{result.summary.unique_hostnames.length - 5} more
                        </button>
                      )}
                    </div>
                  </div>
                )}
                {result.summary.unique_dst_ips?.length > 0 && (
                  <div>
                    <div className="text-xs text-muted-foreground mb-2">Unique Destination IPs ({result.summary.unique_dst_ips.length})</div>
                    <div className="flex flex-wrap gap-1 items-center">
                      {result.summary.unique_dst_ips.slice(0, 5).map((ip, i) => (
                        <span key={i} className="px-2 py-0.5 bg-muted rounded text-xs font-mono">
                          {ip}
                        </span>
                      ))}
                      {result.summary.unique_dst_ips.length > 5 && (
                        <button
                          onClick={() => setListModal({
                            title: `Unique Destination IPs (${result.summary.unique_dst_ips.length})`,
                            items: result.summary.unique_dst_ips
                          })}
                          className="px-2 py-0.5 bg-primary/10 text-primary rounded text-xs font-medium hover:bg-primary/20 transition-colors"
                        >
                          +{result.summary.unique_dst_ips.length - 5} more
                        </button>
                      )}
                    </div>
                  </div>
                )}
                {result.summary.top_ports?.length > 0 && (
                  <div>
                    <div className="text-xs text-muted-foreground mb-2">Top Ports</div>
                    <div className="flex flex-wrap gap-1">
                      {result.summary.top_ports.slice(0, 8).map((port, i) => (
                        <span key={i} className="px-2 py-0.5 bg-muted rounded text-xs font-mono">
                          {port}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Category Sections */}
          <div className="space-y-4">
            {/* Firewall Events (Traffic logs) */}
            <CategorySection<TrackIPWAFEvent>
              name="Firewall Events"
              icon={Shield}
              iconColor="bg-emerald-500/10 text-emerald-500"
              count={result.categories?.events?.count || 0}
              events={result.categories?.events?.events as TrackIPWAFEvent[] || []}
              renderTable={(paginatedEvents) => (
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="text-left py-2 px-3 font-medium">Time</th>
                      <th className="text-left py-2 px-3 font-medium">Type</th>
                      <th className="text-left py-2 px-3 font-medium">Category</th>
                      <th className="text-left py-2 px-3 font-medium">Source</th>
                      <th className="text-left py-2 px-3 font-medium">Destination</th>
                      <th className="text-left py-2 px-3 font-medium">Rule</th>
                      <th className="text-center py-2 px-3 font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedEvents.map((event, idx) => (
                      <tr key={idx} className="border-t hover:bg-muted/30 transition-colors">
                        <td className="py-2 px-3 whitespace-nowrap text-muted-foreground">
                          {new Date(event.timestamp).toLocaleString('fr-FR', {
                            day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
                          })}
                        </td>
                        <td className="py-2 px-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                            event.log_type === 'Firewall' ? 'bg-purple-500/10 text-purple-500' :
                            event.log_type === 'IPS' ? 'bg-red-500/10 text-red-500' :
                            event.log_type === 'WAF' ? 'bg-emerald-500/10 text-emerald-500' :
                            event.log_type === 'VPN' ? 'bg-cyan-500/10 text-cyan-500' :
                            'bg-gray-500/10 text-gray-400'
                          }`}>
                            {event.log_type || 'Unknown'}
                          </span>
                        </td>
                        <td className="py-2 px-3">{event.category || '-'}</td>
                        <td className="py-2 px-3 font-mono text-xs">{event.src_ip}:{event.src_port}</td>
                        <td className="py-2 px-3 font-mono text-xs">{event.dst_ip}:{event.dst_port}</td>
                        <td className="py-2 px-3 truncate max-w-[200px]" title={event.rule_name}>
                          {event.rule_name || event.rule_id || '-'}
                        </td>
                        <td className="py-2 px-3 text-center"><ActionBadge action={event.action} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            />

            {/* WAF Events (Sophos WAF) */}
            <CategorySection<TrackIPWAFEvent>
              name="WAF Events"
              icon={ShieldAlert}
              iconColor="bg-orange-500/10 text-orange-500"
              count={result.categories?.waf?.count || 0}
              events={result.categories?.waf?.events as TrackIPWAFEvent[] || []}
              renderTable={(paginatedEvents) => (
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="text-left py-2 px-3 font-medium">Time</th>
                      <th className="text-left py-2 px-3 font-medium">Category</th>
                      <th className="text-left py-2 px-3 font-medium">Source</th>
                      <th className="text-left py-2 px-3 font-medium">Target</th>
                      <th className="text-left py-2 px-3 font-medium">Host</th>
                      <th className="text-left py-2 px-3 font-medium">URL</th>
                      <th className="text-center py-2 px-3 font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedEvents.map((event, idx) => (
                      <tr key={idx} className="border-t hover:bg-muted/30 transition-colors">
                        <td className="py-2 px-3 whitespace-nowrap text-muted-foreground">
                          {new Date(event.timestamp).toLocaleString('fr-FR', {
                            day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
                          })}
                        </td>
                        <td className="py-2 px-3">
                          <span className="px-2 py-0.5 bg-orange-500/10 text-orange-500 rounded text-xs">
                            {event.category || 'WAF'}
                          </span>
                        </td>
                        <td className="py-2 px-3 font-mono text-xs">{event.src_ip}:{event.src_port}</td>
                        <td className="py-2 px-3 font-mono text-xs">{event.dst_ip}:{event.dst_port}</td>
                        <td className="py-2 px-3 truncate max-w-[150px]" title={event.hostname}>{event.hostname || '-'}</td>
                        <td className="py-2 px-3 truncate max-w-[200px] font-mono text-xs" title={event.url}>{event.url || '-'}</td>
                        <td className="py-2 px-3 text-center"><ActionBadge action={event.action} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            />

            {/* VPN Events */}
            <CategorySection<TrackIPVPNEvent>
              name="VPN Events"
              icon={Lock}
              iconColor="bg-cyan-500/10 text-cyan-500"
              count={result.categories?.vpn?.count || 0}
              events={result.categories?.vpn?.events as TrackIPVPNEvent[] || []}
              renderTable={(paginatedEvents) => (
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="text-left py-2 px-3 font-medium">Time</th>
                      <th className="text-left py-2 px-3 font-medium">Type</th>
                      <th className="text-left py-2 px-3 font-medium">User</th>
                      <th className="text-left py-2 px-3 font-medium">Source IP</th>
                      <th className="text-left py-2 px-3 font-medium">Assigned IP</th>
                      <th className="text-left py-2 px-3 font-medium">Duration</th>
                      <th className="text-right py-2 px-3 font-medium">Traffic</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedEvents.map((event, idx) => (
                      <tr key={idx} className="border-t hover:bg-muted/30 transition-colors">
                        <td className="py-2 px-3 whitespace-nowrap text-muted-foreground">
                          {new Date(event.timestamp).toLocaleString('fr-FR', {
                            day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
                          })}
                        </td>
                        <td className="py-2 px-3">
                          <span className="px-2 py-0.5 bg-cyan-500/10 text-cyan-500 rounded text-xs">
                            {event.vpn_type} - {event.event_type}
                          </span>
                        </td>
                        <td className="py-2 px-3 font-medium">{event.user_name || '-'}</td>
                        <td className="py-2 px-3 font-mono text-xs">
                          {event.src_ip}
                          {event.geo_country && (
                            <span className="ml-1">{getFlagEmoji(event.geo_country)}</span>
                          )}
                        </td>
                        <td className="py-2 px-3 font-mono text-xs">{event.assigned_ip || '-'}</td>
                        <td className="py-2 px-3">{formatDuration(event.duration_seconds)}</td>
                        <td className="py-2 px-3 text-right font-mono text-xs">
                          <span className="text-green-500">{formatBytes(event.bytes_in)}</span>
                          {' / '}
                          <span className="text-blue-500">{formatBytes(event.bytes_out)}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            />

            {/* ATP Events */}
            <CategorySection<TrackIPATPEvent>
              name="Advanced Threat Protection"
              icon={AlertTriangle}
              iconColor="bg-red-500/10 text-red-500"
              count={result.categories?.atp?.count || 0}
              events={result.categories?.atp?.events as TrackIPATPEvent[] || []}
              renderTable={(paginatedEvents) => (
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="text-left py-2 px-3 font-medium">Time</th>
                      <th className="text-left py-2 px-3 font-medium">Severity</th>
                      <th className="text-left py-2 px-3 font-medium">Threat</th>
                      <th className="text-left py-2 px-3 font-medium">Type</th>
                      <th className="text-left py-2 px-3 font-medium">Source</th>
                      <th className="text-left py-2 px-3 font-medium">URL</th>
                      <th className="text-center py-2 px-3 font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedEvents.map((event, idx) => (
                      <tr key={idx} className="border-t hover:bg-muted/30 transition-colors">
                        <td className="py-2 px-3 whitespace-nowrap text-muted-foreground">
                          {new Date(event.timestamp).toLocaleString('fr-FR', {
                            day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
                          })}
                        </td>
                        <td className="py-2 px-3"><SeverityBadge severity={event.severity} /></td>
                        <td className="py-2 px-3 font-medium">{event.threat_name}</td>
                        <td className="py-2 px-3">{event.threat_type}</td>
                        <td className="py-2 px-3 font-mono text-xs">{event.src_ip}</td>
                        <td className="py-2 px-3 truncate max-w-[200px] font-mono text-xs" title={event.url}>
                          {event.url || '-'}
                        </td>
                        <td className="py-2 px-3 text-center"><ActionBadge action={event.action} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            />

            {/* Antivirus Events */}
            <CategorySection<TrackIPAntivirusEvent>
              name="Antivirus Events"
              icon={Bug}
              iconColor="bg-pink-500/10 text-pink-500"
              count={result.categories?.antivirus?.count || 0}
              events={result.categories?.antivirus?.events as TrackIPAntivirusEvent[] || []}
              renderTable={(paginatedEvents) => (
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="text-left py-2 px-3 font-medium">Time</th>
                      <th className="text-left py-2 px-3 font-medium">Malware</th>
                      <th className="text-left py-2 px-3 font-medium">Type</th>
                      <th className="text-left py-2 px-3 font-medium">Source</th>
                      <th className="text-left py-2 px-3 font-medium">File</th>
                      <th className="text-center py-2 px-3 font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedEvents.map((event, idx) => (
                      <tr key={idx} className="border-t hover:bg-muted/30 transition-colors">
                        <td className="py-2 px-3 whitespace-nowrap text-muted-foreground">
                          {new Date(event.timestamp).toLocaleString('fr-FR', {
                            day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
                          })}
                        </td>
                        <td className="py-2 px-3 font-medium text-red-500">{event.malware_name}</td>
                        <td className="py-2 px-3">{event.malware_type}</td>
                        <td className="py-2 px-3 font-mono text-xs">{event.src_ip}</td>
                        <td className="py-2 px-3 truncate max-w-[200px]" title={event.file_path || event.file_name}>
                          {event.file_name}
                        </td>
                        <td className="py-2 px-3 text-center"><ActionBadge action={event.action} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            />

            {/* Heartbeat Events */}
            <CategorySection<TrackIPHeartbeatEvent>
              name="Endpoint Heartbeat"
              icon={HeartPulse}
              iconColor="bg-teal-500/10 text-teal-500"
              count={result.categories?.heartbeat?.count || 0}
              events={result.categories?.heartbeat?.events as TrackIPHeartbeatEvent[] || []}
              renderTable={(paginatedEvents) => (
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="text-left py-2 px-3 font-medium">Time</th>
                      <th className="text-left py-2 px-3 font-medium">Endpoint</th>
                      <th className="text-left py-2 px-3 font-medium">IP</th>
                      <th className="text-left py-2 px-3 font-medium">OS</th>
                      <th className="text-center py-2 px-3 font-medium">Health Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedEvents.map((event, idx) => (
                      <tr key={idx} className="border-t hover:bg-muted/30 transition-colors">
                        <td className="py-2 px-3 whitespace-nowrap text-muted-foreground">
                          {new Date(event.timestamp).toLocaleString('fr-FR', {
                            day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
                          })}
                        </td>
                        <td className="py-2 px-3 font-medium">{event.endpoint_name}</td>
                        <td className="py-2 px-3 font-mono text-xs">{event.endpoint_ip}</td>
                        <td className="py-2 px-3">{event.os_type || '-'}</td>
                        <td className="py-2 px-3 text-center">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                            event.health_status === 'healthy' ? 'bg-green-500/10 text-green-500' :
                            event.health_status === 'suspicious' ? 'bg-yellow-500/10 text-yellow-500' :
                            'bg-red-500/10 text-red-500'
                          }`}>
                            {event.health_status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            />
          </div>
        </div>
      )}

      {/* List Modal */}
      <ListModal
        isOpen={!!listModal}
        onClose={() => setListModal(null)}
        title={listModal?.title || ''}
        items={listModal?.items || []}
      />

      {/* Empty State */}
      {!result && !loading && (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <div className="w-20 h-20 bg-muted rounded-full flex items-center justify-center mb-4">
            <Search className="w-10 h-10 text-muted-foreground" />
          </div>
          <h3 className="text-lg font-semibold mb-2">Track IP or Hostname</h3>
          <p className="text-muted-foreground max-w-md">
            Enter an IP address or hostname to search across all security logs including
            WAF, firewall, VPN, ATP, antivirus, and endpoint health events.
          </p>
        </div>
      )}
    </div>
  )
}
