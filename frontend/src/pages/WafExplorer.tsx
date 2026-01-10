import { useState, useEffect, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Shield, Search, Download, RefreshCw, ChevronDown, ChevronRight, AlertTriangle, CheckCircle, Calendar, X } from 'lucide-react'
import { modsecApi } from '@/lib/api'
import { formatDateTime, getCountryFlag, getCountryName } from '@/lib/utils'
import { useSettings } from '@/contexts/SettingsContext'
import type { ModSecRequestGroup, ModSecLogFilters } from '@/types'

// Period options for WAF logs
type WafPeriod = '7d' | '14d' | '30d'

// Attack type colors
const attackTypeColors: Record<string, string> = {
  sqli: 'bg-red-500/20 text-red-400',
  xss: 'bg-orange-500/20 text-orange-400',
  lfi: 'bg-yellow-500/20 text-yellow-400',
  rfi: 'bg-yellow-500/20 text-yellow-400',
  rce: 'bg-red-600/20 text-red-500',
  protocol: 'bg-blue-500/20 text-blue-400',
  generic: 'bg-purple-500/20 text-purple-400',
}

// Severity badge colors
const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400',
  HIGH: 'bg-orange-500/20 text-orange-400',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400',
  LOW: 'bg-blue-500/20 text-blue-400',
  WARNING: 'bg-yellow-500/20 text-yellow-400',
  NOTICE: 'bg-gray-500/20 text-gray-400',
}

// Helper to format date for display
function formatDateDisplay(dateStr: string): string {
  const date = new Date(dateStr)
  const today = new Date()
  const yesterday = new Date(today)
  yesterday.setDate(yesterday.getDate() - 1)

  if (date.toDateString() === today.toDateString()) {
    return 'Today'
  } else if (date.toDateString() === yesterday.toDateString()) {
    return 'Yesterday'
  } else {
    return date.toLocaleDateString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    })
  }
}

// Helper to get date key from timestamp
function getDateKey(timestamp: string): string {
  return new Date(timestamp).toISOString().split('T')[0]
}

// Helper to get start time from period
function getStartTimeFromPeriod(period: WafPeriod): string {
  const now = new Date()
  const offsets: Record<WafPeriod, number> = {
    '7d': 7 * 24 * 60 * 60 * 1000,
    '14d': 14 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000,
  }
  return new Date(now.getTime() - offsets[period]).toISOString()
}

// Helper to get start/end of a specific day
function getDayBounds(dateStr: string): { start: string; end: string } {
  const date = new Date(dateStr)
  const start = new Date(date.getFullYear(), date.getMonth(), date.getDate(), 0, 0, 0, 0)
  const end = new Date(date.getFullYear(), date.getMonth(), date.getDate(), 23, 59, 59, 999)
  return {
    start: start.toISOString(),
    end: end.toISOString(),
  }
}

// Group requests by day
interface DayGroup {
  date: string
  dateDisplay: string
  requests: ModSecRequestGroup[]
  totalBlocked: number
  totalDetected: number
}

export function WafExplorer() {
  const { shouldShowIP } = useSettings()
  const [searchParams] = useSearchParams()
  const [requests, setRequests] = useState<ModSecRequestGroup[]>([])
  const [pagination, setPagination] = useState({ total: 0, limit: 500, offset: 0, has_more: false })
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [search, setSearch] = useState(searchParams.get('src_ip') || '')
  const [hostname, setHostname] = useState('')
  const [attackType, setAttackType] = useState('')
  const [hostnames, setHostnames] = useState<string[]>([])
  const [expandedDays, setExpandedDays] = useState<Set<string>>(new Set())
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())
  const [syncStatus, setSyncStatus] = useState<{ last_sync: string; is_configured: boolean } | null>(null)
  const [syncing, setSyncing] = useState(false)
  const [viewMode, setViewMode] = useState<'grouped' | 'flat'>('grouped')
  // Period and date selection
  const [period, setPeriod] = useState<WafPeriod>('7d')
  const [selectedDate, setSelectedDate] = useState<string>('') // YYYY-MM-DD format for single day view

  // Fetch sync status
  useEffect(() => {
    modsecApi.getStats().then(setSyncStatus).catch(() => {})
  }, [])

  // Fetch unique hostnames for filter
  useEffect(() => {
    modsecApi.getHostnames().then(data => {
      setHostnames(data || [])
    }).catch(() => {})
  }, [])

  // Fetch grouped ModSec logs
  useEffect(() => {
    async function fetchRequests() {
      setLoading(true)
      try {
        // Determine time filters based on selectedDate or period
        let startTime: string | undefined
        let endTime: string | undefined

        if (selectedDate) {
          // Single day view - show only that specific day
          const bounds = getDayBounds(selectedDate)
          startTime = bounds.start
          endTime = bounds.end
        } else {
          // Period view - show last N days
          startTime = getStartTimeFromPeriod(period)
          endTime = undefined
        }

        const filters: ModSecLogFilters = {
          hostname: hostname || undefined,
          attack_type: attackType || undefined,
          search: search || undefined,
          start_time: startTime,
          end_time: endTime,
          limit: pagination.limit,
          offset: pagination.offset,
        }
        const response = await modsecApi.getGroupedLogs(filters)
        setRequests(response.data || [])
        setPagination(response.pagination || { total: 0, limit: 500, offset: 0, has_more: false })
      } catch (err) {
        console.error('Failed to fetch ModSec logs:', err)
        setRequests([])
      } finally {
        setLoading(false)
      }
    }

    fetchRequests()
  }, [search, hostname, attackType, pagination.offset, period, selectedDate])

  // Group requests by day (filtered by system whitelist)
  const dayGroups = useMemo((): DayGroup[] => {
    // First filter out system IPs (DNS, CDN, etc.)
    const filteredRequests = requests.filter(r => shouldShowIP(r.src_ip))

    const groups: Record<string, ModSecRequestGroup[]> = {}

    for (const request of filteredRequests) {
      const dateKey = getDateKey(request.timestamp)
      if (!groups[dateKey]) {
        groups[dateKey] = []
      }
      groups[dateKey].push(request)
    }

    // Sort days descending (most recent first)
    const sortedDays = Object.keys(groups).sort((a, b) => b.localeCompare(a))

    return sortedDays.map(date => ({
      date,
      dateDisplay: formatDateDisplay(date),
      requests: groups[date],
      totalBlocked: groups[date].filter(r => r.is_blocked).length,
      totalDetected: groups[date].filter(r => !r.is_blocked).length,
    }))
  }, [requests, shouldShowIP])

  // Auto-expand all days on load (up to 7 days)
  useEffect(() => {
    if (dayGroups.length > 0 && expandedDays.size === 0) {
      // Expand all days (or up to 7 most recent)
      const daysToExpand = dayGroups.slice(0, 7).map(g => g.date)
      setExpandedDays(new Set(daysToExpand))
    }
  }, [dayGroups])

  const toggleDay = (date: string) => {
    const newExpanded = new Set(expandedDays)
    if (newExpanded.has(date)) {
      newExpanded.delete(date)
    } else {
      newExpanded.add(date)
    }
    setExpandedDays(newExpanded)
  }

  const toggleRow = (uniqueId: string) => {
    const newExpanded = new Set(expandedRows)
    if (newExpanded.has(uniqueId)) {
      newExpanded.delete(uniqueId)
    } else {
      newExpanded.add(uniqueId)
    }
    setExpandedRows(newExpanded)
  }

  const handleSync = async () => {
    setSyncing(true)
    try {
      await modsecApi.syncNow()
      // Determine time filters
      let startTime: string | undefined
      let endTime: string | undefined
      if (selectedDate) {
        const bounds = getDayBounds(selectedDate)
        startTime = bounds.start
        endTime = bounds.end
      } else {
        startTime = getStartTimeFromPeriod(period)
      }
      const filters: ModSecLogFilters = {
        hostname: hostname || undefined,
        attack_type: attackType || undefined,
        search: search || undefined,
        start_time: startTime,
        end_time: endTime,
        limit: pagination.limit,
        offset: 0,
      }
      const response = await modsecApi.getGroupedLogs(filters)
      setRequests(response.data || [])
      setPagination(response.pagination || { total: 0, limit: 500, offset: 0, has_more: false })
      const status = await modsecApi.getStats()
      setSyncStatus(status)
    } catch (err) {
      console.error('Sync failed:', err)
    } finally {
      setSyncing(false)
    }
  }

  const loadMore = async () => {
    if (!pagination.has_more || loadingMore) return
    setLoadingMore(true)
    try {
      // Determine time filters
      let startTime: string | undefined
      let endTime: string | undefined
      if (selectedDate) {
        const bounds = getDayBounds(selectedDate)
        startTime = bounds.start
        endTime = bounds.end
      } else {
        startTime = getStartTimeFromPeriod(period)
      }
      const filters: ModSecLogFilters = {
        hostname: hostname || undefined,
        attack_type: attackType || undefined,
        search: search || undefined,
        start_time: startTime,
        end_time: endTime,
        limit: pagination.limit,
        offset: pagination.offset + pagination.limit,
      }
      const response = await modsecApi.getGroupedLogs(filters)
      setRequests(prev => [...prev, ...(response.data || [])])
      setPagination(response.pagination || { total: 0, limit: 500, offset: 0, has_more: false })
    } catch (err) {
      console.error('Failed to load more:', err)
    } finally {
      setLoadingMore(false)
    }
  }

  const renderRequestRow = (request: ModSecRequestGroup) => (
    <>
      <tr
        key={request.unique_id}
        className="cursor-pointer hover:bg-muted/50"
        onClick={() => toggleRow(request.unique_id)}
      >
        <td className="w-8">
          {expandedRows.has(request.unique_id) ? (
            <ChevronDown className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          )}
        </td>
        <td className="whitespace-nowrap">
          <span className="text-sm">{formatDateTime(request.timestamp)}</span>
        </td>
        <td>
          <div className="flex flex-col">
            <span className="font-mono text-sm">{request.src_ip}</span>
            {request.geo_country && (
              <div className="flex items-center gap-1 text-xs text-muted-foreground mt-0.5">
                <span>{getCountryFlag(request.geo_country)}</span>
                <span>{getCountryName(request.geo_country)}</span>
                {request.geo_city && <span>- {request.geo_city}</span>}
              </div>
            )}
          </div>
        </td>
        <td>
          <div className="max-w-[200px]">
            <span className="text-sm font-medium">{request.hostname || 'Unknown'}</span>
            {request.uri && (
              <p className="text-xs text-muted-foreground truncate" title={request.uri}>
                {request.uri}
              </p>
            )}
          </div>
        </td>
        <td>
          <div className="flex items-center gap-2">
            <span className="inline-flex px-2 py-0.5 rounded text-xs font-bold bg-purple-500/20 text-purple-400">
              {request.rule_count} rule{request.rule_count > 1 ? 's' : ''}
            </span>
            {request.rules.slice(0, 3).map((rule, idx) => (
              <span
                key={idx}
                className="inline-flex px-1.5 py-0.5 rounded text-xs font-mono bg-gray-500/20 text-gray-300"
                title={rule.rule_msg}
              >
                {rule.rule_id}
              </span>
            ))}
            {request.rule_count > 3 && (
              <span className="text-xs text-muted-foreground">+{request.rule_count - 3}</span>
            )}
          </div>
        </td>
        <td>
          <span className={`inline-flex px-2 py-0.5 rounded text-xs font-bold ${
            request.total_score >= 25 ? 'bg-red-500/20 text-red-400' :
            request.total_score >= 10 ? 'bg-orange-500/20 text-orange-400' :
            request.total_score >= 5 ? 'bg-yellow-500/20 text-yellow-400' :
            'bg-gray-500/20 text-gray-400'
          }`}>
            {request.total_score}
          </span>
        </td>
        <td>
          {request.is_blocked ? (
            <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-red-500/10 text-red-400">
              <AlertTriangle className="w-3 h-3" />
              Blocked
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-orange-500/10 text-orange-400">
              <CheckCircle className="w-3 h-3" />
              Detected
            </span>
          )}
        </td>
      </tr>
      {/* Expanded row showing all rules */}
      {expandedRows.has(request.unique_id) && (
        <tr className="bg-muted/30">
          <td colSpan={7} className="p-4">
            <div className="space-y-3">
              <div className="text-sm font-medium text-muted-foreground mb-2">
                Detection Chain (unique_id: <code className="text-xs bg-muted px-1 rounded">{request.unique_id}</code>)
              </div>
              <div className="space-y-2">
                {request.rules.map((rule, idx) => (
                  <div
                    key={idx}
                    className="flex items-start gap-4 p-3 bg-background rounded-lg border"
                  >
                    <div className="flex-shrink-0">
                      <span className="inline-flex px-2 py-1 rounded text-sm font-bold font-mono bg-purple-500/20 text-purple-400">
                        Rule {rule.rule_id}
                      </span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        {rule.rule_severity && (
                          <span className={`inline-flex px-1.5 py-0.5 rounded text-xs font-medium ${
                            severityColors[rule.rule_severity.toUpperCase()] || 'bg-gray-500/20 text-gray-400'
                          }`}>
                            {rule.rule_severity}
                          </span>
                        )}
                        {rule.attack_type && (
                          <span className={`inline-flex px-1.5 py-0.5 rounded text-xs font-medium ${
                            attackTypeColors[rule.attack_type] || 'bg-gray-500/20 text-gray-400'
                          }`}>
                            {rule.attack_type.toUpperCase()}
                          </span>
                        )}
                        {rule.paranoia_level > 0 && (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-xs font-medium bg-indigo-500/20 text-indigo-400">
                            PL{rule.paranoia_level}
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-orange-400 mb-1">{rule.rule_msg}</p>
                      {rule.rule_data && (
                        <p className="text-xs text-muted-foreground">
                          <span className="font-medium">Matched:</span>{' '}
                          <code className="bg-muted px-1 rounded">{rule.rule_data}</code>
                        </p>
                      )}
                      {rule.rule_file && (
                        <p className="text-xs text-muted-foreground mt-1">
                          <span className="font-medium">File:</span> {rule.rule_file}
                        </p>
                      )}
                      {rule.tags && rule.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {rule.tags.slice(0, 5).map((tag, tagIdx) => (
                            <span
                              key={tagIdx}
                              className="inline-flex px-1 py-0.5 rounded text-xs bg-muted text-muted-foreground"
                            >
                              {tag}
                            </span>
                          ))}
                          {rule.tags.length > 5 && (
                            <span className="text-xs text-muted-foreground">+{rule.tags.length - 5} more</span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 rounded-lg">
            <Shield className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">WAF Explorer - ModSec Rules</h1>
            <p className="text-muted-foreground">
              ModSecurity detection rules from Sophos XGS
              {selectedDate ? (
                <span className="ml-2 text-xs font-medium text-primary">
                  Showing: {formatDateDisplay(selectedDate)}
                </span>
              ) : (
                <span className="ml-2 text-xs">
                  Last {period === '7d' ? '7 days' : period === '14d' ? '14 days' : '30 days'}
                </span>
              )}
              {syncStatus && (
                <span className="ml-2 text-xs text-muted-foreground">
                  (Last sync: {syncStatus.last_sync ? formatDateTime(syncStatus.last_sync) : 'Never'})
                </span>
              )}
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <div className="flex bg-muted rounded-lg p-1">
            <button
              onClick={() => setViewMode('grouped')}
              className={`px-3 py-1.5 text-sm rounded-md transition-colors ${
                viewMode === 'grouped'
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Calendar className="w-4 h-4 inline mr-1" />
              By Day
            </button>
            <button
              onClick={() => setViewMode('flat')}
              className={`px-3 py-1.5 text-sm rounded-md transition-colors ${
                viewMode === 'flat'
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              List
            </button>
          </div>
          <button
            onClick={handleSync}
            disabled={syncing || !syncStatus?.is_configured}
            className="flex items-center gap-2 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${syncing ? 'animate-spin' : ''}`} />
            {syncing ? 'Syncing...' : 'Sync Now'}
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors">
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 p-4 bg-card rounded-xl border">
        {/* Period selector */}
        <div className="flex bg-muted rounded-lg p-1">
          {(['7d', '14d', '30d'] as WafPeriod[]).map((p) => (
            <button
              key={p}
              onClick={() => {
                setPeriod(p)
                setSelectedDate('') // Clear specific date when selecting period
                setExpandedDays(new Set()) // Reset expanded state to trigger auto-expand
              }}
              className={`px-3 py-1.5 text-sm rounded-md transition-colors ${
                !selectedDate && period === p
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {p === '7d' ? '7 days' : p === '14d' ? '14 days' : '30 days'}
            </button>
          ))}
        </div>

        {/* Date picker */}
        <div className="relative flex items-center gap-2">
          <Calendar className="w-4 h-4 text-muted-foreground" />
          <input
            type="date"
            value={selectedDate}
            max={new Date().toISOString().split('T')[0]}
            onChange={(e) => {
              setSelectedDate(e.target.value)
              setExpandedDays(new Set()) // Reset to trigger auto-expand
            }}
            className={`px-3 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary text-sm ${
              selectedDate ? 'border-primary' : ''
            }`}
          />
          {selectedDate && (
            <button
              onClick={() => {
                setSelectedDate('')
                setExpandedDays(new Set())
              }}
              className="p-1 hover:bg-muted rounded-full"
              title="Clear date filter"
            >
              <X className="w-4 h-4 text-muted-foreground" />
            </button>
          )}
        </div>

        {/* Separator */}
        <div className="h-10 w-px bg-border" />

        {/* Search */}
        <div className="flex-1 min-w-[200px]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search rules, URIs, IPs, countries..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
        </div>
        <select
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          className="px-4 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
        >
          <option value="">All Webservers</option>
          {hostnames.map(h => (
            <option key={h} value={h}>{h}</option>
          ))}
        </select>
        <select
          value={attackType}
          onChange={(e) => setAttackType(e.target.value)}
          className="px-4 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
        >
          <option value="">All Attack Types</option>
          <option value="sqli">SQL Injection</option>
          <option value="xss">Cross-Site Scripting</option>
          <option value="lfi">Local File Inclusion</option>
          <option value="rfi">Remote File Inclusion</option>
          <option value="rce">Remote Code Execution</option>
          <option value="protocol">Protocol Attack</option>
        </select>
      </div>

      {/* Results */}
      <div className="bg-card rounded-xl border overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : requests.length === 0 ? (
          <div className="text-center py-12 text-muted-foreground">
            No ModSec logs found. {!syncStatus?.is_configured && 'ModSec sync is not configured.'}
          </div>
        ) : viewMode === 'grouped' ? (
          /* Grouped by Day View */
          <div className="divide-y">
            {dayGroups.map((group) => (
              <div key={group.date}>
                {/* Day Header */}
                <div
                  onClick={() => toggleDay(group.date)}
                  className="flex items-center justify-between p-4 cursor-pointer hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    {expandedDays.has(group.date) ? (
                      <ChevronDown className="w-5 h-5 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="w-5 h-5 text-muted-foreground" />
                    )}
                    <Calendar className="w-5 h-5 text-blue-500" />
                    <span className="font-semibold">{group.dateDisplay}</span>
                    <span className="text-sm text-muted-foreground">({group.date})</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="text-sm">
                      <span className="font-medium">{group.requests.length}</span>
                      <span className="text-muted-foreground"> detections</span>
                    </span>
                    {group.totalBlocked > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-red-500/10 text-red-400">
                        <AlertTriangle className="w-3 h-3" />
                        {group.totalBlocked} blocked
                      </span>
                    )}
                    {group.totalDetected > 0 && (
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-orange-500/10 text-orange-400">
                        {group.totalDetected} detected
                      </span>
                    )}
                  </div>
                </div>

                {/* Day Content */}
                {expandedDays.has(group.date) && (
                  <div className="border-t">
                    <div className="overflow-x-auto">
                      <table className="data-table w-full">
                        <thead>
                          <tr>
                            <th className="w-8"></th>
                            <th>Time</th>
                            <th>Source IP</th>
                            <th>Target</th>
                            <th>Rules Triggered</th>
                            <th>Score</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {group.requests.map((request) => renderRequestRow(request))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            ))}
            {/* Load More button for grouped view */}
            {pagination.has_more && (
              <div className="flex justify-center py-4 border-t">
                <button
                  onClick={loadMore}
                  disabled={loadingMore}
                  className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 flex items-center gap-2"
                >
                  {loadingMore ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current"></div>
                      Loading...
                    </>
                  ) : (
                    <>Load older logs ({pagination.total - requests.length} remaining)</>
                  )}
                </button>
              </div>
            )}
          </div>
        ) : (
          /* Flat List View */
          <div className="overflow-x-auto">
            <table className="data-table w-full">
              <thead>
                <tr>
                  <th className="w-8"></th>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Target</th>
                  <th>Rules Triggered</th>
                  <th>Score</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {requests.map((request) => renderRequestRow(request))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {pagination.total > 0 && (
          <div className="flex items-center justify-between px-4 py-3 border-t">
            <span className="text-sm text-muted-foreground">
              Showing {pagination.offset + 1} - {Math.min(pagination.offset + requests.length, pagination.total)} of {pagination.total} requests
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => setPagination(p => ({ ...p, offset: Math.max(0, p.offset - p.limit) }))}
                disabled={pagination.offset === 0}
                className="px-3 py-1 bg-muted rounded text-sm disabled:opacity-50"
              >
                Previous
              </button>
              <button
                onClick={() => setPagination(p => ({ ...p, offset: p.offset + p.limit }))}
                disabled={!pagination.has_more}
                className="px-3 py-1 bg-muted rounded text-sm disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
