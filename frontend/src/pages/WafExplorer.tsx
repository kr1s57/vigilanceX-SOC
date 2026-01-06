import { useState, useEffect } from 'react'
import { Shield, Search, Download } from 'lucide-react'
import { eventsApi } from '@/lib/api'
import { formatDateTime, getSeverityColor, getSeverityBgColor, getCountryFlag } from '@/lib/utils'
import type { Event } from '@/types'

export function WafExplorer() {
  const [events, setEvents] = useState<Event[]>([])
  const [pagination, setPagination] = useState({ total: 0, limit: 50, offset: 0, has_more: false })
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [action, setAction] = useState('')

  useEffect(() => {
    async function fetchEvents() {
      setLoading(true)
      try {
        const response = await eventsApi.list({
          log_type: 'WAF',
          severity: severity || undefined,
          action: action || undefined,
          search: search || undefined,
          limit: pagination.limit,
          offset: pagination.offset,
        })
        setEvents(response.data)
        setPagination(response.pagination)
      } catch (err) {
        console.error('Failed to fetch WAF events:', err)
      } finally {
        setLoading(false)
      }
    }

    fetchEvents()
  }, [search, severity, action, pagination.offset])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 rounded-lg">
            <Shield className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">WAF Explorer</h1>
            <p className="text-muted-foreground">Web Application Firewall events analysis</p>
          </div>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors">
          <Download className="w-4 h-4" />
          Export
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 p-4 bg-card rounded-xl border">
        <div className="flex-1 min-w-[200px]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search events..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
        </div>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="px-4 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={action}
          onChange={(e) => setAction(e.target.value)}
          className="px-4 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
        >
          <option value="">All Actions</option>
          <option value="drop">Blocked</option>
          <option value="allow">Allowed</option>
        </select>
      </div>

      {/* Events Table */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Source IP</th>
                <th>Target</th>
                <th>Category</th>
                <th>Rule</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} className="text-center py-8">
                    <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary mx-auto"></div>
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-muted-foreground">
                    No events found
                  </td>
                </tr>
              ) : (
                events.map((event) => (
                  <tr key={event.event_id} className="cursor-pointer hover:bg-muted/50">
                    <td className="whitespace-nowrap">
                      <span className="text-sm">{formatDateTime(event.timestamp)}</span>
                    </td>
                    <td>
                      <span className={`inline-flex px-2 py-1 rounded text-xs font-medium ${getSeverityBgColor(event.severity)} ${getSeverityColor(event.severity)}`}>
                        {event.severity}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm">{event.src_ip}</span>
                        {event.geo_country && (
                          <span>{getCountryFlag(event.geo_country)}</span>
                        )}
                      </div>
                    </td>
                    <td>
                      <div className="max-w-[200px] truncate">
                        <span className="text-sm">{event.hostname || event.dst_ip}</span>
                        {event.url && (
                          <p className="text-xs text-muted-foreground truncate">{event.url}</p>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className="text-sm">{event.sub_category || event.category}</span>
                    </td>
                    <td>
                      <div className="max-w-[150px] truncate">
                        <span className="text-sm">{event.rule_name || event.rule_id}</span>
                      </div>
                    </td>
                    <td>
                      <span className={`inline-flex px-2 py-1 rounded text-xs font-medium ${
                        event.action === 'drop' ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'
                      }`}>
                        {event.action === 'drop' ? 'Blocked' : 'Allowed'}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {pagination.total > 0 && (
          <div className="flex items-center justify-between px-4 py-3 border-t">
            <span className="text-sm text-muted-foreground">
              Showing {pagination.offset + 1} - {Math.min(pagination.offset + events.length, pagination.total)} of {pagination.total}
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
