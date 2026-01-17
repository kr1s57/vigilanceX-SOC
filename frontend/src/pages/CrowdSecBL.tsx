import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Search,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Database,
  Shield,
  Clock,
  Filter,
  AlertCircle,
  CheckCircle,
  XCircle,
  Globe,
  Zap,
  Loader2
} from 'lucide-react'
import { crowdsecBlocklistApi } from '@/lib/api'

// Country code to name mapping for common countries
const COUNTRY_NAMES: Record<string, string> = {
  'AF': 'Afghanistan', 'AL': 'Albania', 'DZ': 'Algeria', 'AR': 'Argentina', 'AM': 'Armenia',
  'AU': 'Australia', 'AT': 'Austria', 'AZ': 'Azerbaijan', 'BD': 'Bangladesh', 'BY': 'Belarus',
  'BE': 'Belgium', 'BO': 'Bolivia', 'BA': 'Bosnia', 'BR': 'Brazil', 'BG': 'Bulgaria',
  'KH': 'Cambodia', 'CA': 'Canada', 'CL': 'Chile', 'CN': 'China', 'CO': 'Colombia',
  'CR': 'Costa Rica', 'HR': 'Croatia', 'CU': 'Cuba', 'CY': 'Cyprus', 'CZ': 'Czechia',
  'DK': 'Denmark', 'DO': 'Dominican Rep.', 'EC': 'Ecuador', 'EG': 'Egypt', 'SV': 'El Salvador',
  'EE': 'Estonia', 'ET': 'Ethiopia', 'FI': 'Finland', 'FR': 'France', 'GE': 'Georgia',
  'DE': 'Germany', 'GH': 'Ghana', 'GR': 'Greece', 'GT': 'Guatemala', 'HN': 'Honduras',
  'HK': 'Hong Kong', 'HU': 'Hungary', 'IS': 'Iceland', 'IN': 'India', 'ID': 'Indonesia',
  'IR': 'Iran', 'IQ': 'Iraq', 'IE': 'Ireland', 'IL': 'Israel', 'IT': 'Italy',
  'JP': 'Japan', 'JO': 'Jordan', 'KZ': 'Kazakhstan', 'KE': 'Kenya', 'KW': 'Kuwait',
  'KG': 'Kyrgyzstan', 'LA': 'Laos', 'LV': 'Latvia', 'LB': 'Lebanon', 'LY': 'Libya',
  'LT': 'Lithuania', 'LU': 'Luxembourg', 'MY': 'Malaysia', 'MX': 'Mexico', 'MD': 'Moldova',
  'MN': 'Mongolia', 'MA': 'Morocco', 'MM': 'Myanmar', 'NP': 'Nepal', 'NL': 'Netherlands',
  'NZ': 'New Zealand', 'NI': 'Nicaragua', 'NG': 'Nigeria', 'KP': 'North Korea', 'NO': 'Norway',
  'PK': 'Pakistan', 'PA': 'Panama', 'PY': 'Paraguay', 'PE': 'Peru', 'PH': 'Philippines',
  'PL': 'Poland', 'PT': 'Portugal', 'PR': 'Puerto Rico', 'QA': 'Qatar', 'RO': 'Romania',
  'RU': 'Russia', 'SA': 'Saudi Arabia', 'RS': 'Serbia', 'SG': 'Singapore', 'SK': 'Slovakia',
  'SI': 'Slovenia', 'ZA': 'South Africa', 'KR': 'South Korea', 'ES': 'Spain', 'LK': 'Sri Lanka',
  'SD': 'Sudan', 'SE': 'Sweden', 'CH': 'Switzerland', 'SY': 'Syria', 'TW': 'Taiwan',
  'TJ': 'Tajikistan', 'TZ': 'Tanzania', 'TH': 'Thailand', 'TN': 'Tunisia', 'TR': 'Turkey',
  'TM': 'Turkmenistan', 'UA': 'Ukraine', 'AE': 'UAE', 'GB': 'United Kingdom', 'US': 'United States',
  'UY': 'Uruguay', 'UZ': 'Uzbekistan', 'VE': 'Venezuela', 'VN': 'Vietnam', 'YE': 'Yemen', 'ZW': 'Zimbabwe'
}

const getCountryName = (code: string): string => {
  return COUNTRY_NAMES[code?.toUpperCase()] || code
}

interface BlocklistIP {
  ip: string
  blocklist_id: string
  blocklist_label: string
  first_seen: string
  last_seen: string
  country_code: string
  country_name: string
}

interface BlocklistSummary {
  id: string
  label: string
  ip_count: number
}

interface SyncStatus {
  configured: boolean
  enabled: boolean
  sync_running: boolean
  error?: string
  last_sync: string
  total_ips: number
  group_name: string
  enabled_lists?: string[]
  xgs_ip_count?: number
}

export function CrowdSecBL() {
  // Data state
  const [ips, setIPs] = useState<BlocklistIP[]>([])
  const [blocklists, setBlocklists] = useState<BlocklistSummary[]>([])
  const [status, setStatus] = useState<SyncStatus | null>(null)

  // Pagination state
  const [page, setPage] = useState(1)
  const [pageSize] = useState(50)
  const [totalPages, setTotalPages] = useState(1)
  const [totalIPs, setTotalIPs] = useState(0)

  // Filter state
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [selectedBlocklist, setSelectedBlocklist] = useState<string>('')
  const [selectedCountry, setSelectedCountry] = useState<string>('')
  const [countryList, setCountryList] = useState<Array<{ code: string; name?: string }>>([])

  // UI state
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [needsEnrichment, setNeedsEnrichment] = useState(false)
  const [enrichedCount, setEnrichedCount] = useState(0)
  const [autoEnriching, setAutoEnriching] = useState(false)
  const autoEnrichRef = useRef(false)

  // Load blocklist summary, status, and countries on mount
  useEffect(() => {
    loadStatus()
    loadSummary()
    loadCountries()
  }, [])

  const loadCountries = async () => {
    try {
      const data = await crowdsecBlocklistApi.getUniqueCountries()
      setCountryList(data.countries || [])
      setNeedsEnrichment(data.needs_enrichment || false)
    } catch (err) {
      console.error('Failed to load countries:', err)
    }
  }

  // Auto-enrichment loop
  const startAutoEnrichment = async () => {
    setAutoEnriching(true)
    autoEnrichRef.current = true
    setEnrichedCount(0)

    while (autoEnrichRef.current) {
      try {
        const result = await crowdsecBlocklistApi.enrichCountries()
        setEnrichedCount(prev => prev + result.enriched)

        if (result.enriched === 0) {
          // All done!
          autoEnrichRef.current = false
          setNeedsEnrichment(false)
          await loadCountries()
          await loadIPs()
          break
        }

        // Wait 90 seconds (1.5 minutes) between batches to respect ip-api.com rate limit (45/min)
        await new Promise(resolve => setTimeout(resolve, 90000))

        // Refresh countries list periodically
        await loadCountries()
      } catch (err) {
        console.error('Auto-enrichment error:', err)
        // Wait longer on error
        await new Promise(resolve => setTimeout(resolve, 5000))
      }
    }

    setAutoEnriching(false)
  }

  const stopAutoEnrichment = () => {
    autoEnrichRef.current = false
    setAutoEnriching(false)
  }

  // Load IPs when filters change
  useEffect(() => {
    loadIPs()
  }, [page, search, selectedBlocklist, selectedCountry])

  const loadStatus = async () => {
    try {
      const data = await crowdsecBlocklistApi.getStatus()
      setStatus(data)
    } catch (err) {
      console.error('Failed to load status:', err)
    }
  }

  const loadSummary = async () => {
    try {
      const data = await crowdsecBlocklistApi.getBlocklistsSummary()
      setBlocklists(data.blocklists || [])
    } catch (err) {
      console.error('Failed to load blocklist summary:', err)
    }
  }

  const loadIPs = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await crowdsecBlocklistApi.getIPsPaginated({
        page,
        page_size: pageSize,
        search: search || undefined,
        blocklist_id: selectedBlocklist || undefined,
        country: selectedCountry || undefined,
      })
      setIPs(data.IPs || [])
      setTotalPages(data.TotalPages || 1)
      setTotalIPs(data.Total || 0)
    } catch (err) {
      setError('Failed to load IP list')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }, [page, pageSize, search, selectedBlocklist, selectedCountry])

  const handleSearch = () => {
    setPage(1)
    setSearch(searchInput)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch()
    }
  }

  const handleBlocklistFilter = (blocklistId: string) => {
    setPage(1)
    setSelectedBlocklist(blocklistId)
  }

  const handleCountryFilter = (country: string) => {
    setPage(1)
    setSelectedCountry(country)
  }

  const clearFilters = () => {
    setPage(1)
    setSearch('')
    setSearchInput('')
    setSelectedBlocklist('')
    setSelectedCountry('')
  }

  const handleSyncBlocklists = async () => {
    try {
      setSyncing(true)
      setError(null)
      await crowdsecBlocklistApi.syncAll()
      // Refresh all data after sync
      await Promise.all([loadStatus(), loadSummary(), loadIPs()])
    } catch (err) {
      setError('Sync failed - check API key and connection')
      console.error(err)
    } finally {
      setSyncing(false)
    }
  }

  const refreshAll = async () => {
    await Promise.all([loadStatus(), loadSummary(), loadIPs()])
  }

  const formatDate = (dateStr: string) => {
    if (!dateStr || dateStr === '0001-01-01T00:00:00Z') return 'Never'
    try {
      return new Date(dateStr).toLocaleString()
    } catch {
      return dateStr
    }
  }

  // Convert country code to flag emoji
  const getCountryFlag = (countryCode: string) => {
    if (!countryCode || countryCode.length !== 2) return ''
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map((char) => 127397 + char.charCodeAt(0))
    return String.fromCodePoint(...codePoints)
  }

  const getTimeSinceSync = () => {
    if (!status?.last_sync || status.last_sync === '0001-01-01T00:00:00Z') return 'Never'
    try {
      const lastSync = new Date(status.last_sync)
      const now = new Date()
      const diffMs = now.getTime() - lastSync.getTime()
      const diffMins = Math.floor(diffMs / 60000)
      const diffHours = Math.floor(diffMins / 60)
      const diffDays = Math.floor(diffHours / 24)

      if (diffDays > 0) return `${diffDays}d ago`
      if (diffHours > 0) return `${diffHours}h ago`
      if (diffMins > 0) return `${diffMins}m ago`
      return 'Just now'
    } catch {
      return 'Unknown'
    }
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-orange-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">CrowdSec Blocklist</h1>
            <p className="text-gray-400 text-sm">Direct CrowdSec API - Blocklist Intelligence Database</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Sync Status Badge */}
          {status && (
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm ${
              status.enabled && !status.error
                ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                : status.error
                  ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                  : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
            }`}>
              {status.enabled && !status.error ? (
                <CheckCircle className="h-4 w-4" />
              ) : status.error ? (
                <XCircle className="h-4 w-4" />
              ) : (
                <AlertCircle className="h-4 w-4" />
              )}
              <span>
                {status.sync_running ? 'Syncing...' : status.enabled ? 'Active' : 'Disabled'}
              </span>
              <span className="text-gray-500">|</span>
              <Clock className="h-3.5 w-3.5" />
              <span>{getTimeSinceSync()}</span>
            </div>
          )}

          {/* Sync Blocklist Button - Downloads IPs from CrowdSec API */}
          <button
            onClick={handleSyncBlocklists}
            disabled={syncing || !status?.enabled}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
              syncing
                ? 'bg-purple-500/30 text-purple-300 cursor-wait'
                : status?.enabled
                  ? 'bg-purple-600 hover:bg-purple-700 text-white'
                  : 'bg-gray-700 text-gray-500 cursor-not-allowed'
            }`}
            title={!status?.enabled ? 'Enable CrowdSec integration first' : 'Download latest IPs from CrowdSec blocklists'}
          >
            <Zap className={`h-4 w-4 ${syncing ? 'animate-pulse' : ''}`} />
            {syncing ? 'Downloading...' : 'Sync Blocklists'}
          </button>

          {/* Refresh Button - Refreshes the page data */}
          <button
            onClick={refreshAll}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white transition-colors"
            title="Refresh page data"
          >
            <RefreshCw className="h-4 w-4" />
            <span className="text-sm">Refresh</span>
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Total IPs */}
        <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-500/20">
              <Database className="h-5 w-5 text-purple-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Total IPs</p>
              <p className="text-2xl font-bold text-white">{status?.total_ips?.toLocaleString() || 0}</p>
            </div>
          </div>
        </div>

        {/* Active Blocklists */}
        <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/20">
              <Shield className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Blocklists</p>
              <p className="text-2xl font-bold text-white">{blocklists.length}</p>
            </div>
          </div>
        </div>

        {/* Filtered Results */}
        <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-green-500/20">
              <Filter className="h-5 w-5 text-green-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Filtered Results</p>
              <p className="text-2xl font-bold text-white">{totalIPs.toLocaleString()}</p>
            </div>
          </div>
        </div>

        {/* XGS Group */}
        <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-orange-500/20">
              <Shield className="h-5 w-5 text-orange-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">XGS Group</p>
              <p className="text-2xl font-bold text-white">
                {status?.xgs_ip_count !== undefined ? status.xgs_ip_count.toLocaleString() : '—'}
              </p>
              <p className="text-xs text-gray-500 truncate" title={status?.group_name}>
                {status?.group_name || 'Not configured'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Country Enrichment Card - Shows when IPs need country data */}
      {needsEnrichment && (
        <div className="bg-gradient-to-r from-green-900/30 to-emerald-900/30 rounded-xl p-4 border border-green-500/30">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/20">
                <Globe className="h-6 w-6 text-green-400" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-green-400">Country Enrichment Required</h3>
                <p className="text-sm text-gray-400">
                  Some IPs don't have country data yet. Start enrichment to enable country filtering.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {autoEnriching ? (
                <>
                  <div className="flex items-center gap-2 px-4 py-2 bg-green-500/20 border border-green-500/30 rounded-lg text-green-400">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span className="text-sm font-medium">
                      Enriching... {enrichedCount.toLocaleString()} IPs done
                    </span>
                  </div>
                  <button
                    onClick={stopAutoEnrichment}
                    className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-colors"
                  >
                    Stop
                  </button>
                </>
              ) : (
                <button
                  onClick={startAutoEnrichment}
                  className="flex items-center gap-2 px-6 py-3 bg-green-600 hover:bg-green-700 text-white rounded-lg font-bold transition-colors shadow-lg shadow-green-500/20"
                  title="Start automatic country enrichment (45 IPs every 1.5 minutes)"
                >
                  <Globe className="h-5 w-5" />
                  Start Country Enrichment
                </button>
              )}
            </div>
          </div>
          {autoEnriching && (
            <div className="mt-3 text-xs text-gray-500">
              ⚡ Enriching 45 IPs every 1.5 minutes (ip-api.com rate limit). This runs in background until complete.
            </div>
          )}
        </div>
      )}

      {/* Blocklist Summary */}
      {blocklists.length > 0 && (
        <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700/50">
          <h3 className="text-sm font-medium text-gray-400 mb-3">Active Blocklists</h3>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => handleBlocklistFilter('')}
              className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                selectedBlocklist === ''
                  ? 'bg-purple-500/30 text-purple-300 border border-purple-500/50'
                  : 'bg-gray-700/50 text-gray-400 hover:bg-gray-700 hover:text-white'
              }`}
            >
              All ({status?.total_ips?.toLocaleString() || 0})
            </button>
            {blocklists.map((bl) => (
              <button
                key={bl.id}
                onClick={() => handleBlocklistFilter(bl.id)}
                className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                  selectedBlocklist === bl.id
                    ? 'bg-purple-500/30 text-purple-300 border border-purple-500/50'
                    : 'bg-gray-700/50 text-gray-400 hover:bg-gray-700 hover:text-white'
                }`}
              >
                {bl.label} ({bl.ip_count.toLocaleString()})
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Search and Filters */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex-1 flex items-center gap-2 flex-wrap">
          <div className="relative flex-1 max-w-md min-w-[200px]">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search IP address..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={handleKeyDown}
              className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
            />
          </div>
          <button
            onClick={handleSearch}
            className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors"
          >
            Search
          </button>

          {/* Country Filter */}
          <div className="relative">
            <Globe className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-500 pointer-events-none" />
            <select
              value={selectedCountry}
              onChange={(e) => handleCountryFilter(e.target.value)}
              disabled={needsEnrichment}
              className={`pl-10 pr-8 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-purple-500 appearance-none min-w-[180px] ${
                needsEnrichment ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'
              }`}
              title={needsEnrichment ? 'Country enrichment required before filtering' : 'Filter by country'}
            >
              <option value="">{needsEnrichment ? 'Enrichment required...' : 'All Countries'}</option>
              {countryList.map((c) => (
                <option key={c.code} value={c.code}>
                  {getCountryFlag(c.code)} {getCountryName(c.code)}
                </option>
              ))}
            </select>
            <ChevronRight className="absolute right-3 top-1/2 transform -translate-y-1/2 rotate-90 h-4 w-4 text-gray-500 pointer-events-none" />
          </div>

          {(search || selectedBlocklist || selectedCountry) && (
            <button
              onClick={clearFilters}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg transition-colors"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-4 text-red-400">
          {error}
        </div>
      )}

      {/* IP Table */}
      <div className="bg-gray-800/50 rounded-xl border border-gray-700/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-gray-900/50 border-b border-gray-700/50">
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">IP Address</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Country</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Blocklist</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">First Seen</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                    <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2" />
                    Loading...
                  </td>
                </tr>
              ) : ips.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                    {search || selectedBlocklist ? 'No IPs match your filters' : 'No IPs in database'}
                  </td>
                </tr>
              ) : (
                ips.map((ipItem, idx) => (
                  <tr
                    key={`${ipItem.ip}-${idx}`}
                    className="border-b border-gray-700/30 hover:bg-gray-700/30 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <code className="text-purple-300 bg-purple-500/10 px-2 py-1 rounded font-mono text-sm">
                        {ipItem.ip}
                      </code>
                    </td>
                    <td className="px-4 py-3">
                      {ipItem.country_code ? (
                        <span className="flex items-center gap-2 text-sm text-gray-300">
                          <span className="text-base">{getCountryFlag(ipItem.country_code)}</span>
                          <span>{getCountryName(ipItem.country_code)}</span>
                        </span>
                      ) : (
                        <span className="text-sm text-gray-500 italic">Pending enrichment</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-gray-300">{ipItem.blocklist_label}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-gray-400">{formatDate(ipItem.first_seen)}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-gray-400">{formatDate(ipItem.last_seen)}</span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 bg-gray-900/30 border-t border-gray-700/50">
            <div className="text-sm text-gray-400">
              Page {page} of {totalPages} ({totalIPs.toLocaleString()} total)
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage(Math.max(1, page - 1))}
                disabled={page === 1}
                className="p-2 rounded-lg bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="h-4 w-4 text-gray-300" />
              </button>

              {/* Page numbers */}
              <div className="flex items-center gap-1">
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  let pageNum: number
                  if (totalPages <= 5) {
                    pageNum = i + 1
                  } else if (page <= 3) {
                    pageNum = i + 1
                  } else if (page >= totalPages - 2) {
                    pageNum = totalPages - 4 + i
                  } else {
                    pageNum = page - 2 + i
                  }
                  return (
                    <button
                      key={pageNum}
                      onClick={() => setPage(pageNum)}
                      className={`px-3 py-1 rounded-lg text-sm transition-colors ${
                        page === pageNum
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-white'
                      }`}
                    >
                      {pageNum}
                    </button>
                  )
                })}
              </div>

              <button
                onClick={() => setPage(Math.min(totalPages, page + 1))}
                disabled={page === totalPages}
                className="p-2 rounded-lg bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight className="h-4 w-4 text-gray-300" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
