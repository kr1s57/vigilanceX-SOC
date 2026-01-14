import { useState, useEffect, useCallback } from 'react'
import {
  Brain,
  Search,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Database,
  Shield,
  AlertCircle,
  CheckCircle,
  XCircle,
  Zap,
  Loader2,
  Server
} from 'lucide-react'
import { neuralSyncApi, type NeuralSyncIP, type NeuralSyncBlocklist, type NeuralSyncStatus } from '@/lib/api'

// Country code to name mapping
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

const getCountryName = (code: string): string => COUNTRY_NAMES[code?.toUpperCase()] || code
const getCountryFlag = (code: string): string => {
  if (!code || code.length !== 2) return '🌐'
  const codePoints = code.toUpperCase().split('').map(char => 127397 + char.charCodeAt(0))
  return String.fromCodePoint(...codePoints)
}

export function NeuralSync() {
  // Data state
  const [ips, setIPs] = useState<NeuralSyncIP[]>([])
  const [blocklists, setBlocklists] = useState<NeuralSyncBlocklist[]>([])
  const [status, setStatus] = useState<NeuralSyncStatus | null>(null)

  // Pagination state
  const [page, setPage] = useState(1)
  const [pageSize] = useState(50)
  const [totalPages, setTotalPages] = useState(1)
  const [totalIPs, setTotalIPs] = useState(0)

  // Filter state
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedBlocklist, setSelectedBlocklist] = useState<string>('')
  const [selectedCountry, setSelectedCountry] = useState<string>('')

  // Loading state
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Fetch status
  const fetchStatus = useCallback(async () => {
    try {
      const statusData = await neuralSyncApi.getStatus()
      setStatus(statusData)
    } catch (err) {
      console.error('Failed to fetch status:', err)
    }
  }, [])

  // Fetch blocklists
  const fetchBlocklists = useCallback(async () => {
    try {
      const result = await neuralSyncApi.listBlocklists()
      setBlocklists(result.blocklists || [])
    } catch (err) {
      console.error('Failed to fetch blocklists:', err)
    }
  }, [])

  // Fetch IPs
  const fetchIPs = useCallback(async (pageNum: number = 1) => {
    setLoading(true)
    setError(null)
    try {
      const result = await neuralSyncApi.getIPs({
        page: pageNum,
        page_size: pageSize,
        blocklist_id: selectedBlocklist || undefined,
        country: selectedCountry || undefined,
        search: searchQuery || undefined,
      })
      if (result.error) {
        setError(result.error)
        setIPs([])
      } else {
        setIPs(result.ips || [])
        setTotalIPs(result.total || 0)
        setTotalPages(result.total_pages || 1)
      }
    } catch (err: any) {
      setError(err.message || 'Failed to fetch IPs')
      setIPs([])
    } finally {
      setLoading(false)
    }
  }, [pageSize, selectedBlocklist, selectedCountry, searchQuery])

  // Initial load
  useEffect(() => {
    fetchStatus()
    fetchBlocklists()
  }, [fetchStatus, fetchBlocklists])

  // Fetch IPs when filters change
  useEffect(() => {
    fetchIPs(1)
    setPage(1)
  }, [selectedBlocklist, selectedCountry])

  // Handle refresh
  const handleRefresh = async () => {
    setRefreshing(true)
    await fetchStatus()
    await fetchBlocklists()
    await fetchIPs(page)
    setRefreshing(false)
  }

  // Handle search
  const handleSearch = () => {
    setPage(1)
    fetchIPs(1)
  }

  // Handle page change
  const handlePageChange = (newPage: number) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setPage(newPage)
      fetchIPs(newPage)
    }
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Brain className="h-8 w-8 text-purple-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">Neural-Sync</h1>
            <p className="text-gray-400 text-sm">VigilanceKey Proxy - Centralized Blocklist Database</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Connection Status Badge */}
          {status && (
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm ${
              status.connected
                ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                : status.configured
                  ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                  : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
            }`}>
              {status.connected ? (
                <CheckCircle className="w-4 h-4" />
              ) : status.configured ? (
                <AlertCircle className="w-4 h-4" />
              ) : (
                <XCircle className="w-4 h-4" />
              )}
              <span>
                {status.connected ? 'Connected' : status.configured ? 'Disconnected' : 'Not Configured'}
              </span>
            </div>
          )}

          {/* Refresh Button */}
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Not Configured Warning */}
      {status && !status.configured && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <Server className="w-5 h-5 text-yellow-400 mt-0.5" />
            <div>
              <h3 className="font-semibold text-yellow-400">Neural-Sync Not Configured</h3>
              <p className="text-sm text-gray-400 mt-1">
                Configure Neural-Sync in Settings to connect to VigilanceKey and access centralized blocklists.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Stats Cards */}
      {status && status.configured && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <Server className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-gray-400">Server</p>
                <p className="text-white font-semibold truncate max-w-[150px]" title={status.server_url}>
                  {status.server_url?.replace('https://', '').replace('http://', '') || 'N/A'}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-500/20 rounded-lg">
                <Database className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-gray-400">Blocklists</p>
                <p className="text-white font-semibold">{status.total_blocklists || 0}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-amber-500/20 rounded-lg">
                <Shield className="w-5 h-5 text-amber-400" />
              </div>
              <div>
                <p className="text-sm text-gray-400">Total IPs</p>
                <p className="text-white font-semibold">{status.total_ips?.toLocaleString() || 0}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${status.connected ? 'bg-green-500/20' : 'bg-red-500/20'}`}>
                <Zap className={`w-5 h-5 ${status.connected ? 'text-green-400' : 'text-red-400'}`} />
              </div>
              <div>
                <p className="text-sm text-gray-400">Status</p>
                <p className={`font-semibold ${status.connected ? 'text-green-400' : 'text-red-400'}`}>
                  {status.connected ? 'Connected' : 'Disconnected'}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      {status?.configured && (
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4">
          <div className="flex flex-wrap items-center gap-4">
            {/* Search */}
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                  placeholder="Search IP address..."
                  className="w-full pl-10 pr-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                />
              </div>
            </div>

            {/* Blocklist Filter */}
            <div className="min-w-[200px]">
              <select
                value={selectedBlocklist}
                onChange={(e) => setSelectedBlocklist(e.target.value)}
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50"
              >
                <option value="">All Blocklists</option>
                {blocklists.map(bl => (
                  <option key={bl.id} value={bl.id}>
                    {bl.label || bl.name} ({bl.ip_count?.toLocaleString()})
                  </option>
                ))}
              </select>
            </div>

            {/* Search Button */}
            <button
              onClick={handleSearch}
              className="px-4 py-2 bg-purple-500 hover:bg-purple-600 text-white rounded-lg transition-colors flex items-center gap-2"
            >
              <Search className="w-4 h-4" />
              Search
            </button>

            {/* Clear Filters */}
            {(searchQuery || selectedBlocklist || selectedCountry) && (
              <button
                onClick={() => {
                  setSearchQuery('')
                  setSelectedBlocklist('')
                  setSelectedCountry('')
                }}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      )}

      {/* IP Table */}
      {status?.configured && (
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <h3 className="text-lg font-semibold text-white">Blocklist IPs</h3>
              <span className="text-sm text-gray-400">
                {totalIPs.toLocaleString()} total
              </span>
            </div>
          </div>

          {loading ? (
            <div className="p-12 text-center">
              <Loader2 className="w-8 h-8 text-purple-400 animate-spin mx-auto mb-3" />
              <p className="text-gray-400">Loading IPs from VigilanceKey...</p>
            </div>
          ) : error ? (
            <div className="p-12 text-center">
              <AlertCircle className="w-8 h-8 text-red-400 mx-auto mb-3" />
              <p className="text-red-400">{error}</p>
            </div>
          ) : ips.length === 0 ? (
            <div className="p-12 text-center">
              <Database className="w-8 h-8 text-gray-500 mx-auto mb-3" />
              <p className="text-gray-400">No IPs found</p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-900/50">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">IP Address</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Country</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Blocklist</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700">
                    {ips.map((ip, idx) => (
                      <tr key={`${ip.ip}-${idx}`} className="hover:bg-gray-800/30">
                        <td className="px-4 py-3">
                          <span className="font-mono text-white">{ip.ip}</span>
                        </td>
                        <td className="px-4 py-3">
                          {ip.country_code ? (
                            <span className="flex items-center gap-2">
                              <span className="text-lg">{getCountryFlag(ip.country_code)}</span>
                              <span className="text-gray-300">{getCountryName(ip.country_code)}</span>
                            </span>
                          ) : (
                            <span className="text-gray-500">—</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-1 bg-purple-500/20 text-purple-300 rounded text-sm">
                            {ip.blocklist_label || ip.blocklist_id}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="px-6 py-4 border-t border-gray-700 flex items-center justify-between">
                  <span className="text-sm text-gray-400">
                    Page {page} of {totalPages}
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handlePageChange(page - 1)}
                      disabled={page <= 1}
                      className="p-2 bg-gray-700 hover:bg-gray-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <ChevronLeft className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handlePageChange(page + 1)}
                      disabled={page >= totalPages}
                      className="p-2 bg-gray-700 hover:bg-gray-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Blocklists Info */}
      {status?.configured && blocklists.length > 0 && (
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-700">
            <h3 className="text-lg font-semibold text-white">Available Blocklists</h3>
          </div>
          <div className="divide-y divide-gray-700">
            {blocklists.map(bl => (
              <div key={bl.id} className="px-6 py-4 flex items-center justify-between hover:bg-gray-800/30">
                <div>
                  <p className="text-white font-medium">{bl.label || bl.name}</p>
                  <p className="text-sm text-gray-400">{bl.description || bl.id}</p>
                </div>
                <div className="text-right">
                  <p className="text-amber-400 font-mono">{bl.ip_count?.toLocaleString() || 0} IPs</p>
                  {bl.last_sync && (
                    <p className="text-xs text-gray-500">
                      Last sync: {new Date(bl.last_sync).toLocaleString()}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
