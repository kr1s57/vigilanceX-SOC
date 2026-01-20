import { useState, useEffect, useMemo } from 'react'
import { Ban, Plus, RefreshCw, Clock, AlertCircle, X, ShieldAlert, Power, Users, Calendar, Repeat, Search, XCircle, ShieldCheck, ChevronDown, ChevronUp } from 'lucide-react'
import { bansApi, detect2banApi, pendingBansApi, type Detect2BanStatus } from '@/lib/api'
import { IPThreatModal } from '@/components/IPThreatModal'
import { PendingApprovalDetailModal } from '@/components/PendingApprovalDetailModal'
import { formatDateTime, getCountryFlag, cn } from '@/lib/utils'
import type { BanStatus, BanStats, PendingBan, PendingBanStats } from '@/types'

type StatsFilter = 'active' | 'permanent' | 'recent' | 'recidivist' | null

// v3.57.118: Sorting types
type PendingSortKey = 'date' | 'score'
type BansSortKey = 'status' | 'ban_count' | 'date'
type SortDirection = 'asc' | 'desc'

export function ActiveBans() {
  const [bans, setBans] = useState<BanStatus[]>([])
  const [stats, setStats] = useState<BanStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [showAddBan, setShowAddBan] = useState(false)
  const [selectedIP, setSelectedIP] = useState<string | null>(null)
  const [showThreatModal, setShowThreatModal] = useState(false)

  // Stats modal state
  const [statsFilter, setStatsFilter] = useState<StatsFilter>(null)

  // Detect2Ban state
  const [detect2banStatus, setDetect2banStatus] = useState<Detect2BanStatus | null>(null)
  const [togglingDetect2ban, setTogglingDetect2ban] = useState(false)

  // v3.57.114: Pending Approvals state
  const [pendingBans, setPendingBans] = useState<PendingBan[]>([])
  const [, setPendingStats] = useState<PendingBanStats | null>(null)
  const [approvingIP, setApprovingIP] = useState<string | null>(null)
  const [showPendingModal, setShowPendingModal] = useState(false)
  // v3.57.117: Selected pending for detail modal
  const [selectedPending, setSelectedPending] = useState<PendingBan | null>(null)
  const [showPendingDetailModal, setShowPendingDetailModal] = useState(false)

  // IP Search filter
  const [searchIP, setSearchIP] = useState('')

  // v3.57.118: Sorting state for pending bans
  const [pendingSort, setPendingSort] = useState<{ key: PendingSortKey; dir: SortDirection }>({ key: 'date', dir: 'desc' })
  // v3.57.118: Sorting state for bans list
  const [bansSort, setBansSort] = useState<{ key: BansSortKey; dir: SortDirection }>({ key: 'date', dir: 'desc' })
  // v3.57.118: Time filter for bans list (in hours, 0 = all)
  const [timeFilter, setTimeFilter] = useState<number>(0)

  // v3.57.118: Pagination state
  const [currentPage, setCurrentPage] = useState(1)
  const [itemsPerPage, setItemsPerPage] = useState(25)

  const handleIPLookup = (ip: string) => {
    setSelectedIP(ip)
    setShowThreatModal(true)
  }

  // Filter bans based on stats card clicked
  const getFilteredBans = (): BanStatus[] => {
    if (!statsFilter) return []
    const now = new Date()
    const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)

    switch (statsFilter) {
      case 'active':
        return bans.filter(b => b.status === 'active')
      case 'permanent':
        return bans.filter(b => b.status === 'permanent')
      case 'recent':
        return bans.filter(b => new Date(b.last_ban) >= twentyFourHoursAgo)
      case 'recidivist':
        return bans.filter(b => b.ban_count >= 2)
      default:
        return []
    }
  }

  const getFilterTitle = (): string => {
    switch (statsFilter) {
      case 'active': return 'Active2Ban'
      case 'permanent': return 'Permanent Bans'
      case 'recent': return 'Bans (Last 24h)'
      case 'recidivist': return 'Recidivist IPs'
      default: return ''
    }
  }

  // Filter bans by IP search and time
  const filteredBans = useMemo(() => {
    let filtered = bans
    // v3.57.118: Apply time filter
    if (timeFilter > 0) {
      const cutoff = new Date(Date.now() - timeFilter * 60 * 60 * 1000)
      filtered = filtered.filter(ban => new Date(ban.last_ban) >= cutoff)
    }
    // Apply IP search
    if (searchIP.trim()) {
      const search = searchIP.trim().toLowerCase()
      filtered = filtered.filter(ban => ban.ip.toLowerCase().includes(search))
    }
    return filtered
  }, [bans, searchIP, timeFilter])

  // v3.57.118: Sort filtered bans
  const sortedBans = useMemo(() => {
    const sorted = [...filteredBans]
    sorted.sort((a, b) => {
      let cmp = 0
      switch (bansSort.key) {
        case 'status':
          // permanent > active > other
          const statusOrder = { permanent: 2, active: 1 }
          cmp = (statusOrder[b.status as keyof typeof statusOrder] || 0) - (statusOrder[a.status as keyof typeof statusOrder] || 0)
          break
        case 'ban_count':
          cmp = b.ban_count - a.ban_count
          break
        case 'date':
        default:
          cmp = new Date(b.last_ban).getTime() - new Date(a.last_ban).getTime()
      }
      return bansSort.dir === 'asc' ? -cmp : cmp
    })
    return sorted
  }, [filteredBans, bansSort])

  // v3.57.118: Sort pending bans
  const sortedPendingBans = useMemo(() => {
    const sorted = [...pendingBans]
    sorted.sort((a, b) => {
      let cmp = 0
      switch (pendingSort.key) {
        case 'score':
          cmp = b.threat_score - a.threat_score
          break
        case 'date':
        default:
          cmp = new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      }
      return pendingSort.dir === 'asc' ? -cmp : cmp
    })
    return sorted
  }, [pendingBans, pendingSort])

  // v3.57.118: Toggle sorting for pending bans
  const togglePendingSort = (key: PendingSortKey) => {
    setPendingSort(prev => ({
      key,
      dir: prev.key === key && prev.dir === 'desc' ? 'asc' : 'desc'
    }))
  }

  // v3.57.118: Toggle sorting for bans
  const toggleBansSort = (key: BansSortKey) => {
    setBansSort(prev => ({
      key,
      dir: prev.key === key && prev.dir === 'desc' ? 'asc' : 'desc'
    }))
  }

  // v3.57.118: Pagination calculations
  const totalPages = Math.ceil(sortedBans.length / itemsPerPage)
  const paginatedBans = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage
    return sortedBans.slice(start, start + itemsPerPage)
  }, [sortedBans, currentPage, itemsPerPage])

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1)
  }, [searchIP, timeFilter, bansSort])

  // Form states
  const [banIP, setBanIP] = useState('')
  const [banReason, setBanReason] = useState('')
  const [banPermanent, setBanPermanent] = useState(false)
  const [formError, setFormError] = useState('')

  useEffect(() => {
    fetchData()
    fetchDetect2banStatus()
    fetchPendingBans()
  }, [])

  async function fetchData() {
    setLoading(true)
    try {
      const [bansData, statsData] = await Promise.all([
        bansApi.list(),
        bansApi.stats(),
      ])
      setBans(bansData || [])
      setStats(statsData)
    } catch (err) {
      console.error('Failed to fetch bans:', err)
      setBans([])
    } finally {
      setLoading(false)
    }
  }

  async function fetchDetect2banStatus() {
    try {
      const status = await detect2banApi.getStatus()
      setDetect2banStatus(status)
    } catch (err) {
      console.error('Failed to fetch Detect2Ban status:', err)
    }
  }

  // v3.57.113: Fetch pending approvals
  async function fetchPendingBans() {
    try {
      const [bansData, statsData] = await Promise.all([
        pendingBansApi.list(),
        pendingBansApi.stats()
      ])
      setPendingBans(bansData || [])
      setPendingStats(statsData)
    } catch (err) {
      console.error('Failed to fetch pending bans:', err)
      setPendingBans([])
    }
  }

  // v3.57.113: Approve pending ban
  async function handleApprovePending(id: string, ip: string) {
    if (!confirm(`Approve ban for ${ip}?\n\nThis will create an active ban for this IP.`)) return
    setApprovingIP(ip)
    try {
      await pendingBansApi.approve(id)
      await Promise.all([fetchData(), fetchPendingBans()])
    } catch (err) {
      console.error('Failed to approve pending ban:', err)
    } finally {
      setApprovingIP(null)
    }
  }

  // v3.57.113: Reject pending ban
  async function handleRejectPending(id: string, ip: string) {
    if (!confirm(`Reject ban for ${ip}?\n\nThis IP will NOT be banned and the pending request will be removed.`)) return
    setApprovingIP(ip)
    try {
      await pendingBansApi.reject(id)
      await fetchPendingBans()
    } catch (err) {
      console.error('Failed to reject pending ban:', err)
    } finally {
      setApprovingIP(null)
    }
  }

  // v3.57.117: Approve/Reject from detail modal (no confirm, modal already provides context)
  async function handleApprovePendingFromModal(id: string, ip: string) {
    setApprovingIP(ip)
    try {
      await pendingBansApi.approve(id)
      await Promise.all([fetchData(), fetchPendingBans()])
    } catch (err) {
      console.error('Failed to approve pending ban:', err)
      throw err // Re-throw for modal to handle
    } finally {
      setApprovingIP(null)
    }
  }

  async function handleRejectPendingFromModal(id: string, ip: string) {
    setApprovingIP(ip)
    try {
      await pendingBansApi.reject(id)
      await fetchPendingBans()
    } catch (err) {
      console.error('Failed to reject pending ban:', err)
      throw err // Re-throw for modal to handle
    } finally {
      setApprovingIP(null)
    }
  }

  // v3.57.117: Open detail modal for a pending ban
  function handleOpenPendingDetail(pending: PendingBan) {
    setSelectedPending(pending)
    setShowPendingDetailModal(true)
    setShowPendingModal(false) // Close list modal
  }

  async function handleToggleDetect2ban() {
    setTogglingDetect2ban(true)
    try {
      await detect2banApi.toggle()
      await fetchDetect2banStatus()
    } catch (err) {
      console.error('Failed to toggle Detect2Ban:', err)
    } finally {
      setTogglingDetect2ban(false)
    }
  }

  async function handleSync() {
    setSyncing(true)
    try {
      await bansApi.sync()
      await fetchData()
    } catch (err) {
      console.error('Failed to sync:', err)
    } finally {
      setSyncing(false)
    }
  }

  async function handleUnban(ip: string) {
    if (!confirm(`Are you sure you want to unban ${ip}?`)) return
    try {
      await bansApi.delete(ip)
      await fetchData()
    } catch (err) {
      console.error('Failed to unban:', err)
    }
  }

  async function handleUnbanWithImmunity(ip: string, hours: number = 24) {
    if (!confirm(`Unban ${ip} with ${hours}h immunity?\n\nThe IP will not be auto-banned by Detect2Ban for ${hours} hours.`)) return
    try {
      await bansApi.delete(ip, hours)
      await fetchData()
    } catch (err) {
      console.error('Failed to unban with immunity:', err)
    }
  }

  async function handleAddBan(e: React.FormEvent) {
    e.preventDefault()
    setFormError('')

    if (!banIP.trim()) {
      setFormError('IP address is required')
      return
    }
    if (!banReason.trim()) {
      setFormError('Reason is required')
      return
    }

    try {
      await bansApi.create({
        ip: banIP.trim(),
        reason: banReason.trim(),
        permanent: banPermanent,
      })
      setShowAddBan(false)
      setBanIP('')
      setBanReason('')
      setBanPermanent(false)
      await fetchData()
    } catch (err) {
      console.error('Failed to add ban:', err)
      setFormError('Failed to add ban')
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-500/10 rounded-lg">
            <Ban className="w-6 h-6 text-red-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Active2Ban</h1>
            <p className="text-muted-foreground">Manage blocked IP addresses</p>
          </div>
        </div>
        <div className="flex gap-3">
          {/* Detect2Ban Toggle - Core Security Engine */}
          <button
            onClick={handleToggleDetect2ban}
            disabled={togglingDetect2ban}
            title={detect2banStatus?.enabled
              ? `Detect2Ban Active (${detect2banStatus.scenario_count} scenarios)`
              : 'Detect2Ban Disabled - Click to enable automated threat detection'}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-300 ${
              detect2banStatus?.enabled
                ? 'bg-emerald-500/20 text-emerald-500 border border-emerald-500/50 hover:bg-emerald-500/30'
                : 'bg-muted text-muted-foreground hover:bg-muted/80 border border-transparent'
            }`}
          >
            <div className="relative">
              <ShieldAlert className={`w-5 h-5 ${detect2banStatus?.enabled ? 'animate-pulse' : ''}`} />
              <Power className={`w-2.5 h-2.5 absolute -bottom-0.5 -right-0.5 ${
                detect2banStatus?.enabled ? 'text-emerald-400' : 'text-muted-foreground'
              }`} />
            </div>
            <span className="font-medium">
              {togglingDetect2ban ? 'Loading...' : detect2banStatus?.enabled ? 'D2B Active' : 'D2B Off'}
            </span>
            {detect2banStatus?.enabled && detect2banStatus.scenario_count > 0 && (
              <span className="text-xs bg-emerald-500/30 px-1.5 py-0.5 rounded">
                {detect2banStatus.scenario_count}
              </span>
            )}
          </button>

          <button
            onClick={handleSync}
            disabled={syncing}
            className="flex items-center gap-2 px-4 py-2 bg-muted hover:bg-muted/80 rounded-lg transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${syncing ? 'animate-spin' : ''}`} />
            Sync XGS
          </button>
          <button
            onClick={() => setShowAddBan(true)}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add Ban
          </button>
        </div>
      </div>

      {/* Stats Cards - Clickable */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <button
            onClick={() => setStatsFilter('active')}
            className="bg-card rounded-xl border p-4 text-left hover:bg-muted/50 hover:border-primary/50 transition-all cursor-pointer"
          >
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
              <Users className="w-4 h-4" />
              Active2Ban
            </div>
            <p className="text-2xl font-bold">{stats.total_active_bans}</p>
          </button>
          <button
            onClick={() => setStatsFilter('permanent')}
            className="bg-card rounded-xl border p-4 text-left hover:bg-muted/50 hover:border-red-500/50 transition-all cursor-pointer"
          >
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
              <Ban className="w-4 h-4" />
              Permanent Bans
            </div>
            <p className="text-2xl font-bold text-red-500">{stats.total_permanent_bans}</p>
          </button>
          <button
            onClick={() => setStatsFilter('recent')}
            className="bg-card rounded-xl border p-4 text-left hover:bg-muted/50 hover:border-orange-500/50 transition-all cursor-pointer"
          >
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
              <Calendar className="w-4 h-4" />
              Bans (24h)
            </div>
            <p className="text-2xl font-bold text-orange-500">+{stats.bans_last_24h}</p>
          </button>
          <button
            onClick={() => setStatsFilter('recidivist')}
            className="bg-card rounded-xl border p-4 text-left hover:bg-muted/50 hover:border-yellow-500/50 transition-all cursor-pointer"
          >
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
              <Repeat className="w-4 h-4" />
              Recidivists
            </div>
            <p className="text-2xl font-bold text-yellow-500">{stats.recidivist_ips}</p>
          </button>
          {/* v3.57.114: Pending Approval Card */}
          <button
            onClick={() => setShowPendingModal(true)}
            className={`bg-card rounded-xl border p-4 text-left transition-all cursor-pointer ${
              pendingBans.length > 0
                ? 'hover:bg-amber-500/10 hover:border-amber-500/50 border-amber-500/30 bg-amber-500/5'
                : 'hover:bg-muted/50 hover:border-muted'
            }`}
          >
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
              <ShieldCheck className="w-4 h-4" />
              Pending Approval
            </div>
            <p className={`text-2xl font-bold ${pendingBans.length > 0 ? 'text-amber-500' : ''}`}>
              {pendingBans.length}
            </p>
          </button>
        </div>
      )}

      {/* Bans Table */}
      <div className="bg-card rounded-xl border overflow-hidden">
        {/* IP Search Filter */}
        <div className="p-4 border-b bg-muted/30">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="relative flex-1 min-w-[200px] max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                value={searchIP}
                onChange={(e) => setSearchIP(e.target.value)}
                placeholder="Search by IP address..."
                className="w-full pl-10 pr-10 py-2 bg-background border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
              {searchIP && (
                <button
                  onClick={() => setSearchIP('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 p-1 hover:bg-muted rounded transition-colors"
                >
                  <X className="w-3 h-3 text-muted-foreground" />
                </button>
              )}
            </div>
            {/* v3.57.118: Time filter buttons */}
            <div className="flex items-center gap-1 bg-muted/50 rounded-lg p-1">
              {[
                { label: 'All', value: 0 },
                { label: '8h', value: 8 },
                { label: '24h', value: 24 },
                { label: '7d', value: 168 },
              ].map(({ label, value }) => (
                <button
                  key={value}
                  onClick={() => setTimeFilter(value)}
                  className={cn(
                    "px-3 py-1 text-xs font-medium rounded transition-colors",
                    timeFilter === value
                      ? "bg-primary text-primary-foreground"
                      : "hover:bg-muted"
                  )}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
          {(searchIP || timeFilter > 0) && (
            <p className="mt-2 text-sm text-muted-foreground">
              Found {filteredBans.length} result{filteredBans.length !== 1 ? 's' : ''}
              {searchIP && ` for "${searchIP}"`}
              {timeFilter > 0 && ` in last ${timeFilter < 24 ? timeFilter + 'h' : Math.round(timeFilter / 24) + 'd'}`}
            </p>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th
                  className="cursor-pointer hover:bg-muted/50 select-none"
                  onClick={() => toggleBansSort('status')}
                >
                  <div className="flex items-center gap-1">
                    Status
                    {bansSort.key === 'status' && (
                      bansSort.dir === 'desc' ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />
                    )}
                  </div>
                </th>
                <th
                  className="cursor-pointer hover:bg-muted/50 select-none"
                  onClick={() => toggleBansSort('ban_count')}
                >
                  <div className="flex items-center gap-1">
                    Ban Count
                    {bansSort.key === 'ban_count' && (
                      bansSort.dir === 'desc' ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />
                    )}
                  </div>
                </th>
                <th
                  className="cursor-pointer hover:bg-muted/50 select-none"
                  onClick={() => toggleBansSort('date')}
                >
                  <div className="flex items-center gap-1">
                    Last Ban
                    {bansSort.key === 'date' && (
                      bansSort.dir === 'desc' ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />
                    )}
                  </div>
                </th>
                <th>Expires</th>
                <th>Reason</th>
                <th>Synced</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={8} className="text-center py-8">
                    <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary mx-auto"></div>
                  </td>
                </tr>
              ) : sortedBans.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-muted-foreground">
                    {searchIP ? `No bans found for "${searchIP}"` : 'No active bans'}
                  </td>
                </tr>
              ) : (
                paginatedBans.map((ban) => (
                  <tr
                    key={ban.ip}
                    className="cursor-pointer hover:bg-muted/50 transition-colors"
                    onClick={() => handleIPLookup(ban.ip)}
                  >
                    <td>
                      <div className="flex items-center gap-2">
                        {ban.country && (
                          <span title={ban.country} className="text-base">
                            {getCountryFlag(ban.country)}
                          </span>
                        )}
                        <span className="font-mono">{ban.ip}</span>
                      </div>
                    </td>
                    <td>
                      <span className={`inline-flex px-2 py-1 rounded text-xs font-medium ${
                        ban.status === 'permanent'
                          ? 'bg-red-500/10 text-red-500'
                          : ban.status === 'active'
                          ? 'bg-orange-500/10 text-orange-500'
                          : 'bg-gray-500/10 text-gray-500'
                      }`}>
                        {ban.status}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-1">
                        <span className="font-medium">{ban.ban_count}</span>
                        {ban.ban_count >= 4 && (
                          <AlertCircle className="w-4 h-4 text-red-500" />
                        )}
                      </div>
                    </td>
                    <td className="whitespace-nowrap">
                      {formatDateTime(ban.last_ban)}
                    </td>
                    <td>
                      {ban.expires_at ? (
                        <div className="flex items-center gap-1 text-sm">
                          <Clock className="w-4 h-4" />
                          {formatDateTime(ban.expires_at)}
                        </div>
                      ) : (
                        <span className="text-red-500 font-medium">Never</span>
                      )}
                    </td>
                    <td>
                      <span className="text-sm max-w-[200px] truncate block">{ban.reason}</span>
                    </td>
                    <td>
                      {ban.synced_xgs ? (
                        <span className="text-green-500">Yes</span>
                      ) : (
                        <span className="text-yellow-500">Pending</span>
                      )}
                    </td>
                    <td>
                      <div className="flex gap-2">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            handleUnban(ban.ip)
                          }}
                          className="px-2 py-1 text-xs bg-muted hover:bg-destructive hover:text-destructive-foreground rounded transition-colors"
                          title="Remove ban immediately"
                        >
                          Unban
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            handleUnbanWithImmunity(ban.ip, 24)
                          }}
                          className="px-2 py-1 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors"
                          title="Remove ban and prevent auto-ban for 24 hours"
                        >
                          Unban 24h
                        </button>
                        {ban.status !== 'permanent' && (
                          <button
                            onClick={(e) => e.stopPropagation()}
                            className="px-2 py-1 text-xs bg-muted hover:bg-muted/80 rounded transition-colors"
                          >
                            Extend
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* v3.57.118: Pagination Controls */}
        {sortedBans.length > 0 && (
          <div className="flex items-center justify-between p-4 border-t bg-muted/30">
            <div className="flex items-center gap-4">
              <span className="text-sm text-muted-foreground">
                Showing {((currentPage - 1) * itemsPerPage) + 1} - {Math.min(currentPage * itemsPerPage, sortedBans.length)} of {sortedBans.length}
              </span>
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">Per page:</span>
                <select
                  value={itemsPerPage}
                  onChange={(e) => {
                    setItemsPerPage(Number(e.target.value))
                    setCurrentPage(1)
                  }}
                  className="bg-background border rounded px-2 py-1 text-sm"
                >
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage(1)}
                disabled={currentPage === 1}
                className="px-3 py-1 text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                First
              </button>
              <button
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="px-3 py-1 text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <span className="px-3 py-1 text-sm">
                Page {currentPage} of {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={currentPage >= totalPages}
                className="px-3 py-1 text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
              <button
                onClick={() => setCurrentPage(totalPages)}
                disabled={currentPage >= totalPages}
                className="px-3 py-1 text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Last
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Add Ban Modal */}
      {showAddBan && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-xl border p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Add Ban</h3>
              <button
                onClick={() => { setShowAddBan(false); setFormError('') }}
                className="p-1 hover:bg-muted rounded"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <form onSubmit={handleAddBan} className="space-y-4">
              {formError && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-500 text-sm">
                  {formError}
                </div>
              )}
              <div>
                <label className="block text-sm font-medium mb-1">IP Address</label>
                <input
                  type="text"
                  value={banIP}
                  onChange={(e) => setBanIP(e.target.value)}
                  placeholder="e.g., 192.168.1.100"
                  className="w-full px-3 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Reason</label>
                <input
                  type="text"
                  value={banReason}
                  onChange={(e) => setBanReason(e.target.value)}
                  placeholder="e.g., Malicious activity"
                  className="w-full px-3 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="permanent"
                  checked={banPermanent}
                  onChange={(e) => setBanPermanent(e.target.checked)}
                  className="rounded"
                />
                <label htmlFor="permanent" className="text-sm">Permanent ban</label>
              </div>
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => { setShowAddBan(false); setFormError('') }}
                  className="flex-1 px-4 py-2 bg-muted rounded-lg hover:bg-muted/80 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors"
                >
                  Ban IP
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Stats Filter Modal */}
      {statsFilter && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-xl border p-6 w-full max-w-2xl max-h-[80vh] overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">{getFilterTitle()}</h3>
              <button
                onClick={() => setStatsFilter(null)}
                className="p-1 hover:bg-muted rounded"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="overflow-y-auto max-h-[60vh]">
              {getFilteredBans().length === 0 ? (
                <p className="text-center text-muted-foreground py-8">No IPs found</p>
              ) : (
                <table className="w-full">
                  <thead className="sticky top-0 bg-card">
                    <tr className="border-b">
                      <th className="text-left py-2 px-3 text-sm font-medium text-muted-foreground">IP Address</th>
                      <th className="text-left py-2 px-3 text-sm font-medium text-muted-foreground">Status</th>
                      <th className="text-left py-2 px-3 text-sm font-medium text-muted-foreground">Ban Count</th>
                      <th className="text-left py-2 px-3 text-sm font-medium text-muted-foreground">Last Ban</th>
                      <th className="text-left py-2 px-3 text-sm font-medium text-muted-foreground">Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {getFilteredBans().map((ban) => (
                      <tr
                        key={ban.ip}
                        className="border-b hover:bg-muted/50 cursor-pointer transition-colors"
                        onClick={() => {
                          setStatsFilter(null)
                          handleIPLookup(ban.ip)
                        }}
                      >
                        <td className="py-2 px-3">
                          <div className="flex items-center gap-2">
                            {ban.country && (
                              <span title={ban.country} className="text-base">
                                {getCountryFlag(ban.country)}
                              </span>
                            )}
                            <span className="font-mono text-sm">{ban.ip}</span>
                          </div>
                        </td>
                        <td className="py-2 px-3">
                          <span className={`inline-flex px-2 py-0.5 rounded text-xs font-medium ${
                            ban.status === 'permanent'
                              ? 'bg-red-500/10 text-red-500'
                              : 'bg-orange-500/10 text-orange-500'
                          }`}>
                            {ban.status}
                          </span>
                        </td>
                        <td className="py-2 px-3">
                          <div className="flex items-center gap-1">
                            <span className="font-medium">{ban.ban_count}</span>
                            {ban.ban_count >= 4 && (
                              <AlertCircle className="w-3 h-3 text-red-500" />
                            )}
                          </div>
                        </td>
                        <td className="py-2 px-3 text-sm text-muted-foreground whitespace-nowrap">
                          {formatDateTime(ban.last_ban)}
                        </td>
                        <td className="py-2 px-3 text-sm max-w-[200px] truncate" title={ban.reason}>
                          {ban.reason}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
            <div className="mt-4 pt-4 border-t flex justify-between items-center">
              <span className="text-sm text-muted-foreground">
                {getFilteredBans().length} IP{getFilteredBans().length !== 1 ? 's' : ''} found
              </span>
              <button
                onClick={() => setStatsFilter(null)}
                className="px-4 py-2 bg-muted rounded-lg hover:bg-muted/80 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* v3.57.114: Pending Approval Modal */}
      {showPendingModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-card rounded-xl border w-full max-w-3xl max-h-[85vh] overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b bg-amber-500/10">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-amber-500/20 rounded-lg">
                  <ShieldCheck className="w-5 h-5 text-amber-500" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-amber-600 dark:text-amber-400">
                    Pending Ban Approval
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    IPs from authorized countries requiring admin review
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {/* v3.57.118: Sorting controls */}
                <div className="flex items-center gap-1 bg-muted/50 rounded-lg p-1">
                  <button
                    onClick={() => togglePendingSort('date')}
                    className={cn(
                      "flex items-center gap-1 px-2 py-1 text-xs rounded transition-colors",
                      pendingSort.key === 'date' ? "bg-amber-500/20 text-amber-600" : "hover:bg-muted"
                    )}
                  >
                    <Clock className="w-3 h-3" />
                    Date
                    {pendingSort.key === 'date' && (
                      pendingSort.dir === 'desc' ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />
                    )}
                  </button>
                  <button
                    onClick={() => togglePendingSort('score')}
                    className={cn(
                      "flex items-center gap-1 px-2 py-1 text-xs rounded transition-colors",
                      pendingSort.key === 'score' ? "bg-amber-500/20 text-amber-600" : "hover:bg-muted"
                    )}
                  >
                    <AlertCircle className="w-3 h-3" />
                    Score
                    {pendingSort.key === 'score' && (
                      pendingSort.dir === 'desc' ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />
                    )}
                  </button>
                </div>
                <button
                  onClick={() => setShowPendingModal(false)}
                  className="p-2 hover:bg-muted rounded-lg transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Content */}
            <div className="overflow-y-auto max-h-[60vh]">
              {sortedPendingBans.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <ShieldCheck className="w-12 h-12 mb-4 opacity-50" />
                  <p className="text-lg font-medium">No Pending Approvals</p>
                  <p className="text-sm">All authorized country detections have been reviewed</p>
                </div>
              ) : (
                <div className="divide-y">
                  {sortedPendingBans.map((pending) => (
                    <div
                      key={pending.id}
                      className="p-4 hover:bg-muted/30 transition-colors cursor-pointer"
                      onClick={() => handleOpenPendingDetail(pending)}
                    >
                      <div className="flex items-start justify-between gap-4">
                        {/* IP Info */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-2">
                            <span className="text-xl" title={pending.country}>
                              {getCountryFlag(pending.country)}
                            </span>
                            <span className="font-mono text-lg font-semibold">{pending.ip}</span>
                            <span className="px-2 py-0.5 bg-amber-500/20 text-amber-600 dark:text-amber-400 rounded text-xs font-medium">
                              {pending.country}
                            </span>
                          </div>

                          {/* Details Grid */}
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm mb-3">
                            <div>
                              <p className="text-muted-foreground text-xs">Trigger</p>
                              <p className="font-medium">{pending.trigger_rule}</p>
                            </div>
                            <div>
                              <p className="text-muted-foreground text-xs">Events</p>
                              <p className="font-medium">{pending.event_count}</p>
                            </div>
                            <div>
                              <p className="text-muted-foreground text-xs">TI Score</p>
                              <p className={cn(
                                'font-bold',
                                pending.threat_score >= 70 ? 'text-red-500' :
                                pending.threat_score >= 30 ? 'text-orange-500' : 'text-green-500'
                              )}>
                                {pending.threat_score}%
                              </p>
                            </div>
                            <div>
                              <p className="text-muted-foreground text-xs">Last Event</p>
                              <p className="font-medium text-xs">{formatDateTime(pending.last_event)}</p>
                            </div>
                          </div>

                          {/* Reason */}
                          <p className="text-sm text-muted-foreground truncate" title={pending.reason}>
                            {pending.reason}
                          </p>
                        </div>

                        {/* Quick Actions - v3.57.117: Simplified, main action via click */}
                        <div className="flex flex-col gap-2" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => handleApprovePending(pending.id, pending.ip)}
                            disabled={approvingIP === pending.ip}
                            className="flex items-center justify-center gap-2 px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors text-sm font-medium disabled:opacity-50"
                          >
                            {approvingIP === pending.ip ? (
                              <RefreshCw className="w-4 h-4 animate-spin" />
                            ) : (
                              <Ban className="w-4 h-4" />
                            )}
                            Ban
                          </button>
                          <button
                            onClick={() => handleRejectPending(pending.id, pending.ip)}
                            disabled={approvingIP === pending.ip}
                            className="flex items-center justify-center gap-2 px-4 py-2 bg-green-500/10 text-green-500 border border-green-500/30 rounded-lg hover:bg-green-500/20 transition-colors text-sm font-medium disabled:opacity-50"
                          >
                            <XCircle className="w-4 h-4" />
                            Deny
                          </button>
                        </div>
                      </div>
                      {/* Click hint */}
                      <p className="text-xs text-muted-foreground mt-2 text-center">
                        Click to view full TI analysis and detection history
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="p-4 border-t bg-muted/30 flex items-center justify-between">
              <span className="text-sm text-muted-foreground">
                {pendingBans.length} pending approval{pendingBans.length !== 1 ? 's' : ''}
              </span>
              <button
                onClick={() => setShowPendingModal(false)}
                className="px-4 py-2 bg-muted rounded-lg hover:bg-muted/80 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* IP Threat Modal */}
      <IPThreatModal
        key={selectedIP || 'closed'}
        ip={selectedIP}
        isOpen={showThreatModal}
        onClose={() => {
          setShowThreatModal(false)
          setSelectedIP(null)
        }}
      />

      {/* v3.57.117: Pending Approval Detail Modal */}
      <PendingApprovalDetailModal
        pending={selectedPending}
        isOpen={showPendingDetailModal}
        onClose={() => {
          setShowPendingDetailModal(false)
          setSelectedPending(null)
        }}
        onApprove={handleApprovePendingFromModal}
        onReject={handleRejectPendingFromModal}
      />
    </div>
  )
}
