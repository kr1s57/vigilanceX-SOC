import { useState, useEffect } from 'react'
import { Ban, Plus, RefreshCw, Clock, AlertCircle, X } from 'lucide-react'
import { bansApi } from '@/lib/api'
import { IPThreatModal } from '@/components/IPThreatModal'
import { formatDateTime } from '@/lib/utils'
import type { BanStatus, BanStats } from '@/types'

export function ActiveBans() {
  const [bans, setBans] = useState<BanStatus[]>([])
  const [stats, setStats] = useState<BanStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [showAddBan, setShowAddBan] = useState(false)
  const [selectedIP, setSelectedIP] = useState<string | null>(null)
  const [showThreatModal, setShowThreatModal] = useState(false)

  const handleIPLookup = (ip: string) => {
    setSelectedIP(ip)
    setShowThreatModal(true)
  }

  // Form states
  const [banIP, setBanIP] = useState('')
  const [banReason, setBanReason] = useState('')
  const [banPermanent, setBanPermanent] = useState(false)
  const [formError, setFormError] = useState('')

  useEffect(() => {
    fetchData()
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
            <h1 className="text-2xl font-bold">Active Bans</h1>
            <p className="text-muted-foreground">Manage blocked IP addresses</p>
          </div>
        </div>
        <div className="flex gap-3">
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

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-card rounded-xl border p-4">
            <p className="text-sm text-muted-foreground">Active Bans</p>
            <p className="text-2xl font-bold">{stats.total_active_bans}</p>
          </div>
          <div className="bg-card rounded-xl border p-4">
            <p className="text-sm text-muted-foreground">Permanent Bans</p>
            <p className="text-2xl font-bold">{stats.total_permanent_bans}</p>
          </div>
          <div className="bg-card rounded-xl border p-4">
            <p className="text-sm text-muted-foreground">Bans (24h)</p>
            <p className="text-2xl font-bold text-red-500">+{stats.bans_last_24h}</p>
          </div>
          <div className="bg-card rounded-xl border p-4">
            <p className="text-sm text-muted-foreground">Recidivists</p>
            <p className="text-2xl font-bold text-orange-500">{stats.recidivist_ips}</p>
          </div>
        </div>
      )}

      {/* Bans Table */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Status</th>
                <th>Ban Count</th>
                <th>Last Ban</th>
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
              ) : bans.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-muted-foreground">
                    No active bans
                  </td>
                </tr>
              ) : (
                bans.map((ban) => (
                  <tr
                    key={ban.ip}
                    className="cursor-pointer hover:bg-muted/50 transition-colors"
                    onClick={() => handleIPLookup(ban.ip)}
                  >
                    <td>
                      <span className="font-mono">{ban.ip}</span>
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
                        >
                          Unban
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
