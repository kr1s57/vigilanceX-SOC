import { useState, useEffect } from 'react'
import { Shield, ShieldCheck, Eye, Plus, Trash2, Search, RefreshCw, Clock, Tag, Server, Globe } from 'lucide-react'
import { softWhitelistApi, configApi, SystemWhitelistEntry } from '@/lib/api'
import type { WhitelistEntry, WhitelistStats, WhitelistCheckResult, WhitelistRequest } from '@/types'

export function SoftWhitelist() {
  const [stats, setStats] = useState<WhitelistStats | null>(null)
  const [entries, setEntries] = useState<WhitelistEntry[]>([])
  const [filterType, setFilterType] = useState<'all' | 'hard' | 'soft' | 'monitor'>('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // System whitelist (protected IPs)
  const [systemWhitelist, setSystemWhitelist] = useState<{
    entries: SystemWhitelistEntry[]
    by_category: Record<string, SystemWhitelistEntry[]>
  } | null>(null)
  const [showSystemIPs, setShowSystemIPs] = useState(false)

  // Add entry modal
  const [showAddModal, setShowAddModal] = useState(false)
  const [newEntry, setNewEntry] = useState<WhitelistRequest>({
    ip: '',
    type: 'soft',
    reason: '',
    description: '',
    score_modifier: 50,
    alert_only: true,
    duration_days: null,
    tags: [],
  })
  const [tagInput, setTagInput] = useState('')

  // IP check
  const [checkIP, setCheckIP] = useState('')
  const [checkResult, setCheckResult] = useState<WhitelistCheckResult | null>(null)
  const [checkLoading, setCheckLoading] = useState(false)

  useEffect(() => {
    loadData()
  }, [filterType])

  // Load system whitelist on mount
  useEffect(() => {
    configApi.getSystemWhitelist()
      .then(setSystemWhitelist)
      .catch(err => console.error('Failed to load system whitelist:', err))
  }, [])

  const loadData = async () => {
    try {
      setLoading(true)
      setError(null)
      const [statsData, entriesData] = await Promise.all([
        softWhitelistApi.stats(),
        softWhitelistApi.list(filterType === 'all' ? undefined : filterType),
      ])
      setStats(statsData)
      setEntries(entriesData.data || [])
    } catch (err) {
      setError('Failed to load whitelist data')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const handleAddEntry = async () => {
    if (!newEntry.ip || !newEntry.reason) return

    try {
      // Parse CIDR notation if present (e.g., "10.25.72.0/24" -> ip: "10.25.72.0", cidr_mask: 24)
      let ip = newEntry.ip.trim()
      let cidrMask = 32 // Default: single IP

      if (ip.includes('/')) {
        const parts = ip.split('/')
        ip = parts[0]
        const mask = parseInt(parts[1], 10)
        if (!isNaN(mask) && mask >= 0 && mask <= 32) {
          cidrMask = mask
        }
      }

      await softWhitelistApi.add({
        ...newEntry,
        ip,
        cidr_mask: cidrMask,
      })
      setShowAddModal(false)
      setNewEntry({
        ip: '',
        type: 'soft',
        reason: '',
        description: '',
        score_modifier: 50,
        alert_only: true,
        duration_days: null,
        tags: [],
      })
      loadData()
    } catch (err) {
      console.error('Failed to add entry:', err)
    }
  }

  const handleDeleteEntry = async (ip: string) => {
    if (!confirm(`Remove ${ip} from whitelist?`)) return

    try {
      await softWhitelistApi.remove(ip)
      loadData()
    } catch (err) {
      console.error('Failed to remove entry:', err)
    }
  }

  const handleCheckIP = async () => {
    if (!checkIP) return

    try {
      setCheckLoading(true)
      const result = await softWhitelistApi.check(checkIP)
      setCheckResult(result)
    } catch (err) {
      console.error('Failed to check IP:', err)
      setCheckResult(null)
    } finally {
      setCheckLoading(false)
    }
  }

  const addTag = () => {
    if (tagInput && !newEntry.tags?.includes(tagInput)) {
      setNewEntry({ ...newEntry, tags: [...(newEntry.tags || []), tagInput] })
      setTagInput('')
    }
  }

  const removeTag = (tag: string) => {
    setNewEntry({ ...newEntry, tags: newEntry.tags?.filter(t => t !== tag) || [] })
  }

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'hard': return 'bg-green-500/20 text-green-400 border-green-500/30'
      case 'soft': return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
      case 'monitor': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30'
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'hard': return <ShieldCheck className="w-4 h-4" />
      case 'soft': return <Shield className="w-4 h-4" />
      case 'monitor': return <Eye className="w-4 h-4" />
      default: return <Shield className="w-4 h-4" />
    }
  }

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never'
    return new Date(dateStr).toLocaleDateString('fr-FR', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Soft Whitelist</h1>
          <p className="text-muted-foreground">Manage IP whitelist with graduated trust levels</p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90"
        >
          <Plus className="w-4 h-4" />
          Add Entry
        </button>
      </div>

      {error && (
        <div className="bg-destructive/20 text-destructive px-4 py-3 rounded-lg">{error}</div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-card border border-border rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/20 rounded-lg">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Total Entries</p>
              <p className="text-2xl font-bold">{stats?.total || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-card border border-border rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/20 rounded-lg">
              <ShieldCheck className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Hard Whitelist</p>
              <p className="text-2xl font-bold">{stats?.by_type?.hard || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-card border border-border rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/20 rounded-lg">
              <Shield className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Soft Whitelist</p>
              <p className="text-2xl font-bold">{stats?.by_type?.soft || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-card border border-border rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-500/20 rounded-lg">
              <Eye className="w-5 h-5 text-yellow-400" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Monitor Only</p>
              <p className="text-2xl font-bold">{stats?.by_type?.monitor || 0}</p>
            </div>
          </div>
        </div>
      </div>

      {/* IP Check */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Search className="w-5 h-5" />
          Check IP Whitelist Status
        </h2>
        <div className="flex gap-2">
          <input
            type="text"
            value={checkIP}
            onChange={(e) => setCheckIP(e.target.value)}
            placeholder="Enter IP address..."
            className="flex-1 px-3 py-2 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
            onKeyDown={(e) => e.key === 'Enter' && handleCheckIP()}
          />
          <button
            onClick={handleCheckIP}
            disabled={checkLoading || !checkIP}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50"
          >
            {checkLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'Check'}
          </button>
        </div>

        {checkResult && (
          <div className="mt-4 p-4 bg-muted/50 rounded-lg">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="text-muted-foreground">Whitelisted:</span>
                <span className={`ml-2 font-medium ${checkResult.is_whitelisted ? 'text-green-400' : 'text-red-400'}`}>
                  {checkResult.is_whitelisted ? 'Yes' : 'No'}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">Type:</span>
                <span className={`ml-2 px-2 py-0.5 rounded text-xs ${getTypeColor(checkResult.effective_type)}`}>
                  {checkResult.effective_type}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">Score Modifier:</span>
                <span className="ml-2 font-medium">{checkResult.score_modifier}%</span>
              </div>
              <div>
                <span className="text-muted-foreground">Auto-ban:</span>
                <span className={`ml-2 font-medium ${checkResult.allow_auto_ban ? 'text-red-400' : 'text-green-400'}`}>
                  {checkResult.allow_auto_ban ? 'Allowed' : 'Blocked'}
                </span>
              </div>
            </div>
            {checkResult.entry && (
              <div className="mt-3 pt-3 border-t border-border">
                <p className="text-sm"><span className="text-muted-foreground">Reason:</span> {checkResult.entry.reason}</p>
                {checkResult.entry.tags && checkResult.entry.tags.length > 0 && (
                  <div className="flex gap-1 mt-2">
                    {checkResult.entry.tags.map((tag) => (
                      <span key={tag} className="px-2 py-0.5 bg-primary/20 text-primary text-xs rounded">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Filter and Entries List */}
      <div className="bg-card border border-border rounded-lg">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="text-lg font-semibold">Whitelist Entries</h2>
          <div className="flex items-center gap-2">
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value as typeof filterType)}
              className="px-3 py-1.5 bg-background border border-border rounded-lg text-sm"
            >
              <option value="all">All Types</option>
              <option value="hard">Hard</option>
              <option value="soft">Soft</option>
              <option value="monitor">Monitor</option>
            </select>
            <button
              onClick={loadData}
              className="p-2 hover:bg-muted rounded-lg"
              title="Refresh"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="divide-y divide-border">
          {entries.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">
              No whitelist entries found
            </div>
          ) : (
            entries.map((entry) => (
              <div key={entry.ip} className="p-4 hover:bg-muted/50">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3">
                      <code className="text-sm font-mono bg-muted px-2 py-1 rounded">
                        {entry.ip}{entry.cidr_mask > 0 && entry.cidr_mask < 32 ? `/${entry.cidr_mask}` : ''}
                      </code>
                      <span className={`flex items-center gap-1 px-2 py-0.5 rounded text-xs border ${getTypeColor(entry.type)}`}>
                        {getTypeIcon(entry.type)}
                        {entry.type}
                      </span>
                      {!entry.is_active && (
                        <span className="px-2 py-0.5 bg-red-500/20 text-red-400 text-xs rounded">
                          Inactive
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">{entry.reason}</p>
                    {entry.description && (
                      <p className="text-xs text-muted-foreground mt-1">{entry.description}</p>
                    )}
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      {entry.type === 'soft' && (
                        <span>Score: -{entry.score_modifier}%</span>
                      )}
                      {entry.alert_only && entry.type === 'soft' && (
                        <span className="text-yellow-400">Alert Only</span>
                      )}
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        Expires: {formatDate(entry.expires_at)}
                      </span>
                      <span>Added: {formatDate(entry.created_at)}</span>
                    </div>
                    {entry.tags && entry.tags.length > 0 && (
                      <div className="flex items-center gap-1 mt-2">
                        <Tag className="w-3 h-3 text-muted-foreground" />
                        {entry.tags.map((tag) => (
                          <span key={tag} className="px-2 py-0.5 bg-primary/20 text-primary text-xs rounded">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <button
                    onClick={() => handleDeleteEntry(entry.ip)}
                    className="p-2 hover:bg-destructive/20 text-destructive rounded-lg"
                    title="Remove from whitelist"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Type Legend */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Whitelist Types</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="flex items-start gap-3">
            <div className="p-2 bg-green-500/20 rounded-lg">
              <ShieldCheck className="w-4 h-4 text-green-400" />
            </div>
            <div>
              <p className="font-medium text-green-400">Hard</p>
              <p className="text-muted-foreground text-xs">Full bypass - never banned, score ignored</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <div className="p-2 bg-blue-500/20 rounded-lg">
              <Shield className="w-4 h-4 text-blue-400" />
            </div>
            <div>
              <p className="font-medium text-blue-400">Soft</p>
              <p className="text-muted-foreground text-xs">Score reduced, alert only (no auto-ban)</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <div className="p-2 bg-yellow-500/20 rounded-lg">
              <Eye className="w-4 h-4 text-yellow-400" />
            </div>
            <div>
              <p className="font-medium text-yellow-400">Monitor</p>
              <p className="text-muted-foreground text-xs">Logging only, no impact on score or bans</p>
            </div>
          </div>
        </div>
      </div>

      {/* System IPs Section */}
      <div className="bg-card border border-border rounded-lg">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/20 rounded-lg">
              <Server className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">System Protected IPs</h2>
              <p className="text-sm text-muted-foreground">
                Infrastructure IPs that are never blocked (DNS, CDN, Health Checks)
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowSystemIPs(!showSystemIPs)}
            className="px-3 py-1.5 text-sm bg-muted hover:bg-muted/80 rounded-lg transition-colors"
          >
            {showSystemIPs ? 'Hide' : 'Show'} ({systemWhitelist?.entries.length || 0} IPs)
          </button>
        </div>

        {showSystemIPs && systemWhitelist && (
          <div className="p-4">
            {Object.entries(systemWhitelist.by_category).map(([category, ips]) => (
              <div key={category} className="mb-4 last:mb-0">
                <h4 className="text-sm font-medium text-muted-foreground mb-2 capitalize flex items-center gap-2">
                  {category === 'dns' && <Globe className="w-4 h-4" />}
                  {category === 'cloud' && <Server className="w-4 h-4" />}
                  {category === 'monitoring' && <Eye className="w-4 h-4" />}
                  {category.toUpperCase()} ({ips.length})
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {ips.map((ip) => (
                    <div
                      key={ip.ip}
                      className="flex items-center gap-3 p-2 bg-muted/50 rounded-lg"
                    >
                      <code className="text-sm font-mono text-cyan-400">{ip.ip}</code>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium truncate">{ip.name}</p>
                        <p className="text-xs text-muted-foreground truncate">{ip.provider}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
            <p className="text-xs text-muted-foreground mt-4 italic">
              These IPs are automatically filtered from logs when "Hide system IPs" is enabled in Settings.
            </p>
          </div>
        )}
      </div>

      {/* Add Entry Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card border border-border rounded-lg p-6 w-full max-w-md">
            <h2 className="text-lg font-semibold mb-4">Add Whitelist Entry</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">IP Address *</label>
                <input
                  type="text"
                  value={newEntry.ip}
                  onChange={(e) => setNewEntry({ ...newEntry, ip: e.target.value })}
                  placeholder="192.168.1.1 or 10.0.0.0/24"
                  className="w-full px-3 py-2 bg-background border border-border rounded-lg"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Type *</label>
                <select
                  value={newEntry.type}
                  onChange={(e) => setNewEntry({ ...newEntry, type: e.target.value as 'hard' | 'soft' | 'monitor' })}
                  className="w-full px-3 py-2 bg-background border border-border rounded-lg"
                >
                  <option value="hard">Hard - Full bypass</option>
                  <option value="soft">Soft - Score reduction</option>
                  <option value="monitor">Monitor - Logging only</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Reason *</label>
                <input
                  type="text"
                  value={newEntry.reason}
                  onChange={(e) => setNewEntry({ ...newEntry, reason: e.target.value })}
                  placeholder="Why is this IP whitelisted?"
                  className="w-full px-3 py-2 bg-background border border-border rounded-lg"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <input
                  type="text"
                  value={newEntry.description}
                  onChange={(e) => setNewEntry({ ...newEntry, description: e.target.value })}
                  placeholder="Additional details..."
                  className="w-full px-3 py-2 bg-background border border-border rounded-lg"
                />
              </div>

              {newEntry.type === 'soft' && (
                <>
                  <div>
                    <label className="block text-sm font-medium mb-1">
                      Score Reduction: {newEntry.score_modifier}%
                    </label>
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={newEntry.score_modifier}
                      onChange={(e) => setNewEntry({ ...newEntry, score_modifier: parseInt(e.target.value) })}
                      className="w-full"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="alertOnly"
                      checked={newEntry.alert_only}
                      onChange={(e) => setNewEntry({ ...newEntry, alert_only: e.target.checked })}
                      className="rounded"
                    />
                    <label htmlFor="alertOnly" className="text-sm">Alert only (no auto-ban)</label>
                  </div>
                </>
              )}

              <div>
                <label className="block text-sm font-medium mb-1">Duration (days, empty = permanent)</label>
                <input
                  type="number"
                  value={newEntry.duration_days || ''}
                  onChange={(e) => setNewEntry({ ...newEntry, duration_days: e.target.value ? parseInt(e.target.value) : null })}
                  placeholder="Leave empty for permanent"
                  className="w-full px-3 py-2 bg-background border border-border rounded-lg"
                  min="1"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Tags</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    placeholder="Add tag..."
                    className="flex-1 px-3 py-2 bg-background border border-border rounded-lg"
                    onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addTag())}
                  />
                  <button
                    type="button"
                    onClick={addTag}
                    className="px-3 py-2 bg-muted hover:bg-muted/80 rounded-lg"
                  >
                    Add
                  </button>
                </div>
                {newEntry.tags && newEntry.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {newEntry.tags.map((tag) => (
                      <span
                        key={tag}
                        className="flex items-center gap-1 px-2 py-0.5 bg-primary/20 text-primary text-xs rounded"
                      >
                        {tag}
                        <button onClick={() => removeTag(tag)} className="hover:text-destructive">&times;</button>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 border border-border rounded-lg hover:bg-muted"
              >
                Cancel
              </button>
              <button
                onClick={handleAddEntry}
                disabled={!newEntry.ip || !newEntry.reason}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50"
              >
                Add Entry
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
