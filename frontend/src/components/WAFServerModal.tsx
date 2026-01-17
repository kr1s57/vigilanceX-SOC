import { useState, useEffect } from 'react'
import {
  X,
  Plus,
  Settings,
  Trash2,
  Globe,
  ShieldCheck,
  ShieldOff,
  Loader2,
  Server,
  AlertTriangle,
  FileText,
  Clock,
  Eye,
} from 'lucide-react'
import { wafServersApi, modsecApi, type WAFMonitoredServer, type WAFServerRequest } from '@/lib/api'
import { CountrySelector } from './CountrySelector'
import { cn } from '@/lib/utils'

interface WAFServerModalProps {
  isOpen: boolean
  onClose: () => void
  onServersUpdated?: () => void
  initialHostname?: string // If set, opens in edit mode for this hostname
}

type ViewMode = 'list' | 'add' | 'edit'

// Combined server info: configured or auto-discovered
interface ServerInfo {
  hostname: string
  displayName: string
  isConfigured: boolean
  server?: WAFMonitoredServer
}

export function WAFServerModal({
  isOpen,
  onClose,
  onServersUpdated,
  initialHostname,
}: WAFServerModalProps) {
  const [mode, setMode] = useState<ViewMode>('list')
  const [servers, setServers] = useState<WAFMonitoredServer[]>([])
  const [discoveredHostnames, setDiscoveredHostnames] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [editingServer, setEditingServer] = useState<WAFMonitoredServer | null>(null)

  // Delete confirmation state
  const [deleteConfirm, setDeleteConfirm] = useState<{
    hostname: string
    displayName: string
    deleteLogs: boolean
    isConfigured: boolean
  } | null>(null)

  // Form state
  const [formData, setFormData] = useState<WAFServerRequest>({
    hostname: '',
    display_name: '',
    description: '',
    policy_enabled: false,
    policy_mode: 'none',
    white_countries: [],
    block_countries: [],
    waf_threshold: 5,
    custom_ban_reason: '',
    enabled: true,
  })

  // Fetch servers on open
  useEffect(() => {
    if (isOpen) {
      fetchServers()
      if (initialHostname) {
        setMode('edit')
        loadServer(initialHostname)
      } else {
        setMode('list')
      }
    }
  }, [isOpen, initialHostname])

  const fetchServers = async () => {
    setLoading(true)
    setError(null)
    try {
      // Fetch both configured servers and auto-discovered hostnames
      const [configuredResult, discoveredResult] = await Promise.all([
        wafServersApi.list(),
        modsecApi.getHostnames().catch(() => []),
      ])
      setServers(configuredResult.data || [])
      setDiscoveredHostnames(discoveredResult || [])
    } catch (err) {
      console.error('Failed to fetch servers:', err)
      setError('Failed to load WAF servers')
    } finally {
      setLoading(false)
    }
  }

  // Combine configured servers and auto-discovered hostnames
  const allServers: ServerInfo[] = (() => {
    const configuredHostnames = new Set(servers.map(s => s.hostname))
    const result: ServerInfo[] = []

    // Add configured servers first
    for (const server of servers) {
      result.push({
        hostname: server.hostname,
        displayName: server.display_name || server.hostname,
        isConfigured: true,
        server,
      })
    }

    // Add auto-discovered hostnames that are not configured
    for (const hostname of discoveredHostnames) {
      if (!configuredHostnames.has(hostname)) {
        result.push({
          hostname,
          displayName: hostname,
          isConfigured: false,
        })
      }
    }

    return result.sort((a, b) => a.hostname.localeCompare(b.hostname))
  })()

  const loadServer = async (hostname: string) => {
    setLoading(true)
    setError(null)
    try {
      const result = await wafServersApi.get(hostname)
      const server = result.data
      setEditingServer(server)
      setFormData({
        hostname: server.hostname,
        display_name: server.display_name,
        description: server.description,
        policy_enabled: server.policy_enabled,
        policy_mode: server.policy_mode,
        white_countries: server.white_countries || [],
        block_countries: server.block_countries || [],
        waf_threshold: server.waf_threshold,
        custom_ban_reason: server.custom_ban_reason,
        enabled: server.enabled,
      })
    } catch (err) {
      console.error('Failed to load server:', err)
      setError('Failed to load server details')
      setMode('list')
    } finally {
      setLoading(false)
    }
  }

  const resetForm = () => {
    setFormData({
      hostname: '',
      display_name: '',
      description: '',
      policy_enabled: false,
      policy_mode: 'none',
      white_countries: [],
      block_countries: [],
      waf_threshold: 5,
      custom_ban_reason: '',
      enabled: true,
    })
    setEditingServer(null)
    setError(null)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    setError(null)

    try {
      if (mode === 'add') {
        await wafServersApi.create(formData)
      } else if (mode === 'edit' && editingServer) {
        await wafServersApi.update(editingServer.hostname, formData)
      }
      await fetchServers()
      onServersUpdated?.()
      setMode('list')
      resetForm()
    } catch (err: unknown) {
      console.error('Failed to save server:', err)
      const errorMessage = err instanceof Error ? err.message : 'Failed to save server'
      setError(errorMessage)
    } finally {
      setSaving(false)
    }
  }

  const openDeleteConfirm = (info: ServerInfo) => {
    setDeleteConfirm({
      hostname: info.hostname,
      displayName: info.displayName,
      deleteLogs: !info.isConfigured, // Default to delete logs for auto-discovered servers
      isConfigured: info.isConfigured,
    })
  }

  const handleDelete = async () => {
    if (!deleteConfirm) return

    setDeleting(true)
    try {
      await wafServersApi.delete(deleteConfirm.hostname, deleteConfirm.deleteLogs)
      await fetchServers()
      onServersUpdated?.()
      setDeleteConfirm(null)
    } catch (err) {
      console.error('Failed to delete server:', err)
      setError('Failed to delete server')
    } finally {
      setDeleting(false)
    }
  }

  const startEdit = (server: WAFMonitoredServer) => {
    setEditingServer(server)
    setFormData({
      hostname: server.hostname,
      display_name: server.display_name,
      description: server.description,
      policy_enabled: server.policy_enabled,
      policy_mode: server.policy_mode,
      white_countries: server.white_countries || [],
      block_countries: server.block_countries || [],
      waf_threshold: server.waf_threshold,
      custom_ban_reason: server.custom_ban_reason,
      enabled: server.enabled,
    })
    setMode('edit')
  }

  const startAdd = () => {
    resetForm()
    setMode('add')
  }

  if (!isOpen) return null

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 z-40"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="fixed inset-4 md:inset-auto md:left-1/2 md:top-1/2 md:-translate-x-1/2 md:-translate-y-1/2 md:w-[700px] md:max-h-[80vh] z-50 flex flex-col rounded-lg bg-gray-900 border border-gray-700 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
          <div className="flex items-center gap-2">
            <Server className="w-5 h-5 text-blue-400" />
            <h2 className="text-lg font-semibold text-white">
              {mode === 'list' && 'WAF Servers'}
              {mode === 'add' && 'Add Server'}
              {mode === 'edit' && 'Edit Server'}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {error && (
            <div className="mb-4 p-3 rounded bg-red-500/10 border border-red-500/30 text-red-400 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              {error}
            </div>
          )}

          {mode === 'list' && (
            <div className="space-y-4">
              {/* Add button */}
              <button
                onClick={startAdd}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg border border-dashed border-gray-600 text-gray-400 hover:text-white hover:border-blue-500 hover:bg-blue-500/10 transition-colors"
              >
                <Plus className="w-5 h-5" />
                Add New Server
              </button>

              {/* Server list */}
              {loading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
                </div>
              ) : allServers.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  No servers found (configured or discovered)
                </div>
              ) : (
                <div className="space-y-2">
                  {allServers.map((info) => (
                    <div
                      key={info.hostname}
                      className={cn(
                        "flex items-center gap-3 p-3 rounded-lg border",
                        info.isConfigured
                          ? "bg-gray-800 border-gray-700 hover:border-gray-600"
                          : "bg-gray-800/50 border-dashed border-gray-600 hover:border-gray-500"
                      )}
                    >
                      {/* Status indicator */}
                      <div
                        className={cn(
                          'w-2 h-2 rounded-full',
                          info.isConfigured
                            ? (info.server?.enabled ? 'bg-green-500' : 'bg-gray-500')
                            : 'bg-yellow-500'
                        )}
                        title={info.isConfigured ? 'Configured' : 'Auto-discovered (not configured)'}
                      />

                      {/* Server info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm text-white truncate">
                            {info.hostname}
                          </span>
                          {!info.isConfigured && (
                            <span className="px-1.5 py-0.5 rounded text-xs bg-yellow-500/20 text-yellow-400 flex items-center gap-1">
                              <Eye className="w-3 h-3" />
                              Discovered
                            </span>
                          )}
                          {info.server?.policy_enabled && (
                            <span
                              className={cn(
                                'px-1.5 py-0.5 rounded text-xs',
                                info.server.policy_mode === 'whitecountry'
                                  ? 'bg-green-500/20 text-green-400'
                                  : info.server.policy_mode === 'blockcountry'
                                  ? 'bg-red-500/20 text-red-400'
                                  : 'bg-gray-500/20 text-gray-400'
                              )}
                            >
                              {info.server.policy_mode === 'whitecountry' && 'Authorized'}
                              {info.server.policy_mode === 'blockcountry' && 'Hostile'}
                            </span>
                          )}
                        </div>
                        {info.server?.display_name && (
                          <div className="text-xs text-gray-500 truncate">
                            {info.server.display_name}
                          </div>
                        )}
                        {!info.isConfigured && (
                          <div className="text-xs text-gray-500 truncate">
                            Found in WAF logs - click + to configure
                          </div>
                        )}
                      </div>

                      {/* Policy icon */}
                      {info.isConfigured ? (
                        info.server?.policy_enabled ? (
                          <ShieldCheck className="w-5 h-5 text-green-500" />
                        ) : (
                          <ShieldOff className="w-5 h-5 text-gray-500" />
                        )
                      ) : (
                        <span title="Auto-discovered">
                          <Eye className="w-5 h-5 text-yellow-500" />
                        </span>
                      )}

                      {/* Actions */}
                      {info.isConfigured ? (
                        <button
                          onClick={() => info.server && startEdit(info.server)}
                          className="p-1.5 rounded hover:bg-gray-700 text-gray-400 hover:text-white"
                          title="Edit configuration"
                        >
                          <Settings className="w-4 h-4" />
                        </button>
                      ) : (
                        <button
                          onClick={() => {
                            setFormData({ ...formData, hostname: info.hostname })
                            setMode('add')
                          }}
                          className="p-1.5 rounded hover:bg-gray-700 text-gray-400 hover:text-green-400"
                          title="Configure this server"
                        >
                          <Plus className="w-4 h-4" />
                        </button>
                      )}
                      <button
                        onClick={() => openDeleteConfirm(info)}
                        className="p-1.5 rounded hover:bg-gray-700 text-gray-400 hover:text-red-400"
                        title={info.isConfigured ? "Delete server" : "Delete logs for this hostname"}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {(mode === 'add' || mode === 'edit') && (
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Basic info */}
              <div className="space-y-3">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Hostname *
                  </label>
                  <input
                    type="text"
                    value={formData.hostname}
                    onChange={(e) =>
                      setFormData({ ...formData, hostname: e.target.value })
                    }
                    placeholder="api.example.com"
                    className="w-full px-3 py-2 rounded bg-gray-800 border border-gray-700 text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                    required
                    disabled={mode === 'edit'}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Display Name
                  </label>
                  <input
                    type="text"
                    value={formData.display_name}
                    onChange={(e) =>
                      setFormData({ ...formData, display_name: e.target.value })
                    }
                    placeholder="API Server"
                    className="w-full px-3 py-2 rounded bg-gray-800 border border-gray-700 text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Description
                  </label>
                  <textarea
                    value={formData.description}
                    onChange={(e) =>
                      setFormData({ ...formData, description: e.target.value })
                    }
                    placeholder="Optional description..."
                    rows={2}
                    className="w-full px-3 py-2 rounded bg-gray-800 border border-gray-700 text-white focus:outline-none focus:ring-1 focus:ring-blue-500 resize-none"
                  />
                </div>
              </div>

              {/* Country Access Policy */}
              <div className="border-t border-gray-700 pt-4 mt-4">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Globe className="w-5 h-5 text-blue-400" />
                    <span className="font-medium text-white">Country Access Policy</span>
                  </div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.policy_enabled}
                      onChange={(e) =>
                        setFormData({ ...formData, policy_enabled: e.target.checked })
                      }
                      className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-300">Enabled</span>
                  </label>
                </div>

                {formData.policy_enabled && (
                  <div className="space-y-4 pl-4 border-l-2 border-blue-500/30">
                    {/* Policy mode */}
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Policy Mode
                      </label>
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() =>
                            setFormData({ ...formData, policy_mode: 'whitecountry' })
                          }
                          className={cn(
                            'flex-1 px-3 py-2 rounded border text-sm',
                            formData.policy_mode === 'whitecountry'
                              ? 'bg-green-500/20 border-green-500 text-green-400'
                              : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600'
                          )}
                        >
                          <ShieldCheck className="w-4 h-4 inline-block mr-1" />
                          Authorized
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            setFormData({ ...formData, policy_mode: 'blockcountry' })
                          }
                          className={cn(
                            'flex-1 px-3 py-2 rounded border text-sm',
                            formData.policy_mode === 'blockcountry'
                              ? 'bg-red-500/20 border-red-500 text-red-400'
                              : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600'
                          )}
                        >
                          <ShieldOff className="w-4 h-4 inline-block mr-1" />
                          Hostile
                        </button>
                      </div>
                      <p className="text-xs text-gray-500 mt-2">
                        {formData.policy_mode === 'whitecountry' &&
                          'Only authorized countries can access. All others will be banned immediately.'}
                        {formData.policy_mode === 'blockcountry' &&
                          'Hostile countries will be banned on first WAF detection.'}
                      </p>
                    </div>

                    {/* Country selector */}
                    {formData.policy_mode === 'whitecountry' && (
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                          Authorized Countries
                        </label>
                        <CountrySelector
                          selectedCountries={formData.white_countries || []}
                          onChange={(countries) =>
                            setFormData({ ...formData, white_countries: countries })
                          }
                          placeholder="Select authorized countries..."
                        />
                      </div>
                    )}

                    {formData.policy_mode === 'blockcountry' && (
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                          Hostile Countries
                        </label>
                        <CountrySelector
                          selectedCountries={formData.block_countries || []}
                          onChange={(countries) =>
                            setFormData({ ...formData, block_countries: countries })
                          }
                          placeholder="Select hostile countries..."
                        />
                      </div>
                    )}

                    {/* Custom ban reason */}
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-1">
                        Custom Ban Reason (optional)
                      </label>
                      <input
                        type="text"
                        value={formData.custom_ban_reason}
                        onChange={(e) =>
                          setFormData({ ...formData, custom_ban_reason: e.target.value })
                        }
                        placeholder="Leave empty for default reason"
                        className="w-full px-3 py-2 rounded bg-gray-800 border border-gray-700 text-white focus:outline-none focus:ring-1 focus:ring-blue-500 text-sm"
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* WAF Settings */}
              <div className="border-t border-gray-700 pt-4 mt-4">
                <div className="flex items-center gap-2 mb-3">
                  <Settings className="w-5 h-5 text-gray-400" />
                  <span className="font-medium text-white">WAF Settings</span>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    WAF Threshold (events before action)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={formData.waf_threshold}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        waf_threshold: parseInt(e.target.value) || 5,
                      })
                    }
                    className="w-32 px-3 py-2 rounded bg-gray-800 border border-gray-700 text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                </div>
              </div>

              {/* Server status */}
              <div className="border-t border-gray-700 pt-4 mt-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.enabled}
                    onChange={(e) =>
                      setFormData({ ...formData, enabled: e.target.checked })
                    }
                    className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-500 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-300">Server Enabled</span>
                </label>
              </div>
            </form>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-2 px-4 py-3 border-t border-gray-700 bg-gray-800/50">
          {mode === 'list' ? (
            <button
              onClick={onClose}
              className="px-4 py-2 rounded bg-gray-700 text-white hover:bg-gray-600"
            >
              Close
            </button>
          ) : (
            <>
              <button
                type="button"
                onClick={() => {
                  setMode('list')
                  resetForm()
                }}
                className="px-4 py-2 rounded bg-gray-700 text-white hover:bg-gray-600"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={saving || !formData.hostname}
                className="px-4 py-2 rounded bg-blue-600 text-white hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {saving && <Loader2 className="w-4 h-4 animate-spin" />}
                {mode === 'add' ? 'Add Server' : 'Save Changes'}
              </button>
            </>
          )}
        </div>
      </div>

      {/* Delete Confirmation Dialog */}
      {deleteConfirm && (
        <>
          <div
            className="fixed inset-0 bg-black/70 z-[60]"
            onClick={() => setDeleteConfirm(null)}
          />
          <div className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-[70] w-[450px] rounded-lg bg-gray-900 border border-gray-700 shadow-2xl">
            <div className="px-4 py-3 border-b border-gray-700">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Trash2 className="w-5 h-5 text-red-400" />
                {deleteConfirm.isConfigured ? 'Delete Server' : 'Delete WAF Logs'}
              </h3>
            </div>

            <div className="p-4 space-y-4">
              {deleteConfirm.isConfigured ? (
                <p className="text-gray-300">
                  Are you sure you want to delete{' '}
                  <span className="font-mono text-white">{deleteConfirm.displayName}</span>?
                </p>
              ) : (
                <div className="space-y-2">
                  <p className="text-gray-300">
                    <span className="font-mono text-white">{deleteConfirm.displayName}</span>{' '}
                    is an auto-discovered server (not configured).
                  </p>
                  <p className="text-sm text-yellow-400">
                    Deleting will remove all WAF logs for this hostname from the database.
                  </p>
                </div>
              )}

              {/* Log retention option - only for configured servers */}
              {deleteConfirm.isConfigured && (
                <div className="p-3 rounded-lg bg-gray-800 border border-gray-700 space-y-3">
                  <div className="flex items-start gap-2">
                    <FileText className="w-5 h-5 text-blue-400 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-white">WAF Logs</p>
                      <p className="text-xs text-gray-400">
                        Choose what to do with existing WAF logs for this server
                      </p>
                    </div>
                  </div>

                  <div className="space-y-2 pl-7">
                    <label className="flex items-start gap-2 cursor-pointer p-2 rounded hover:bg-gray-700/50">
                      <input
                        type="radio"
                        name="deleteLogs"
                        checked={!deleteConfirm.deleteLogs}
                        onChange={() =>
                          setDeleteConfirm({ ...deleteConfirm, deleteLogs: false })
                        }
                        className="mt-1 w-4 h-4 text-blue-500 border-gray-600 bg-gray-700 focus:ring-blue-500"
                      />
                      <div>
                        <span className="text-sm text-gray-200">Keep logs for 30 days</span>
                        <p className="text-xs text-gray-500 flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          Logs will be available if you re-add this server
                        </p>
                      </div>
                    </label>

                    <label className="flex items-start gap-2 cursor-pointer p-2 rounded hover:bg-gray-700/50">
                      <input
                        type="radio"
                        name="deleteLogs"
                        checked={deleteConfirm.deleteLogs}
                        onChange={() =>
                          setDeleteConfirm({ ...deleteConfirm, deleteLogs: true })
                        }
                        className="mt-1 w-4 h-4 text-red-500 border-gray-600 bg-gray-700 focus:ring-red-500"
                      />
                      <div>
                        <span className="text-sm text-gray-200">Delete logs immediately</span>
                        <p className="text-xs text-gray-500">
                          All WAF logs for this hostname will be permanently deleted
                        </p>
                      </div>
                    </label>
                  </div>
                </div>
              )}

              {deleteConfirm.deleteLogs && (
                <div className="p-2 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  <span>This action cannot be undone. All logs will be permanently deleted.</span>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 px-4 py-3 border-t border-gray-700 bg-gray-800/50">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 rounded bg-gray-700 text-white hover:bg-gray-600"
                disabled={deleting}
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                disabled={deleting}
                className={cn(
                  'px-4 py-2 rounded text-white flex items-center gap-2',
                  deleteConfirm.deleteLogs
                    ? 'bg-red-600 hover:bg-red-500'
                    : 'bg-orange-600 hover:bg-orange-500',
                  'disabled:opacity-50 disabled:cursor-not-allowed'
                )}
              >
                {deleting && <Loader2 className="w-4 h-4 animate-spin" />}
                {deleteConfirm.isConfigured
                  ? (deleteConfirm.deleteLogs ? 'Delete Server & Logs' : 'Delete Server')
                  : 'Delete Logs'
                }
              </button>
            </div>
          </div>
        </>
      )}
    </>
  )
}
