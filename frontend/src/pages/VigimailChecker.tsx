import { useState, useEffect, useCallback } from 'react'
import {
  Mail,
  RefreshCw,
  Plus,
  Trash2,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Eye,
  Shield,
  Settings,
  Loader2,
  Globe,
  Key,
  Clock,
  ChevronDown,
  ChevronRight,
  ExternalLink
} from 'lucide-react'
import { vigimailApi } from '@/lib/api'
import type {
  VigimailConfig,
  VigimailDomain,
  VigimailEmail,
  VigimailLeak,
  DomainDNSCheck,
  VigimailStatus,
  VigimailStats
} from '@/types'

// DNS Status badge component
function DNSStatusBadge({ check, compact = false }: { check: DomainDNSCheck | null; compact?: boolean }) {
  if (!check) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs bg-gray-700 text-gray-300">
        <Clock className="w-3 h-3" /> Pending
      </span>
    )
  }

  const statusColors = {
    good: 'bg-green-500/20 text-green-400 border-green-500/30',
    warning: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    unknown: 'bg-gray-500/20 text-gray-400 border-gray-500/30'
  }

  if (compact) {
    return (
      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs border ${statusColors[check.overall_status]}`}>
        {check.overall_status === 'good' && <CheckCircle className="w-3 h-3" />}
        {check.overall_status === 'warning' && <AlertTriangle className="w-3 h-3" />}
        {check.overall_status === 'critical' && <XCircle className="w-3 h-3" />}
        {check.overall_score}/100
      </span>
    )
  }

  return (
    <div className="flex gap-2 flex-wrap">
      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs ${check.spf_exists ? (check.spf_valid ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400') : 'bg-red-500/20 text-red-400'}`}>
        SPF {check.spf_exists ? (check.spf_valid ? '✓' : '⚠') : '✗'}
      </span>
      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs ${check.dkim_exists ? (check.dkim_valid ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400') : 'bg-red-500/20 text-red-400'}`}>
        DKIM {check.dkim_exists ? (check.dkim_valid ? '✓' : '⚠') : '✗'}
      </span>
      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs ${check.dmarc_exists ? (check.dmarc_valid ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400') : 'bg-red-500/20 text-red-400'}`}>
        DMARC {check.dmarc_exists ? (check.dmarc_valid ? '✓' : '⚠') : '✗'}
      </span>
    </div>
  )
}

// Email status badge
function EmailStatusBadge({ status, leakCount }: { status: string; leakCount: number }) {
  if (status === 'pending') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs bg-gray-700 text-gray-300">
        <Clock className="w-3 h-3" /> Pending
      </span>
    )
  }
  if (status === 'clean' || leakCount === 0) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs bg-green-500/20 text-green-400 border border-green-500/30">
        <CheckCircle className="w-3 h-3" /> Clean
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs bg-red-500/20 text-red-400 border border-red-500/30">
      <AlertTriangle className="w-3 h-3" /> {leakCount} Leak{leakCount > 1 ? 's' : ''}
    </span>
  )
}

export function VigimailChecker() {
  // Data state
  const [domains, setDomains] = useState<VigimailDomain[]>([])
  const [emailsByDomain, setEmailsByDomain] = useState<Record<string, VigimailEmail[]>>({})
  const [dnsChecks, setDnsChecks] = useState<Record<string, DomainDNSCheck>>({})
  const [status, setStatus] = useState<VigimailStatus | null>(null)
  const [stats, setStats] = useState<VigimailStats | null>(null)
  const [config, setConfig] = useState<VigimailConfig | null>(null)

  // UI state
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set())
  const [error, setError] = useState<string | null>(null)

  // Modal state
  const [showAddDomain, setShowAddDomain] = useState(false)
  const [showAddEmail, setShowAddEmail] = useState<string | null>(null)
  const [showLeakDetails, setShowLeakDetails] = useState<{ email: string; leaks: VigimailLeak[] } | null>(null)
  const [showDNSDetails, setShowDNSDetails] = useState<DomainDNSCheck | null>(null)
  const [showConfig, setShowConfig] = useState(false)

  // Form state
  const [newDomain, setNewDomain] = useState('')
  const [newEmail, setNewEmail] = useState('')
  const [addingDomain, setAddingDomain] = useState(false)
  const [addingEmail, setAddingEmail] = useState(false)
  const [checkingAll, setCheckingAll] = useState(false)

  // Fetch all data
  const fetchData = useCallback(async () => {
    try {
      const [domainsRes, emailsRes, statusRes, statsRes, configRes] = await Promise.all([
        vigimailApi.listDomains(),
        vigimailApi.listEmails(),
        vigimailApi.getStatus(),
        vigimailApi.getStats(),
        vigimailApi.getConfig()
      ])

      setDomains(domainsRes.domains || [])
      setEmailsByDomain(emailsRes.emails_by_domain || {})
      setStatus(statusRes)
      setStats(statsRes)
      setConfig(configRes)

      // Expand all domains by default
      const allDomains = new Set((domainsRes.domains || []).map(d => d.domain))
      setExpandedDomains(allDomains)

      // Fetch DNS checks for each domain
      const dnsData: Record<string, DomainDNSCheck> = {}
      for (const domain of domainsRes.domains || []) {
        try {
          const dns = await vigimailApi.getDomainDNS(domain.domain)
          dnsData[domain.domain] = dns
        } catch {
          // DNS check not yet available
        }
      }
      setDnsChecks(dnsData)
    } catch (err) {
      console.error('Failed to fetch vigimail data:', err)
      setError('Failed to load data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  // Refresh handler
  const handleRefresh = async () => {
    setRefreshing(true)
    await fetchData()
    setRefreshing(false)
  }

  // Add domain
  const handleAddDomain = async () => {
    if (!newDomain.trim()) return
    setAddingDomain(true)
    try {
      await vigimailApi.addDomain(newDomain.trim())
      setNewDomain('')
      setShowAddDomain(false)
      await fetchData()
    } catch (err: unknown) {
      const error = err as { response?: { data?: { error?: string } } }
      setError(error.response?.data?.error || 'Failed to add domain')
    } finally {
      setAddingDomain(false)
    }
  }

  // Delete domain
  const handleDeleteDomain = async (domain: string) => {
    if (!confirm(`Delete domain "${domain}" and all associated emails?`)) return
    try {
      await vigimailApi.deleteDomain(domain)
      await fetchData()
    } catch {
      setError('Failed to delete domain')
    }
  }

  // Add email
  const handleAddEmail = async () => {
    if (!newEmail.trim() || !showAddEmail) return
    setAddingEmail(true)
    try {
      await vigimailApi.addEmail(newEmail.trim())
      setNewEmail('')
      setShowAddEmail(null)
      await fetchData()
    } catch (err: unknown) {
      const error = err as { response?: { data?: { error?: string } } }
      setError(error.response?.data?.error || 'Failed to add email')
    } finally {
      setAddingEmail(false)
    }
  }

  // Delete email
  const handleDeleteEmail = async (email: string) => {
    if (!confirm(`Delete email "${email}"?`)) return
    try {
      await vigimailApi.deleteEmail(email)
      await fetchData()
    } catch {
      setError('Failed to delete email')
    }
  }

  // View leaks
  const handleViewLeaks = async (email: string) => {
    try {
      const result = await vigimailApi.getEmailLeaks(email)
      setShowLeakDetails({ email, leaks: result.leaks })
    } catch {
      setError('Failed to fetch leaks')
    }
  }

  // Check domain DNS
  const handleCheckDomain = async (domain: string) => {
    try {
      const dns = await vigimailApi.checkDomain(domain)
      setDnsChecks(prev => ({ ...prev, [domain]: dns }))
    } catch {
      setError('Failed to check domain DNS')
    }
  }

  // Check email
  const handleCheckEmail = async (email: string) => {
    try {
      await vigimailApi.checkEmail(email)
      await fetchData()
    } catch {
      setError('Failed to check email')
    }
  }

  // Check all
  const handleCheckAll = async () => {
    setCheckingAll(true)
    try {
      await vigimailApi.checkAll()
      await fetchData()
    } catch {
      setError('Failed to run full check')
    } finally {
      setCheckingAll(false)
    }
  }

  // Toggle domain expansion
  const toggleDomain = (domain: string) => {
    setExpandedDomains(prev => {
      const next = new Set(prev)
      if (next.has(domain)) {
        next.delete(domain)
      } else {
        next.add(domain)
      }
      return next
    })
  }

  // Save config
  const handleSaveConfig = async (newConfig: Partial<VigimailConfig>) => {
    try {
      await vigimailApi.updateConfig(newConfig)
      await fetchData()
      setShowConfig(false)
    } catch {
      setError('Failed to save configuration')
    }
  }

  // v3.57.111: Helper to check if date is valid/real (not zero time or epoch)
  const isValidDate = (dateStr: string): boolean => {
    if (!dateStr) return false
    // Check for Go zero time and Unix epoch
    if (dateStr.startsWith('0001-01-01') || dateStr.startsWith('1970-01-01')) return false
    const date = new Date(dateStr)
    // Check for invalid date
    if (isNaN(date.getTime())) return false
    // Check if date is before year 2000 (likely invalid for this system)
    if (date.getFullYear() < 2000) return false
    return true
  }

  // Format date
  const formatDate = (dateStr: string) => {
    if (!isValidDate(dateStr)) return 'Never'
    const date = new Date(dateStr)
    return date.toLocaleString()
  }

  // Format relative time
  const formatRelative = (dateStr: string) => {
    if (!isValidDate(dateStr)) return 'Never'
    const date = new Date(dateStr)
    const now = new Date()
    const diff = now.getTime() - date.getTime()
    const hours = Math.floor(diff / (1000 * 60 * 60))
    if (hours < 1) return 'Just now'
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    return `${days}d ago`
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-teal-500" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Mail className="w-8 h-8 text-teal-500" />
          <div>
            <h1 className="text-2xl font-bold text-white">Vigimail Checker</h1>
            <p className="text-gray-400 text-sm">Email leak detection &amp; DNS security monitoring</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowConfig(true)}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white transition-colors"
          >
            <Settings className="w-4 h-4" /> Configure
          </button>
          <button
            onClick={handleCheckAll}
            disabled={checkingAll}
            className="flex items-center gap-2 px-4 py-2 bg-teal-600 hover:bg-teal-700 rounded-lg text-white transition-colors disabled:opacity-50"
          >
            {checkingAll ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
            Check All
          </button>
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <span className="text-red-400">{error}</span>
          <button onClick={() => setError(null)} className="ml-auto text-red-400 hover:text-red-300">
            <XCircle className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* Stats cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <Globe className="w-8 h-8 text-blue-400" />
            <div>
              <div className="text-2xl font-bold text-white">{stats?.total_domains || 0}</div>
              <div className="text-gray-400 text-sm">Domains</div>
            </div>
          </div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <Mail className="w-8 h-8 text-teal-400" />
            <div>
              <div className="text-2xl font-bold text-white">{stats?.total_emails || 0}</div>
              <div className="text-gray-400 text-sm">Emails Monitored</div>
            </div>
          </div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-8 h-8 text-red-400" />
            <div>
              <div className="text-2xl font-bold text-white">{stats?.total_leaks || 0}</div>
              <div className="text-gray-400 text-sm">Leaks Detected</div>
            </div>
          </div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <Clock className="w-8 h-8 text-purple-400" />
            <div>
              <div className="text-lg font-bold text-white">{formatRelative(status?.last_check || '')}</div>
              <div className="text-gray-400 text-sm">Last Check</div>
            </div>
          </div>
        </div>
      </div>

      {/* Status indicators */}
      <div className="flex items-center gap-4 text-sm">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${status?.hibp_configured ? 'bg-green-400' : 'bg-yellow-400'}`} />
          <span className="text-gray-400">HIBP: {status?.hibp_configured ? 'Configured' : 'Not configured'}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${status?.leakcheck_configured ? 'bg-green-400' : 'bg-yellow-400'}`} />
          <span className="text-gray-400">LeakCheck: {status?.leakcheck_configured ? 'Configured' : 'Active (Free)'}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${status?.worker_running ? 'bg-green-400 animate-pulse' : 'bg-gray-400'}`} />
          <span className="text-gray-400">Auto-check: {status?.worker_running ? `Every ${config?.check_interval_hours}h` : 'Disabled'}</span>
        </div>
        <button onClick={handleRefresh} disabled={refreshing} className="ml-auto text-gray-400 hover:text-white">
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Domains list */}
      <div className="space-y-4">
        {domains.map(domain => (
          <div key={domain.id} className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
            {/* Domain header */}
            <div className="flex items-center justify-between p-4 bg-gray-800/50">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => toggleDomain(domain.domain)}
                  className="text-gray-400 hover:text-white"
                >
                  {expandedDomains.has(domain.domain) ? (
                    <ChevronDown className="w-5 h-5" />
                  ) : (
                    <ChevronRight className="w-5 h-5" />
                  )}
                </button>
                <Globe className="w-5 h-5 text-blue-400" />
                <span className="font-semibold text-white">{domain.domain}</span>
                <DNSStatusBadge check={dnsChecks[domain.domain]} compact />
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleCheckDomain(domain.domain)}
                  className="p-2 text-gray-400 hover:text-teal-400 hover:bg-gray-700 rounded"
                  title="Check DNS"
                >
                  <Shield className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setShowDNSDetails(dnsChecks[domain.domain])}
                  disabled={!dnsChecks[domain.domain]}
                  className="p-2 text-gray-400 hover:text-blue-400 hover:bg-gray-700 rounded disabled:opacity-50"
                  title="View DNS Details"
                >
                  <Eye className="w-4 h-4" />
                </button>
                <button
                  onClick={() => {
                    setShowAddEmail(domain.domain)
                    setNewEmail(`@${domain.domain}`)
                  }}
                  className="flex items-center gap-1 px-3 py-1 bg-teal-600 hover:bg-teal-700 rounded text-sm text-white"
                >
                  <Plus className="w-4 h-4" /> Email
                </button>
                <button
                  onClick={() => handleDeleteDomain(domain.domain)}
                  className="p-2 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded"
                  title="Delete Domain"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* DNS Status */}
            {expandedDomains.has(domain.domain) && dnsChecks[domain.domain] && (
              <div className="px-4 py-2 border-t border-gray-700 bg-gray-850">
                <DNSStatusBadge check={dnsChecks[domain.domain]} />
              </div>
            )}

            {/* Emails */}
            {expandedDomains.has(domain.domain) && (
              <div className="border-t border-gray-700">
                {(emailsByDomain[domain.domain] || []).length === 0 ? (
                  <div className="p-4 text-center text-gray-500">
                    No emails added yet. Click "+ Email" to add one.
                  </div>
                ) : (
                  <table className="w-full">
                    <thead>
                      <tr className="text-left text-gray-400 text-sm border-b border-gray-700">
                        <th className="px-4 py-2">Email</th>
                        <th className="px-4 py-2">Status</th>
                        <th className="px-4 py-2">Last Check</th>
                        <th className="px-4 py-2 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(emailsByDomain[domain.domain] || []).map(email => (
                        <tr key={email.id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                          <td className="px-4 py-3">
                            <span className="text-white">{email.email}</span>
                          </td>
                          <td className="px-4 py-3">
                            <EmailStatusBadge status={email.status} leakCount={email.leak_count} />
                          </td>
                          <td className="px-4 py-3 text-gray-400 text-sm">
                            {formatRelative(email.last_check)}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <div className="flex items-center justify-end gap-1">
                              <button
                                onClick={() => handleCheckEmail(email.email)}
                                className="p-2 text-gray-400 hover:text-teal-400 hover:bg-gray-700 rounded"
                                title="Check Now"
                              >
                                <RefreshCw className="w-4 h-4" />
                              </button>
                              {email.leak_count > 0 && (
                                <button
                                  onClick={() => handleViewLeaks(email.email)}
                                  className="p-2 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded"
                                  title="View Leaks"
                                >
                                  <Eye className="w-4 h-4" />
                                </button>
                              )}
                              <button
                                onClick={() => handleDeleteEmail(email.email)}
                                className="p-2 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded"
                                title="Delete Email"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
          </div>
        ))}

        {/* Add domain button */}
        <button
          onClick={() => setShowAddDomain(true)}
          className="w-full p-4 border-2 border-dashed border-gray-700 hover:border-teal-500 rounded-lg text-gray-400 hover:text-teal-400 transition-colors flex items-center justify-center gap-2"
        >
          <Plus className="w-5 h-5" /> Add Domain
        </button>
      </div>

      {/* Add Domain Modal */}
      {showAddDomain && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md border border-gray-700">
            <h2 className="text-xl font-semibold text-white mb-4">Add Domain</h2>
            <input
              type="text"
              value={newDomain}
              onChange={e => setNewDomain(e.target.value)}
              placeholder="example.com"
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:border-teal-500 focus:outline-none"
              onKeyDown={e => e.key === 'Enter' && handleAddDomain()}
              autoFocus
            />
            <p className="text-gray-500 text-sm mt-2">
              DNS security check will be performed automatically after adding.
            </p>
            <div className="flex justify-end gap-3 mt-4">
              <button
                onClick={() => setShowAddDomain(false)}
                className="px-4 py-2 text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleAddDomain}
                disabled={addingDomain || !newDomain.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-teal-600 hover:bg-teal-700 rounded-lg text-white disabled:opacity-50"
              >
                {addingDomain ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                Add Domain
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Email Modal */}
      {showAddEmail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md border border-gray-700">
            <h2 className="text-xl font-semibold text-white mb-4">Add Email to {showAddEmail}</h2>
            <input
              type="email"
              value={newEmail}
              onChange={e => setNewEmail(e.target.value)}
              placeholder={`user@${showAddEmail}`}
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:border-teal-500 focus:outline-none"
              onKeyDown={e => e.key === 'Enter' && handleAddEmail()}
              autoFocus
            />
            <p className="text-gray-500 text-sm mt-2">
              Email will be checked for leaks immediately after adding.
            </p>
            <div className="flex justify-end gap-3 mt-4">
              <button
                onClick={() => setShowAddEmail(null)}
                className="px-4 py-2 text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleAddEmail}
                disabled={addingEmail || !newEmail.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-teal-600 hover:bg-teal-700 rounded-lg text-white disabled:opacity-50"
              >
                {addingEmail ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                Add Email
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Leak Details Modal */}
      {showLeakDetails && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl border border-gray-700 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-xl font-semibold text-white">Leak Details</h2>
                <p className="text-gray-400">{showLeakDetails.email}</p>
              </div>
              <button onClick={() => setShowLeakDetails(null)} className="text-gray-400 hover:text-white">
                <XCircle className="w-6 h-6" />
              </button>
            </div>

            {showLeakDetails.leaks.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                <CheckCircle className="w-12 h-12 mx-auto mb-2 text-green-500" />
                No leaks found for this email.
              </div>
            ) : (
              <div className="space-y-4">
                {showLeakDetails.leaks.map((leak, idx) => (
                  <div key={idx} className="bg-gray-900 rounded-lg p-4 border border-gray-700">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-2 mb-2">
                          <AlertTriangle className="w-5 h-5 text-red-400" />
                          <span className="font-semibold text-white">{leak.breach_name}</span>
                          {leak.is_verified && (
                            <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 text-xs rounded">Verified</span>
                          )}
                          {leak.is_sensitive && (
                            <span className="px-2 py-0.5 bg-red-500/20 text-red-400 text-xs rounded">Sensitive</span>
                          )}
                        </div>
                        <div className="text-gray-400 text-sm space-y-1">
                          <p>Source: <span className="text-white uppercase">{leak.source}</span></p>
                          {leak.breach_date && <p>Breach Date: <span className="text-white">{leak.breach_date}</span></p>}
                          <p>First Seen: <span className="text-white">{formatDate(leak.first_seen)}</span></p>
                        </div>
                      </div>
                    </div>
                    {leak.data_classes && leak.data_classes.length > 0 && (
                      <div className="mt-3 flex flex-wrap gap-2">
                        {leak.data_classes.map((dc, i) => (
                          <span key={i} className="px-2 py-1 bg-gray-800 text-gray-300 text-xs rounded">
                            {dc}
                          </span>
                        ))}
                      </div>
                    )}
                    {leak.description && (
                      <p className="mt-3 text-gray-500 text-sm">{leak.description}</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* DNS Details Modal */}
      {showDNSDetails && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl border border-gray-700 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-xl font-semibold text-white">DNS Security Check</h2>
                <p className="text-gray-400">{showDNSDetails.domain}</p>
              </div>
              <button onClick={() => setShowDNSDetails(null)} className="text-gray-400 hover:text-white">
                <XCircle className="w-6 h-6" />
              </button>
            </div>

            {/* Overall Score */}
            <div className="flex items-center justify-between mb-6 p-4 bg-gray-900 rounded-lg">
              <div>
                <div className="text-3xl font-bold text-white">{showDNSDetails.overall_score}/100</div>
                <div className="text-gray-400">Security Score</div>
              </div>
              <div className={`px-4 py-2 rounded-lg font-semibold ${
                showDNSDetails.overall_status === 'good' ? 'bg-green-500/20 text-green-400' :
                showDNSDetails.overall_status === 'warning' ? 'bg-yellow-500/20 text-yellow-400' :
                'bg-red-500/20 text-red-400'
              }`}>
                {showDNSDetails.overall_status.toUpperCase()}
              </div>
            </div>

            {/* SPF */}
            <div className="mb-4 p-4 bg-gray-900 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                {showDNSDetails.spf_exists ? (
                  showDNSDetails.spf_valid ? <CheckCircle className="w-5 h-5 text-green-400" /> : <AlertTriangle className="w-5 h-5 text-yellow-400" />
                ) : <XCircle className="w-5 h-5 text-red-400" />}
                <span className="font-semibold text-white">SPF Record</span>
              </div>
              {showDNSDetails.spf_record && (
                <code className="block p-2 bg-gray-800 rounded text-xs text-gray-300 overflow-x-auto">
                  {showDNSDetails.spf_record}
                </code>
              )}
              {showDNSDetails.spf_issues && showDNSDetails.spf_issues.length > 0 && (
                <ul className="mt-2 text-sm text-yellow-400">
                  {showDNSDetails.spf_issues.map((issue, i) => (
                    <li key={i} className="flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" /> {issue}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* DKIM */}
            <div className="mb-4 p-4 bg-gray-900 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                {showDNSDetails.dkim_exists ? (
                  showDNSDetails.dkim_valid ? <CheckCircle className="w-5 h-5 text-green-400" /> : <AlertTriangle className="w-5 h-5 text-yellow-400" />
                ) : <XCircle className="w-5 h-5 text-red-400" />}
                <span className="font-semibold text-white">DKIM Records</span>
              </div>
              {showDNSDetails.dkim_selectors && showDNSDetails.dkim_selectors.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {showDNSDetails.dkim_selectors.map((sel, i) => (
                    <span key={i} className="px-2 py-1 bg-gray-800 text-green-400 text-xs rounded">
                      {sel}._domainkey
                    </span>
                  ))}
                </div>
              )}
              {showDNSDetails.dkim_issues && showDNSDetails.dkim_issues.length > 0 && (
                <ul className="mt-2 text-sm text-yellow-400">
                  {showDNSDetails.dkim_issues.map((issue, i) => (
                    <li key={i} className="flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" /> {issue}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* DMARC */}
            <div className="mb-4 p-4 bg-gray-900 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                {showDNSDetails.dmarc_exists ? (
                  showDNSDetails.dmarc_valid ? <CheckCircle className="w-5 h-5 text-green-400" /> : <AlertTriangle className="w-5 h-5 text-yellow-400" />
                ) : <XCircle className="w-5 h-5 text-red-400" />}
                <span className="font-semibold text-white">DMARC Record</span>
                {showDNSDetails.dmarc_policy && (
                  <span className={`px-2 py-0.5 text-xs rounded ${
                    showDNSDetails.dmarc_policy === 'reject' ? 'bg-green-500/20 text-green-400' :
                    showDNSDetails.dmarc_policy === 'quarantine' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-red-500/20 text-red-400'
                  }`}>
                    p={showDNSDetails.dmarc_policy}
                  </span>
                )}
              </div>
              {showDNSDetails.dmarc_record && (
                <code className="block p-2 bg-gray-800 rounded text-xs text-gray-300 overflow-x-auto">
                  {showDNSDetails.dmarc_record}
                </code>
              )}
              {showDNSDetails.dmarc_issues && showDNSDetails.dmarc_issues.length > 0 && (
                <ul className="mt-2 text-sm text-yellow-400">
                  {showDNSDetails.dmarc_issues.map((issue, i) => (
                    <li key={i} className="flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" /> {issue}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* MX Records */}
            <div className="p-4 bg-gray-900 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                {showDNSDetails.mx_exists ? <CheckCircle className="w-5 h-5 text-green-400" /> : <XCircle className="w-5 h-5 text-red-400" />}
                <span className="font-semibold text-white">MX Records</span>
              </div>
              {showDNSDetails.mx_records && showDNSDetails.mx_records.length > 0 && (
                <ul className="space-y-1">
                  {showDNSDetails.mx_records.map((mx, i) => (
                    <li key={i} className="text-gray-300 text-sm font-mono">{mx}</li>
                  ))}
                </ul>
              )}
            </div>

            <div className="mt-4 text-right text-gray-500 text-sm">
              Last checked: {formatDate(showDNSDetails.check_time)}
            </div>
          </div>
        </div>
      )}

      {/* Configuration Modal */}
      {showConfig && config && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-lg border border-gray-700">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold text-white">Vigimail Configuration</h2>
              <button onClick={() => setShowConfig(false)} className="text-gray-400 hover:text-white">
                <XCircle className="w-6 h-6" />
              </button>
            </div>

            <ConfigForm config={config} onSave={handleSaveConfig} onCancel={() => setShowConfig(false)} />
          </div>
        </div>
      )}
    </div>
  )
}

// Config form component
function ConfigForm({
  config,
  onSave,
  onCancel
}: {
  config: VigimailConfig
  onSave: (config: Partial<VigimailConfig>) => void
  onCancel: () => void
}) {
  const [enabled, setEnabled] = useState(config.enabled)
  const [checkInterval, setCheckInterval] = useState(config.check_interval_hours)
  const [hibpKey, setHibpKey] = useState('')
  const [leakcheckKey, setLeakcheckKey] = useState('')
  const [saving, setSaving] = useState(false)
  // v3.57.119: HIBP API key test state
  const [testingHibp, setTestingHibp] = useState(false)
  const [hibpTestResult, setHibpTestResult] = useState<{ success: boolean; message: string } | null>(null)

  // v3.57.119: Test HIBP API key before saving
  const handleTestHibpKey = async () => {
    const keyToTest = hibpKey || config.hibp_api_key
    if (!keyToTest || keyToTest.includes('****')) {
      setHibpTestResult({ success: false, message: 'Please enter a valid API key' })
      return
    }

    setTestingHibp(true)
    setHibpTestResult(null)

    try {
      const response = await fetch('/api/v1/vigimail/test-hibp', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ api_key: keyToTest })
      })

      const data = await response.json()
      if (response.ok && data.success) {
        setHibpTestResult({ success: true, message: 'API key is valid!' })
      } else {
        setHibpTestResult({ success: false, message: data.error || 'API key test failed' })
      }
    } catch {
      setHibpTestResult({ success: false, message: 'Connection error' })
    } finally {
      setTestingHibp(false)
    }
  }

  const handleSave = async () => {
    // v3.57.119: If HIBP key was changed, require successful test first
    const hibpKeyChanged = hibpKey && !hibpKey.includes('****')
    if (hibpKeyChanged && (!hibpTestResult || !hibpTestResult.success)) {
      setHibpTestResult({ success: false, message: 'Please test the API key before saving' })
      return
    }

    setSaving(true)
    const updates: Partial<VigimailConfig> = {
      enabled,
      check_interval_hours: checkInterval
    }
    if (hibpKey && !hibpKey.includes('****')) {
      updates.hibp_api_key = hibpKey
    }
    if (leakcheckKey && !leakcheckKey.includes('****')) {
      updates.leakcheck_api_key = leakcheckKey
    }
    await onSave(updates)
    setSaving(false)
  }

  return (
    <div className="space-y-4">
      {/* Enable toggle */}
      <div className="flex items-center justify-between p-3 bg-gray-900 rounded-lg">
        <div>
          <div className="font-semibold text-white">Enable Auto-Check</div>
          <div className="text-gray-500 text-sm">Automatically check emails on schedule</div>
        </div>
        <button
          onClick={() => setEnabled(!enabled)}
          className={`relative w-12 h-6 rounded-full transition-colors ${enabled ? 'bg-teal-600' : 'bg-gray-700'}`}
        >
          <span className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${enabled ? 'left-7' : 'left-1'}`} />
        </button>
      </div>

      {/* Check interval */}
      <div className="p-3 bg-gray-900 rounded-lg">
        <div className="font-semibold text-white mb-2">Check Interval</div>
        <select
          value={checkInterval}
          onChange={e => setCheckInterval(parseInt(e.target.value))}
          className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
        >
          <option value={6}>Every 6 hours</option>
          <option value={12}>Every 12 hours</option>
          <option value={24}>Every 24 hours</option>
          <option value={48}>Every 48 hours</option>
          <option value={168}>Every 7 days</option>
        </select>
      </div>

      {/* HIBP API Key - v3.57.119: Added Test & Save functionality */}
      <div className="p-3 bg-gray-900 rounded-lg">
        <div className="flex items-center gap-2 mb-2">
          <Key className="w-4 h-4 text-purple-400" />
          <span className="font-semibold text-white">HaveIBeenPwned API Key</span>
          <a href="https://haveibeenpwned.com/API/Key" target="_blank" rel="noopener noreferrer" className="text-gray-500 hover:text-white">
            <ExternalLink className="w-4 h-4" />
          </a>
        </div>
        <div className="flex gap-2">
          <input
            type="password"
            value={hibpKey || config.hibp_api_key}
            onChange={e => {
              setHibpKey(e.target.value)
              setHibpTestResult(null) // Reset test result when key changes
            }}
            placeholder="Enter HIBP API key (paid, $3.50/month)"
            className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500"
          />
          <button
            onClick={handleTestHibpKey}
            disabled={testingHibp || (!hibpKey && !config.hibp_api_key)}
            className="px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-700 disabled:opacity-50 rounded-lg text-white text-sm font-medium flex items-center gap-2 transition-colors"
          >
            {testingHibp ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Testing...
              </>
            ) : (
              <>
                <CheckCircle className="w-4 h-4" />
                Test Key
              </>
            )}
          </button>
        </div>
        {/* Test result message */}
        {hibpTestResult && (
          <div className={`mt-2 p-2 rounded-lg text-sm flex items-center gap-2 ${
            hibpTestResult.success
              ? 'bg-green-500/10 border border-green-500/30 text-green-400'
              : 'bg-red-500/10 border border-red-500/30 text-red-400'
          }`}>
            {hibpTestResult.success ? (
              <CheckCircle className="w-4 h-4" />
            ) : (
              <AlertTriangle className="w-4 h-4" />
            )}
            {hibpTestResult.message}
          </div>
        )}
        <p className="text-gray-500 text-xs mt-1">Required for breach detection. Test your key before saving.</p>
      </div>

      {/* LeakCheck API Key */}
      <div className="p-3 bg-gray-900 rounded-lg">
        <div className="flex items-center gap-2 mb-2">
          <Key className="w-4 h-4 text-green-400" />
          <span className="font-semibold text-white">LeakCheck API Key</span>
          <span className="text-green-400 text-xs">(Optional)</span>
        </div>
        <input
          type="password"
          value={leakcheckKey || config.leakcheck_api_key}
          onChange={e => setLeakcheckKey(e.target.value)}
          placeholder="Enter LeakCheck API key (optional, for higher limits)"
          className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500"
        />
        <p className="text-gray-500 text-xs mt-1">Works without API key (10 req/day free). Key increases limits.</p>
      </div>

      {/* Actions */}
      <div className="flex justify-end gap-3 pt-4">
        <button onClick={onCancel} className="px-4 py-2 text-gray-400 hover:text-white">
          Cancel
        </button>
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 px-4 py-2 bg-teal-600 hover:bg-teal-700 rounded-lg text-white disabled:opacity-50"
        >
          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
          Save Configuration
        </button>
      </div>
    </div>
  )
}

export default VigimailChecker
