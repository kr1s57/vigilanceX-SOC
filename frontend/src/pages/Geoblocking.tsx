import { useState, useEffect } from 'react'
import { Globe, Shield, Eye, AlertTriangle, Plus, Trash2, Search, RefreshCw, MapPin } from 'lucide-react'
import { geoblockingApi } from '@/lib/api'
import { getCountryFlag, getCountryName } from '@/lib/utils'
import type { GeoBlockRule, GeoBlockStats, GeoCheckResult, HighRiskCountry, GeoLocation } from '@/types'

export function Geoblocking() {
  const [stats, setStats] = useState<GeoBlockStats | null>(null)
  const [rules, setRules] = useState<GeoBlockRule[]>([])
  const [highRiskCountries, setHighRiskCountries] = useState<HighRiskCountry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Form states
  const [showAddModal, setShowAddModal] = useState(false)
  const [newRule, setNewRule] = useState({
    rule_type: 'country_watch',
    target: '',
    action: 'watch',
    score_modifier: 25,
    reason: ''
  })
  const [formError, setFormError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  // IP Lookup states
  const [lookupIP, setLookupIP] = useState('')
  const [lookupResult, setLookupResult] = useState<GeoCheckResult | null>(null)
  const [lookupLoading, setLookupLoading] = useState(false)

  // GeoIP Lookup states
  const [geoLookupIP, setGeoLookupIP] = useState('')
  const [geoLookupResult, setGeoLookupResult] = useState<GeoLocation | null>(null)
  const [geoLookupLoading, setGeoLookupLoading] = useState(false)

  const fetchData = async () => {
    try {
      setLoading(true)
      const [statsRes, rulesRes, highRiskRes] = await Promise.all([
        geoblockingApi.getStats(),
        geoblockingApi.listRules(),
        geoblockingApi.getHighRiskCountries()
      ])
      setStats(statsRes)
      setRules(rulesRes.data || [])
      setHighRiskCountries(highRiskRes.high_risk_countries || [])
      setError(null)
    } catch (err) {
      setError('Failed to load geoblocking data')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleAddRule = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newRule.target.trim()) {
      setFormError('Target is required')
      return
    }

    try {
      setSaving(true)
      setFormError(null)
      await geoblockingApi.createRule({
        rule_type: newRule.rule_type,
        target: newRule.target.toUpperCase(),
        action: newRule.action,
        score_modifier: newRule.score_modifier,
        reason: newRule.reason
      })
      await fetchData()
      setShowAddModal(false)
      setNewRule({
        rule_type: 'country_watch',
        target: '',
        action: 'watch',
        score_modifier: 25,
        reason: ''
      })
    } catch (err: any) {
      setFormError(err.response?.data?.error || 'Failed to create rule')
    } finally {
      setSaving(false)
    }
  }

  const handleDeleteRule = async (id: string) => {
    if (!confirm('Delete this rule?')) return
    try {
      await geoblockingApi.deleteRule(id)
      await fetchData()
    } catch (err) {
      console.error('Failed to delete rule:', err)
    }
  }

  const handleCheckIP = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!lookupIP.trim()) return

    try {
      setLookupLoading(true)
      const result = await geoblockingApi.checkIP(lookupIP.trim())
      setLookupResult(result)
    } catch (err) {
      console.error('Failed to check IP:', err)
      setLookupResult(null)
    } finally {
      setLookupLoading(false)
    }
  }

  const handleGeoLookup = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!geoLookupIP.trim()) return

    try {
      setGeoLookupLoading(true)
      const result = await geoblockingApi.lookupIP(geoLookupIP.trim())
      setGeoLookupResult(result)
    } catch (err) {
      console.error('Failed to lookup IP:', err)
      setGeoLookupResult(null)
    } finally {
      setGeoLookupLoading(false)
    }
  }

  const handleRefreshCache = async () => {
    try {
      await geoblockingApi.refreshCache()
      await fetchData()
    } catch (err) {
      console.error('Failed to refresh cache:', err)
    }
  }

  const getRuleTypeLabel = (type: string) => {
    switch (type) {
      case 'country_block': return 'Country Block'
      case 'country_watch': return 'Country Watch'
      case 'asn_block': return 'ASN Block'
      case 'asn_watch': return 'ASN Watch'
      default: return type
    }
  }

  const getRuleTypeColor = (type: string) => {
    if (type.includes('block')) return 'bg-red-500/20 text-red-400'
    return 'bg-yellow-500/20 text-yellow-400'
  }

  const getActionColor = (action: string) => {
    switch (action) {
      case 'block': return 'text-red-400'
      case 'watch': return 'text-yellow-400'
      case 'boost': return 'text-orange-400'
      default: return 'text-gray-400'
    }
  }

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-400 bg-red-500/20'
      case 'high': return 'text-orange-400 bg-orange-500/20'
      case 'medium': return 'text-yellow-400 bg-yellow-500/20'
      default: return 'text-gray-400 bg-gray-500/20'
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Globe className="h-7 w-7 text-blue-400" />
            Geoblocking
          </h1>
          <p className="text-gray-400 mt-1">Manage geographic blocking rules and IP geolocation</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleRefreshCache}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh Cache
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg text-white transition-colors"
          >
            <Plus className="h-4 w-4" />
            Add Rule
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400">
          {error}
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/20 rounded-lg">
              <Shield className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Total Rules</p>
              <p className="text-2xl font-bold text-white">{stats?.total_rules || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/20 rounded-lg">
              <Eye className="h-5 w-5 text-green-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Active Rules</p>
              <p className="text-2xl font-bold text-white">{stats?.active_rules || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-500/20 rounded-lg">
              <AlertTriangle className="h-5 w-5 text-red-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Blocked Countries</p>
              <p className="text-2xl font-bold text-white">{stats?.blocked_countries?.length || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-500/20 rounded-lg">
              <Eye className="h-5 w-5 text-yellow-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Watched Countries</p>
              <p className="text-2xl font-bold text-white">{stats?.watched_countries?.length || 0}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Rules List */}
        <div className="lg:col-span-2 bg-gray-800 rounded-lg border border-gray-700">
          <div className="p-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">Active Rules</h2>
          </div>
          <div className="divide-y divide-gray-700 max-h-[500px] overflow-y-auto">
            {rules.length === 0 ? (
              <div className="p-8 text-center text-gray-400">
                No rules configured. Click "Add Rule" to create one.
              </div>
            ) : (
              rules.map((rule) => (
                <div key={rule.id} className="p-4 hover:bg-gray-750 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getRuleTypeColor(rule.rule_type)}`}>
                        {getRuleTypeLabel(rule.rule_type)}
                      </span>
                      <span className="text-white font-mono flex items-center gap-2">
                        {rule.rule_type.includes('country') && (
                          <span>{getCountryFlag(rule.target)}</span>
                        )}
                        {rule.target}
                        {rule.rule_type.includes('country') && (
                          <span className="text-gray-400 text-sm">({getCountryName(rule.target)})</span>
                        )}
                      </span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className={`text-sm font-medium ${getActionColor(rule.action)}`}>
                        {rule.action.toUpperCase()}
                      </span>
                      <span className="text-gray-400 text-sm">
                        +{rule.score_modifier} pts
                      </span>
                      <button
                        onClick={() => handleDeleteRule(rule.id)}
                        className="p-1 text-gray-400 hover:text-red-400 transition-colors"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                  {rule.reason && (
                    <p className="text-gray-400 text-sm mt-2">{rule.reason}</p>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          {/* IP Check */}
          <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Search className="h-5 w-5 text-blue-400" />
              Check IP Against Rules
            </h3>
            <form onSubmit={handleCheckIP} className="space-y-3">
              <input
                type="text"
                value={lookupIP}
                onChange={(e) => setLookupIP(e.target.value)}
                placeholder="Enter IP address..."
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
              />
              <button
                type="submit"
                disabled={lookupLoading}
                className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 rounded-lg text-white transition-colors"
              >
                {lookupLoading ? 'Checking...' : 'Check IP'}
              </button>
            </form>
            {lookupResult && (
              <div className="mt-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Country:</span>
                  <span className="text-white">
                    {lookupResult.geo_location && (
                      <>
                        {getCountryFlag(lookupResult.geo_location.country_code)}{' '}
                        {lookupResult.geo_location.country_name}
                      </>
                    )}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Score Boost:</span>
                  <span className={lookupResult.total_score_boost > 0 ? 'text-orange-400' : 'text-green-400'}>
                    +{lookupResult.total_score_boost}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Should Block:</span>
                  <span className={lookupResult.should_block ? 'text-red-400' : 'text-green-400'}>
                    {lookupResult.should_block ? 'YES' : 'NO'}
                  </span>
                </div>
                {lookupResult.matched_rules.length > 0 && (
                  <div className="mt-2">
                    <span className="text-gray-400 text-sm">Matched Rules:</span>
                    <div className="mt-1 space-y-1">
                      {lookupResult.matched_rules.map((rule) => (
                        <div key={rule.id} className="text-xs bg-gray-700 rounded px-2 py-1">
                          {getRuleTypeLabel(rule.rule_type)} - {rule.target}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* GeoIP Lookup */}
          <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <MapPin className="h-5 w-5 text-green-400" />
              GeoIP Lookup
            </h3>
            <form onSubmit={handleGeoLookup} className="space-y-3">
              <input
                type="text"
                value={geoLookupIP}
                onChange={(e) => setGeoLookupIP(e.target.value)}
                placeholder="Enter IP address..."
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-green-500"
              />
              <button
                type="submit"
                disabled={geoLookupLoading}
                className="w-full px-4 py-2 bg-green-600 hover:bg-green-500 disabled:bg-gray-600 rounded-lg text-white transition-colors"
              >
                {geoLookupLoading ? 'Looking up...' : 'Lookup'}
              </button>
            </form>
            {geoLookupResult && (
              <div className="mt-4 space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Country:</span>
                  <span className="text-white">
                    {getCountryFlag(geoLookupResult.country_code)} {geoLookupResult.country_name}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">City:</span>
                  <span className="text-white">{geoLookupResult.city || '-'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">ASN:</span>
                  <span className="text-white">{geoLookupResult.asn || '-'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Organization:</span>
                  <span className="text-white truncate ml-2">{geoLookupResult.as_org || '-'}</span>
                </div>
                <div className="flex flex-wrap gap-2 mt-2">
                  {geoLookupResult.is_vpn && (
                    <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">VPN</span>
                  )}
                  {geoLookupResult.is_proxy && (
                    <span className="px-2 py-1 bg-orange-500/20 text-orange-400 rounded text-xs">Proxy</span>
                  )}
                  {geoLookupResult.is_tor && (
                    <span className="px-2 py-1 bg-red-500/20 text-red-400 rounded text-xs">Tor</span>
                  )}
                  {geoLookupResult.is_datacenter && (
                    <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs">Datacenter</span>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* High Risk Countries */}
          <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              High Risk Countries
            </h3>
            <div className="space-y-2">
              {highRiskCountries.map((country) => (
                <div key={country.country_code} className="flex items-center justify-between py-2 border-b border-gray-700 last:border-0">
                  <div className="flex items-center gap-2">
                    <span>{getCountryFlag(country.country_code)}</span>
                    <span className="text-white">{country.country_name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${getRiskColor(country.risk_level)}`}>
                      {country.risk_level}
                    </span>
                    <span className="text-gray-400 text-sm">+{country.base_score}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Add Rule Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md border border-gray-700">
            <h3 className="text-xl font-bold text-white mb-4">Add Geoblocking Rule</h3>
            <form onSubmit={handleAddRule} className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Rule Type</label>
                <select
                  value={newRule.rule_type}
                  onChange={(e) => setNewRule({ ...newRule, rule_type: e.target.value })}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="country_watch">Country Watch</option>
                  <option value="country_block">Country Block</option>
                  <option value="asn_watch">ASN Watch</option>
                  <option value="asn_block">ASN Block</option>
                </select>
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-1">
                  {newRule.rule_type.includes('country') ? 'Country Code (e.g., RU, CN)' : 'ASN Number'}
                </label>
                <input
                  type="text"
                  value={newRule.target}
                  onChange={(e) => setNewRule({ ...newRule, target: e.target.value })}
                  placeholder={newRule.rule_type.includes('country') ? 'RU' : '12345'}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-1">Action</label>
                <select
                  value={newRule.action}
                  onChange={(e) => setNewRule({ ...newRule, action: e.target.value })}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="watch">Watch (Score boost only)</option>
                  <option value="block">Block (Auto-ban)</option>
                  <option value="boost">Boost (Increase score)</option>
                </select>
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-1">Score Modifier (+points)</label>
                <input
                  type="number"
                  value={newRule.score_modifier}
                  onChange={(e) => setNewRule({ ...newRule, score_modifier: parseInt(e.target.value) || 0 })}
                  min="0"
                  max="100"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-1">Reason (optional)</label>
                <input
                  type="text"
                  value={newRule.reason}
                  onChange={(e) => setNewRule({ ...newRule, reason: e.target.value })}
                  placeholder="High threat activity from this region"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                />
              </div>

              {formError && (
                <div className="text-red-400 text-sm">{formError}</div>
              )}

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 rounded-lg text-white transition-colors"
                >
                  {saving ? 'Creating...' : 'Create Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
