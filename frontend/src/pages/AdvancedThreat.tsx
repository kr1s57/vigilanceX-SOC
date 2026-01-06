import { useState, useEffect, useMemo } from 'react'
import {
  AlertTriangle,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Globe,
  Search,
  RefreshCw,
  ExternalLink,
  CheckCircle,
  XCircle,
  Loader2,
  Eye,
  X,
} from 'lucide-react'
import { threatsApi } from '@/lib/api'
import { StatCard } from '@/components/dashboard/StatCard'
import { formatNumber, getCountryFlag, formatDateTime, cn } from '@/lib/utils'
import type { ThreatScore, ThreatStats, ThreatProvider } from '@/types'

// Threat level colors
const threatLevelColors: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-500', border: 'border-red-500/30' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-500', border: 'border-orange-500/30' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-500', border: 'border-yellow-500/30' },
  low: { bg: 'bg-blue-500/10', text: 'text-blue-500', border: 'border-blue-500/30' },
  minimal: { bg: 'bg-green-500/10', text: 'text-green-500', border: 'border-green-500/30' },
  none: { bg: 'bg-gray-500/10', text: 'text-gray-500', border: 'border-gray-500/30' },
}

// IP Details Modal
function IPDetailsModal({
  ip,
  isOpen,
  onClose,
}: {
  ip: string | null
  isOpen: boolean
  onClose: () => void
}) {
  const [score, setScore] = useState<ThreatScore | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [checking, setChecking] = useState(false)

  useEffect(() => {
    if (isOpen && ip) {
      setLoading(true)
      setError(null)
      threatsApi.score(ip)
        .then(data => setScore(data))
        .catch(() => setError('Score not found in database'))
        .finally(() => setLoading(false))
    }
  }, [isOpen, ip])

  const handleRefreshCheck = async () => {
    if (!ip) return
    setChecking(true)
    try {
      const data = await threatsApi.check(ip)
      setScore(data)
      setError(null)
    } catch {
      setError('Failed to check IP')
    } finally {
      setChecking(false)
    }
  }

  if (!isOpen || !ip) return null

  const colors = score ? threatLevelColors[score.threat_level] || threatLevelColors.none : threatLevelColors.none

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-card border rounded-xl shadow-2xl w-full max-w-2xl max-h-[85vh] overflow-hidden m-4">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b">
          <div className="flex items-center gap-3">
            <div className={cn('p-2 rounded-lg', colors.bg)}>
              <ShieldAlert className={cn('w-5 h-5', colors.text)} />
            </div>
            <div>
              <h2 className="text-lg font-semibold font-mono">{ip}</h2>
              <p className="text-sm text-muted-foreground">
                {score?.country && (
                  <span className="inline-flex items-center gap-1">
                    {getCountryFlag(score.country)} {score.country}
                    {score.isp && <span> - {score.isp}</span>}
                  </span>
                )}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleRefreshCheck}
              disabled={checking}
              className="p-2 hover:bg-muted rounded-lg transition-colors"
              title="Re-check with threat intel providers"
            >
              {checking ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                <RefreshCw className="w-5 h-5" />
              )}
            </button>
            <button onClick={onClose} className="p-2 hover:bg-muted rounded-lg transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto max-h-[calc(85vh-120px)] p-4 space-y-4">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : error && !score ? (
            <div className="text-center py-8">
              <p className="text-muted-foreground mb-4">{error}</p>
              <button
                onClick={handleRefreshCheck}
                disabled={checking}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-lg"
              >
                {checking ? 'Checking...' : 'Check with Threat Intel'}
              </button>
            </div>
          ) : score ? (
            <>
              {/* Score Overview */}
              <div className={cn('rounded-lg border p-4', colors.border, colors.bg)}>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Aggregated Threat Score</p>
                    <p className={cn('text-4xl font-bold', colors.text)}>
                      {score.aggregated_score}
                    </p>
                  </div>
                  <div className="text-right">
                    <span className={cn(
                      'inline-flex items-center gap-1 px-3 py-1.5 rounded-full text-sm font-medium',
                      colors.bg, colors.text
                    )}>
                      {score.threat_level.toUpperCase()}
                    </span>
                    <p className="text-xs text-muted-foreground mt-1">
                      Confidence: {(score.confidence * 100).toFixed(0)}%
                    </p>
                  </div>
                </div>
              </div>

              {/* Provider Scores */}
              <div className="grid grid-cols-3 gap-4">
                <div className="bg-muted/50 rounded-lg p-4 text-center">
                  <p className="text-xs text-muted-foreground mb-1">AbuseIPDB</p>
                  <p className={cn(
                    'text-2xl font-bold',
                    score.abuseipdb_score >= 50 ? 'text-red-500' : 'text-green-500'
                  )}>
                    {score.abuseipdb_score}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {score.abuseipdb_reports} reports
                  </p>
                </div>
                <div className="bg-muted/50 rounded-lg p-4 text-center">
                  <p className="text-xs text-muted-foreground mb-1">VirusTotal</p>
                  <p className={cn(
                    'text-2xl font-bold',
                    score.virustotal_score >= 50 ? 'text-red-500' : 'text-green-500'
                  )}>
                    {score.virustotal_score}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {score.virustotal_positives}/{score.virustotal_total} engines
                  </p>
                </div>
                <div className="bg-muted/50 rounded-lg p-4 text-center">
                  <p className="text-xs text-muted-foreground mb-1">AlienVault OTX</p>
                  <p className={cn(
                    'text-2xl font-bold',
                    score.otx_score >= 50 ? 'text-red-500' : 'text-green-500'
                  )}>
                    {score.otx_score}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {score.alienvault_pulses} pulses
                  </p>
                </div>
              </div>

              {/* Details */}
              <div className="space-y-3">
                {/* Badges */}
                <div className="flex flex-wrap gap-2">
                  {score.is_tor && (
                    <span className="inline-flex items-center gap-1 px-2 py-1 text-xs rounded-full bg-purple-500/10 text-purple-500">
                      <Globe className="w-3 h-3" />
                      Tor Exit Node
                    </span>
                  )}
                  {score.is_malicious && (
                    <span className="inline-flex items-center gap-1 px-2 py-1 text-xs rounded-full bg-red-500/10 text-red-500">
                      <ShieldOff className="w-3 h-3" />
                      Malicious
                    </span>
                  )}
                  {score.total_attacks > 0 && (
                    <span className="inline-flex items-center gap-1 px-2 py-1 text-xs rounded-full bg-orange-500/10 text-orange-500">
                      <AlertTriangle className="w-3 h-3" />
                      {score.total_attacks} attacks
                    </span>
                  )}
                </div>

                {/* Tags */}
                {score.tags && score.tags.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Tags</p>
                    <div className="flex flex-wrap gap-1">
                      {score.tags.slice(0, 20).map((tag, i) => (
                        <span key={i} className="px-2 py-0.5 text-xs bg-muted rounded">
                          {tag}
                        </span>
                      ))}
                      {score.tags.length > 20 && (
                        <span className="text-xs text-muted-foreground">
                          +{score.tags.length - 20} more
                        </span>
                      )}
                    </div>
                  </div>
                )}

                {/* Network Info */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-xs text-muted-foreground">ASN</p>
                    <p className="font-mono truncate" title={score.asn}>{score.asn || '-'}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">ISP</p>
                    <p className="truncate" title={score.isp}>{score.isp || '-'}</p>
                  </div>
                </div>

                {/* Timestamps */}
                <div className="grid grid-cols-2 gap-4 text-sm border-t pt-3">
                  <div>
                    <p className="text-xs text-muted-foreground">Last Checked</p>
                    <p>{formatDateTime(score.last_checked)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">First Seen</p>
                    <p>{score.first_seen !== '0001-01-01T00:00:00Z' ? formatDateTime(score.first_seen) : '-'}</p>
                  </div>
                </div>
              </div>

              {/* External Links */}
              <div className="flex gap-2 pt-2 border-t">
                <a
                  href={`https://www.abuseipdb.com/check/${ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 text-center py-2 text-sm bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                >
                  AbuseIPDB <ExternalLink className="inline w-3 h-3 ml-1" />
                </a>
                <a
                  href={`https://www.virustotal.com/gui/ip-address/${ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 text-center py-2 text-sm bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                >
                  VirusTotal <ExternalLink className="inline w-3 h-3 ml-1" />
                </a>
                <a
                  href={`https://otx.alienvault.com/indicator/ip/${ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 text-center py-2 text-sm bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                >
                  AlienVault <ExternalLink className="inline w-3 h-3 ml-1" />
                </a>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </div>
  )
}

export function AdvancedThreat() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [stats, setStats] = useState<ThreatStats | null>(null)
  const [providers, setProviders] = useState<ThreatProvider[]>([])
  const [threats, setThreats] = useState<ThreatScore[]>([])
  const [selectedLevel, setSelectedLevel] = useState<string>('all')
  const [searchIP, setSearchIP] = useState('')
  const [selectedIP, setSelectedIP] = useState<string | null>(null)
  const [showModal, setShowModal] = useState(false)

  useEffect(() => {
    async function fetchData() {
      setLoading(true)
      setError(null)
      try {
        const [statsData, providersData, threatsData] = await Promise.all([
          threatsApi.stats(),
          threatsApi.providers(),
          threatsApi.list(50),
        ])
        setStats(statsData)
        setProviders(providersData)
        setThreats(threatsData)
      } catch (err) {
        setError('Failed to load threat data')
        console.error(err)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 60000)
    return () => clearInterval(interval)
  }, [])

  // Filter threats by level
  const filteredThreats = useMemo(() => {
    let filtered = threats
    if (selectedLevel !== 'all') {
      filtered = threats.filter(t => t.threat_level === selectedLevel)
    }
    if (searchIP) {
      const term = searchIP.toLowerCase()
      filtered = filtered.filter(t =>
        t.ip.toLowerCase().includes(term) ||
        t.country?.toLowerCase().includes(term) ||
        t.isp?.toLowerCase().includes(term)
      )
    }
    return filtered
  }, [threats, selectedLevel, searchIP])

  const handleIPClick = (ip: string) => {
    setSelectedIP(ip)
    setShowModal(true)
  }

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (searchIP && /^[\d.]+$/.test(searchIP)) {
      handleIPClick(searchIP)
    }
  }

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (error && !stats) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <AlertTriangle className="w-12 h-12 text-destructive" />
        <p className="text-lg font-medium">{error}</p>
        <button
          onClick={() => window.location.reload()}
          className="px-4 py-2 bg-primary text-primary-foreground rounded-lg"
        >
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-500/10 rounded-lg">
            <AlertTriangle className="w-6 h-6 text-red-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Advanced Threat Intelligence</h1>
            <p className="text-muted-foreground">IP reputation and threat analysis</p>
          </div>
        </div>
        {/* IP Search */}
        <form onSubmit={handleSearchSubmit} className="flex gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Check IP address..."
              value={searchIP}
              onChange={(e) => setSearchIP(e.target.value)}
              className="pl-10 pr-4 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary w-[200px]"
            />
          </div>
          <button
            type="submit"
            disabled={!searchIP}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm disabled:opacity-50"
          >
            Check
          </button>
        </form>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          <StatCard
            title="Total Tracked"
            value={formatNumber(stats.total_tracked)}
            subtitle="IPs in database"
            icon={<Shield className="w-5 h-5 text-blue-500" />}
          />
          <StatCard
            title="Critical Threats"
            value={formatNumber(stats.critical_count)}
            subtitle="Score >= 80"
            icon={<ShieldAlert className="w-5 h-5 text-red-500" />}
            variant={stats.critical_count > 0 ? 'critical' : 'default'}
          />
          <StatCard
            title="High Threats"
            value={formatNumber(stats.high_count)}
            subtitle="Score 60-79"
            icon={<ShieldOff className="w-5 h-5 text-orange-500" />}
            variant={stats.high_count > 0 ? 'warning' : 'default'}
          />
          <StatCard
            title="Tor Exit Nodes"
            value={formatNumber(stats.tor_exit_nodes)}
            subtitle="Anonymization"
            icon={<Globe className="w-5 h-5 text-purple-500" />}
          />
          <StatCard
            title="Checked (24h)"
            value={formatNumber(stats.checks_last_24h)}
            subtitle="IP lookups"
            icon={<ShieldCheck className="w-5 h-5 text-green-500" />}
          />
        </div>
      )}

      {/* Providers Status */}
      <div className="bg-card rounded-xl border p-4">
        <h3 className="text-sm font-medium text-muted-foreground mb-3">Threat Intelligence Providers</h3>
        <div className="flex flex-wrap gap-4">
          {providers.map((provider) => (
            <div key={provider.name} className="flex items-center gap-2">
              {provider.configured && provider.available ? (
                <CheckCircle className="w-4 h-4 text-green-500" />
              ) : (
                <XCircle className="w-4 h-4 text-red-500" />
              )}
              <span className="text-sm">{provider.name}</span>
            </div>
          ))}
          {stats?.cache_stats && (
            <div className="ml-auto text-xs text-muted-foreground">
              Cache: {stats.cache_stats.size} entries |
              Hit rate: {(stats.cache_stats.hit_rate * 100).toFixed(1)}%
            </div>
          )}
        </div>
      </div>

      {/* Level Filter */}
      <div className="flex items-center gap-2 bg-muted rounded-lg p-1 w-fit">
        {['all', 'critical', 'high', 'medium', 'low'].map((level) => (
          <button
            key={level}
            onClick={() => setSelectedLevel(level)}
            className={cn(
              'px-3 py-1.5 rounded-md text-sm font-medium transition-colors capitalize',
              selectedLevel === level
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            {level}
          </button>
        ))}
      </div>

      {/* Threats Table */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b">
              <tr>
                <th className="text-left py-3 px-4 font-medium">IP Address</th>
                <th className="text-left py-3 px-4 font-medium">Country</th>
                <th className="text-center py-3 px-4 font-medium">Score</th>
                <th className="text-center py-3 px-4 font-medium">Level</th>
                <th className="text-center py-3 px-4 font-medium">AbuseIPDB</th>
                <th className="text-center py-3 px-4 font-medium">VirusTotal</th>
                <th className="text-center py-3 px-4 font-medium">Tor</th>
                <th className="text-left py-3 px-4 font-medium">Last Checked</th>
                <th className="text-center py-3 px-4 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredThreats.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-muted-foreground">
                    {threats.length === 0 ? 'No threat data available' : 'No threats match the filter'}
                  </td>
                </tr>
              ) : (
                filteredThreats.map((threat) => {
                  const colors = threatLevelColors[threat.threat_level] || threatLevelColors.none
                  return (
                    <tr
                      key={threat.ip}
                      className="border-b last:border-0 hover:bg-muted/50 transition-colors cursor-pointer"
                      onClick={() => handleIPClick(threat.ip)}
                    >
                      <td className="py-3 px-4">
                        <span className="font-mono">{threat.ip}</span>
                      </td>
                      <td className="py-3 px-4">
                        {threat.country ? (
                          <div className="flex items-center gap-2">
                            <span className="text-lg">{getCountryFlag(threat.country)}</span>
                            <span className="text-muted-foreground">{threat.country}</span>
                          </div>
                        ) : '-'}
                      </td>
                      <td className="py-3 px-4 text-center">
                        <span className={cn('font-bold text-lg', colors.text)}>
                          {threat.aggregated_score}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-center">
                        <span className={cn(
                          'inline-flex px-2 py-1 rounded text-xs font-medium capitalize',
                          colors.bg, colors.text
                        )}>
                          {threat.threat_level}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-center">
                        <span className={cn(
                          'font-mono',
                          threat.abuseipdb_score >= 50 ? 'text-red-500' : 'text-muted-foreground'
                        )}>
                          {threat.abuseipdb_score}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-center">
                        <span className={cn(
                          'font-mono',
                          threat.virustotal_score >= 50 ? 'text-red-500' : 'text-muted-foreground'
                        )}>
                          {threat.virustotal_score}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-center">
                        {threat.is_tor ? (
                          <Globe className="w-4 h-4 text-purple-500 mx-auto" />
                        ) : '-'}
                      </td>
                      <td className="py-3 px-4 text-muted-foreground whitespace-nowrap">
                        {formatDateTime(threat.last_checked)}
                      </td>
                      <td className="py-3 px-4 text-center">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            handleIPClick(threat.ip)
                          }}
                          className="p-1.5 hover:bg-muted rounded transition-colors"
                          title="View details"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* IP Details Modal */}
      <IPDetailsModal
        ip={selectedIP}
        isOpen={showModal}
        onClose={() => {
          setShowModal(false)
          setSelectedIP(null)
        }}
      />
    </div>
  )
}
