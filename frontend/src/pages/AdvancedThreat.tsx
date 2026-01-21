import { useState, useEffect, useMemo } from 'react'
import {
  AlertTriangle,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Globe,
  Search,
  CheckCircle,
  XCircle,
  Eye,
  Bug,
  Radar,
  Radio,
  List,
  Fingerprint,
  Activity,
  Skull,
  Link2,
  Scan,
  Key,
} from 'lucide-react'
import { threatsApi } from '@/lib/api'
import { StatCard } from '@/components/dashboard/StatCard'
// v3.58.108: Use lazy-loaded modal for better performance
import { LazyIPThreatModal } from '@/components/ui/LazyModals'
import { formatNumber, getCountryFlag, formatDateTime, cn } from '@/lib/utils'
import { useSettings } from '@/contexts/SettingsContext'
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

// Provider icons and colors (v2.9.5: 10 providers with tiers)
const getProviderStyle = (name: string): { icon: React.ReactNode; color: string; bg: string } => {
  const styles: Record<string, { icon: React.ReactNode; color: string; bg: string }> = {
    // Tier 1: Unlimited (always queried)
    'IPSum': { icon: <List className="w-4 h-4" />, color: 'text-purple-400', bg: 'bg-purple-500/10' },
    'AlienVault OTX': { icon: <Radar className="w-4 h-4" />, color: 'text-cyan-400', bg: 'bg-cyan-500/10' },
    'ThreatFox': { icon: <Skull className="w-4 h-4" />, color: 'text-rose-400', bg: 'bg-rose-500/10' },
    'URLhaus': { icon: <Link2 className="w-4 h-4" />, color: 'text-amber-400', bg: 'bg-amber-500/10' },
    'Shodan InternetDB': { icon: <Scan className="w-4 h-4" />, color: 'text-teal-400', bg: 'bg-teal-500/10' },
    // Tier 2: Moderate limits (queried on suspicion)
    'AbuseIPDB': { icon: <ShieldAlert className="w-4 h-4" />, color: 'text-red-400', bg: 'bg-red-500/10' },
    'GreyNoise': { icon: <Radio className="w-4 h-4" />, color: 'text-gray-400', bg: 'bg-gray-500/10' },
    // Tier 3: Limited (queried on high suspicion)
    'VirusTotal': { icon: <Bug className="w-4 h-4" />, color: 'text-blue-400', bg: 'bg-blue-500/10' },
    'CriminalIP': { icon: <Fingerprint className="w-4 h-4" />, color: 'text-orange-400', bg: 'bg-orange-500/10' },
    'Pulsedive': { icon: <Activity className="w-4 h-4" />, color: 'text-green-400', bg: 'bg-green-500/10' },
  }
  return styles[name] || { icon: <Shield className="w-4 h-4" />, color: 'text-gray-400', bg: 'bg-gray-500/10' }
}

// Tier badge colors
const getTierBadge = (tier: number | undefined): { label: string; color: string } => {
  switch (tier) {
    case 1: return { label: 'T1', color: 'bg-green-500/20 text-green-400' }
    case 2: return { label: 'T2', color: 'bg-yellow-500/20 text-yellow-400' }
    case 3: return { label: 'T3', color: 'bg-red-500/20 text-red-400' }
    default: return { label: '', color: '' }
  }
}

export function AdvancedThreat() {
  const { shouldShowIP } = useSettings()
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
        setStats(statsData || null)
        setProviders(providersData || [])
        setThreats(threatsData || [])
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

  // Filter threats by level and system whitelist
  const filteredThreats = useMemo(() => {
    // First filter out system IPs (DNS, CDN, etc.)
    let filtered = threats.filter(t => shouldShowIP(t.ip))

    if (selectedLevel !== 'all') {
      filtered = filtered.filter(t => t.threat_level === selectedLevel)
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
  }, [threats, selectedLevel, searchIP, shouldShowIP])

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

      {/* Providers Status (v2.9.5: 10 providers with cascade tiers) */}
      <div className="bg-card rounded-xl border p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-muted-foreground">Threat Intelligence Providers</h3>
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-green-500"></span> T1: Unlimited
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-yellow-500"></span> T2: Moderate
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-red-500"></span> T3: Limited
            </span>
          </div>
        </div>
        <div className="flex flex-wrap gap-3">
          {providers.map((provider) => {
            const style = getProviderStyle(provider.name)
            const tierBadge = getTierBadge(provider.tier)
            const isActive = provider.configured
            return (
              <div
                key={provider.name}
                className={cn(
                  'flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-colors group relative',
                  isActive
                    ? `${style.bg} ${style.color} border-current/20`
                    : 'bg-muted/50 text-muted-foreground border-transparent opacity-50'
                )}
                title={provider.description || provider.name}
              >
                {/* Tier Badge */}
                {tierBadge.label && (
                  <span className={cn('text-[10px] font-bold px-1 rounded', tierBadge.color)}>
                    {tierBadge.label}
                  </span>
                )}
                <span className={isActive ? style.color : 'text-muted-foreground'}>
                  {style.icon}
                </span>
                <span className="text-sm font-medium">{provider.name}</span>
                {/* API Key indicator */}
                {provider.requires_key && !isActive && (
                  <span title="Requires API key">
                    <Key className="w-3 h-3 text-amber-500" />
                  </span>
                )}
                {isActive ? (
                  <CheckCircle className="w-3 h-3 text-green-500" />
                ) : (
                  <XCircle className="w-3 h-3 text-red-400" />
                )}
              </div>
            )
          })}
        </div>
        {/* Cache stats */}
        {stats?.cache_stats && (
          <div className="mt-3 pt-3 border-t flex items-center justify-between text-xs text-muted-foreground">
            <span>Cascade mode: Tier 1 → Tier 2 (score≥30) → Tier 3 (score≥60)</span>
            <span>
              Cache: {stats.cache_stats.size} entries |
              Hit rate: {(stats.cache_stats.hit_rate * 100).toFixed(1)}%
            </span>
          </div>
        )}
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

      {/* IP Details Modal - v3.58.108: Lazy loaded */}
      <LazyIPThreatModal
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
