import { useState } from 'react'
import { Activity, Search, RefreshCw, TrendingUp, TrendingDown, Clock, Shield, Globe, AlertTriangle, Ban, CheckCircle } from 'lucide-react'
import { threatsApi } from '@/lib/api'
import { getCountryFlag } from '@/lib/utils'
import type { RiskAssessment} from '@/types'

// Default scoring weights (matching backend defaults)
const DEFAULT_WEIGHTS = {
  threat_intel: 0.40,
  blocklist: 0.30,
  freshness: 0.20,
  geolocation: 0.10,
}

// Default freshness config (matching backend defaults)
const DEFAULT_FRESHNESS_CONFIG = {
  decay_factor: 7,
  min_multiplier: 0.1,
  max_multiplier: 1.5,
  recent_activity_boost_days: 3,
  recent_activity_boost: 1.25,
  stale_threshold_days: 30,
}

export function RiskScoring() {
  const [searchIP, setSearchIP] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<RiskAssessment | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleSearch = async () => {
    if (!searchIP) return

    try {
      setLoading(true)
      setError(null)
      const data = await threatsApi.riskAssessment(searchIP)
      setResult(data)
    } catch (err) {
      setError('Failed to assess IP risk')
      setResult(null)
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-red-500 bg-red-500/20'
      case 'high': return 'text-orange-500 bg-orange-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-blue-500 bg-blue-500/20'
      default: return 'text-green-500 bg-green-500/20'
    }
  }

  const getScoreBarColor = (score: number) => {
    if (score >= 80) return 'bg-red-500'
    if (score >= 60) return 'bg-orange-500'
    if (score >= 40) return 'bg-yellow-500'
    if (score >= 20) return 'bg-blue-500'
    return 'bg-green-500'
  }

  const getFreshnessReasonText = (reason: string) => {
    switch (reason) {
      case 'recent_activity_boost': return 'Recent activity detected - score boosted'
      case 'stale_decay': return 'Stale data - score decayed'
      case 'normal_window': return 'Within normal activity window'
      case 'multi_source_recent_boost': return 'Multiple recent sources - additional boost'
      default: return 'Unknown last seen time'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Risk Scoring</h1>
        <p className="text-muted-foreground">Combined risk assessment with freshness-based scoring</p>
      </div>

      {/* Scoring Weights */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-card border border-border rounded-lg p-4">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            Scoring Weights
          </h2>
          <p className="text-sm text-muted-foreground mb-4">
            Combined risk score is calculated using weighted components:
          </p>
          <div className="space-y-3">
            {Object.entries(DEFAULT_WEIGHTS).map(([key, weight]) => (
              <div key={key} className="flex items-center gap-3">
                <div className="w-24 text-sm capitalize">{key.replace('_', ' ')}</div>
                <div className="flex-1 bg-muted rounded-full h-4 overflow-hidden">
                  <div
                    className="h-full bg-primary transition-all"
                    style={{ width: `${weight * 100}%` }}
                  />
                </div>
                <div className="w-12 text-right text-sm font-medium">{(weight * 100).toFixed(0)}%</div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-card border border-border rounded-lg p-4">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Clock className="w-5 h-5 text-primary" />
            Freshness Algorithm
          </h2>
          <p className="text-sm text-muted-foreground mb-4">
            Scores decay over time for stale threat data:
          </p>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Recent window (boost)</span>
              <span className="font-medium text-green-400">≤ {DEFAULT_FRESHNESS_CONFIG.recent_activity_boost_days} days → +{((DEFAULT_FRESHNESS_CONFIG.recent_activity_boost - 1) * 100).toFixed(0)}%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Normal window</span>
              <span className="font-medium">≤ {DEFAULT_FRESHNESS_CONFIG.stale_threshold_days} days → 100%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Stale threshold</span>
              <span className="font-medium text-yellow-400">&gt; {DEFAULT_FRESHNESS_CONFIG.stale_threshold_days} days → decay</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Decay factor</span>
              <span className="font-medium">{DEFAULT_FRESHNESS_CONFIG.decay_factor} days half-life</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Floor multiplier</span>
              <span className="font-medium text-red-400">{(DEFAULT_FRESHNESS_CONFIG.min_multiplier * 100).toFixed(0)}% minimum</span>
            </div>
          </div>
        </div>
      </div>

      {/* IP Risk Assessment */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Search className="w-5 h-5" />
          IP Risk Assessment
        </h2>
        <div className="flex gap-2">
          <input
            type="text"
            value={searchIP}
            onChange={(e) => setSearchIP(e.target.value)}
            placeholder="Enter IP address..."
            className="flex-1 px-3 py-2 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
          />
          <button
            onClick={handleSearch}
            disabled={loading || !searchIP}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'Assess'}
          </button>
        </div>

        {error && (
          <div className="mt-4 p-4 bg-destructive/20 text-destructive rounded-lg">{error}</div>
        )}

        {result && (
          <div className="mt-6 space-y-6">
            {/* Main Score */}
            <div className="flex items-center justify-between p-4 bg-muted/50 rounded-lg">
              <div>
                <div className="flex items-center gap-3">
                  <code className="text-lg font-mono">{result.ip}</code>
                  {result.country && (
                    <span className="text-sm">{getCountryFlag(result.country)} {result.country}</span>
                  )}
                </div>
                <div className="flex gap-2 mt-2">
                  {result.is_tor && <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 text-xs rounded">TOR</span>}
                  {result.is_vpn && <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 text-xs rounded">VPN</span>}
                  {result.is_proxy && <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded">Proxy</span>}
                  {result.is_benign && <span className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded">Benign</span>}
                </div>
              </div>
              <div className="text-right">
                <div className="text-4xl font-bold">{result.combined_score}</div>
                <div className={`text-sm px-2 py-0.5 rounded capitalize ${getRiskColor(result.combined_risk)}`}>
                  {result.combined_risk} risk
                </div>
              </div>
            </div>

            {/* Recommendation */}
            <div className={`flex items-center gap-3 p-4 rounded-lg ${result.recommend_ban ? 'bg-red-500/20' : 'bg-green-500/20'}`}>
              {result.recommend_ban ? (
                <>
                  <Ban className="w-6 h-6 text-red-400" />
                  <div>
                    <p className="font-medium text-red-400">Ban Recommended</p>
                    <p className="text-sm text-muted-foreground">Score exceeds threshold for automatic ban</p>
                  </div>
                </>
              ) : (
                <>
                  <CheckCircle className="w-6 h-6 text-green-400" />
                  <div>
                    <p className="font-medium text-green-400">No Action Required</p>
                    <p className="text-sm text-muted-foreground">Score below ban threshold</p>
                  </div>
                </>
              )}
              <div className="ml-auto text-sm text-muted-foreground">
                Confidence: {(result.scoring_confidence * 100).toFixed(0)}%
              </div>
            </div>

            {/* Score Components */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-muted/30 rounded-lg p-4">
                <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Score Components
                </h3>
                <div className="space-y-3">
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>Threat Intel ({(result.score_components.threat_intel_weight * 100).toFixed(0)}%)</span>
                      <span className="font-medium">{result.score_components.threat_intel}</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div className={`h-full ${getScoreBarColor(result.score_components.threat_intel)}`} style={{ width: `${result.score_components.threat_intel}%` }} />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>Blocklist ({(result.score_components.blocklist_weight * 100).toFixed(0)}%)</span>
                      <span className="font-medium">{result.score_components.blocklist}</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div className={`h-full ${getScoreBarColor(result.score_components.blocklist)}`} style={{ width: `${result.score_components.blocklist}%` }} />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>Freshness ({(result.score_components.freshness_weight * 100).toFixed(0)}%)</span>
                      <span className="font-medium">{result.score_components.freshness}</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div className={`h-full ${getScoreBarColor(result.score_components.freshness)}`} style={{ width: `${Math.min(result.score_components.freshness, 100)}%` }} />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>Geolocation ({(result.score_components.geolocation_weight * 100).toFixed(0)}%)</span>
                      <span className="font-medium">{result.score_components.geolocation}</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div className={`h-full ${getScoreBarColor(result.score_components.geolocation)}`} style={{ width: `${result.score_components.geolocation}%` }} />
                    </div>
                  </div>
                  {result.score_components.whitelist_reduction > 0 && (
                    <div className="pt-2 border-t border-border">
                      <div className="flex justify-between text-sm text-green-400">
                        <span>Whitelist Reduction</span>
                        <span className="font-medium">-{result.score_components.whitelist_reduction}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className="space-y-4">
                {/* Freshness Status */}
                {result.freshness && (
                  <div className="bg-muted/30 rounded-lg p-4">
                    <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
                      <Clock className="w-4 h-4" />
                      Freshness Status
                    </h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Days since last seen</span>
                        <span className="font-medium">{result.freshness.days_since_last_seen}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Multiplier</span>
                        <span className={`font-medium ${result.freshness.multiplier > 1 ? 'text-red-400' : result.freshness.multiplier < 1 ? 'text-green-400' : ''}`}>
                          {result.freshness.multiplier.toFixed(2)}x
                          {result.freshness.multiplier > 1 && <TrendingUp className="w-3 h-3 inline ml-1" />}
                          {result.freshness.multiplier < 1 && <TrendingDown className="w-3 h-3 inline ml-1" />}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Status</span>
                        <span className={`font-medium ${result.freshness.is_recent ? 'text-red-400' : result.freshness.is_stale ? 'text-green-400' : ''}`}>
                          {result.freshness.is_recent ? 'Recent' : result.freshness.is_stale ? 'Stale' : 'Normal'}
                        </span>
                      </div>
                      <div className="pt-2 text-xs text-muted-foreground">
                        {getFreshnessReasonText(result.freshness.reason)}
                      </div>
                    </div>
                  </div>
                )}

                {/* Whitelist Status */}
                {result.whitelist_status && (
                  <div className="bg-muted/30 rounded-lg p-4">
                    <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      Whitelist Status
                    </h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Whitelisted</span>
                        <span className={`font-medium ${result.whitelist_status.is_whitelisted ? 'text-green-400' : ''}`}>
                          {result.whitelist_status.is_whitelisted ? 'Yes' : 'No'}
                        </span>
                      </div>
                      {result.whitelist_status.is_whitelisted && (
                        <>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Type</span>
                            <span className="font-medium capitalize">{result.whitelist_status.type}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Score modifier</span>
                            <span className="font-medium text-green-400">-{result.whitelist_status.score_modifier}%</span>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                )}

                {/* Blocklist Info */}
                {result.blocklist_count > 0 && (
                  <div className="bg-muted/30 rounded-lg p-4">
                    <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
                      <Globe className="w-4 h-4" />
                      Blocklist Presence
                    </h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Sources</span>
                        <span className="font-medium text-red-400">{result.blocklist_count}</span>
                      </div>
                      {result.blocklist_sources && result.blocklist_sources.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {result.blocklist_sources.map((source) => (
                            <span key={source} className="px-2 py-0.5 bg-red-500/20 text-red-400 text-xs rounded">
                              {source}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Tags */}
            {result.tags && result.tags.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {result.tags.map((tag) => (
                  <span key={tag} className="px-2 py-1 bg-primary/20 text-primary text-xs rounded">
                    {tag}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Formula Explanation */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h2 className="text-lg font-semibold mb-4">Scoring Formula</h2>
        <div className="space-y-4 text-sm">
          <div className="p-3 bg-muted rounded font-mono text-xs overflow-x-auto">
            combined_score = (threat_intel × 0.40) + (blocklist × 0.30) + (freshness × 0.20) + (geolocation × 0.10)
          </div>
          <div className="p-3 bg-muted rounded font-mono text-xs overflow-x-auto">
            freshness_multiplier = e^(-(days_over_threshold) / decay_factor)
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
            <div>
              <h4 className="font-medium mb-2">Risk Levels</h4>
              <ul className="space-y-1 text-muted-foreground">
                <li><span className="text-red-500">●</span> Critical: ≥ 80</li>
                <li><span className="text-orange-500">●</span> High: ≥ 60</li>
                <li><span className="text-yellow-500">●</span> Medium: ≥ 40</li>
                <li><span className="text-blue-500">●</span> Low: ≥ 20</li>
                <li><span className="text-green-500">●</span> None: &lt; 20</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium mb-2">Auto-ban Threshold</h4>
              <p className="text-muted-foreground">
                IPs with combined score ≥ 70 are recommended for automatic ban, unless:
              </p>
              <ul className="mt-2 space-y-1 text-muted-foreground list-disc list-inside">
                <li>IP is on hard whitelist</li>
                <li>IP is on soft whitelist with alert-only</li>
                <li>IP is marked as benign by GreyNoise</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
