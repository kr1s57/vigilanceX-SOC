import { useState, useEffect } from 'react'
import {
  AlertTriangle,
  Globe,
  RefreshCw,
  ExternalLink,
  ShieldAlert,
  ShieldOff,
  Loader2,
  X,
  Search,
} from 'lucide-react'
import { threatsApi } from '@/lib/api'
import { formatDateTime, getCountryFlag, cn } from '@/lib/utils'
import type { ThreatScore } from '@/types'

// Threat level colors
const threatLevelColors: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-500', border: 'border-red-500/30' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-500', border: 'border-orange-500/30' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-500', border: 'border-yellow-500/30' },
  low: { bg: 'bg-blue-500/10', text: 'text-blue-500', border: 'border-blue-500/30' },
  minimal: { bg: 'bg-green-500/10', text: 'text-green-500', border: 'border-green-500/30' },
  none: { bg: 'bg-gray-500/10', text: 'text-gray-500', border: 'border-gray-500/30' },
}

interface IPThreatModalProps {
  ip: string | null
  isOpen: boolean
  onClose: () => void
}

export function IPThreatModal({ ip, isOpen, onClose }: IPThreatModalProps) {
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

// Small button to trigger IP lookup
interface IPLookupButtonProps {
  ip: string
  onClick: (ip: string) => void
  className?: string
}

export function IPLookupButton({ ip, onClick, className }: IPLookupButtonProps) {
  return (
    <button
      onClick={(e) => {
        e.stopPropagation()
        onClick(ip)
      }}
      className={cn(
        'p-1 hover:bg-primary/10 rounded transition-colors text-muted-foreground hover:text-primary',
        className
      )}
      title={`Lookup threat intel for ${ip}`}
    >
      <Search className="w-4 h-4" />
    </button>
  )
}
