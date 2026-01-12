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
  Activity,
  Target,
  Radio,
  Ban,
  History,
  Clock,
  Shield,
  ShieldCheck,
  ShieldX,
} from 'lucide-react'
import { threatsApi, bansApi, softWhitelistApi } from '@/lib/api'
import { formatDateTime, getCountryFlag, cn } from '@/lib/utils'
import type { ThreatScore, BanHistory, WhitelistCheckResult } from '@/types'

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
  const [banning, setBanning] = useState(false)
  const [isBanned, setIsBanned] = useState(false)
  const [banStatus, setBanStatus] = useState<string | null>(null)
  const [banHistory, setBanHistory] = useState<BanHistory[]>([])
  const [whitelistStatus, setWhitelistStatus] = useState<WhitelistCheckResult | null>(null)

  const handleBanIP = async () => {
    if (!ip) return
    setBanning(true)
    try {
      await bansApi.create({
        ip,
        reason: `Manual ban from Threat Intel - Score: ${score?.aggregated_score || 'N/A'}`,
        permanent: false,
      })
      setIsBanned(true)
      setBanStatus('active')
    } catch (err) {
      console.error('Failed to ban IP:', err)
    } finally {
      setBanning(false)
    }
  }

  useEffect(() => {
    if (isOpen && ip) {
      setLoading(true)
      setError(null)
      setIsBanned(false)
      setBanStatus(null)
      setBanHistory([])
      setWhitelistStatus(null)

      // Fetch threat score, ban status, ban history, and whitelist status in parallel
      Promise.all([
        threatsApi.score(ip).catch(() => null),
        bansApi.get(ip).catch(() => null),
        bansApi.history(ip).catch(() => []),
        softWhitelistApi.check(ip).catch(() => null)
      ]).then(([scoreData, banData, historyData, whitelistData]) => {
        if (scoreData) setScore(scoreData)
        else setError('Score not found in database')

        if (banData && (banData.status === 'active' || banData.status === 'permanent')) {
          setIsBanned(true)
          setBanStatus(banData.status)
        }

        if (historyData && historyData.length > 0) {
          setBanHistory(historyData)
        }

        if (whitelistData) {
          setWhitelistStatus(whitelistData)
        }
      }).finally(() => setLoading(false))
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
            {isBanned ? (
              <span className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium',
                banStatus === 'permanent'
                  ? 'bg-red-500/20 text-red-500'
                  : 'bg-orange-500/20 text-orange-500'
              )}>
                <Ban className="w-4 h-4" />
                {banStatus === 'permanent' ? 'Permanent Ban' : 'Banned'}
              </span>
            ) : (
              <button
                onClick={handleBanIP}
                disabled={banning}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors text-sm font-medium bg-red-500/10 text-red-500 hover:bg-red-500/20"
                title="Ban this IP"
              >
                {banning ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <>
                    <Ban className="w-4 h-4" />
                    Ban IP
                  </>
                )}
              </button>
            )}
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
              <div className="grid grid-cols-4 gap-3">
                <div className="bg-muted/50 rounded-lg p-3 text-center">
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
                <div className="bg-muted/50 rounded-lg p-3 text-center">
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
                <div className="bg-muted/50 rounded-lg p-3 text-center">
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
                <div className={cn(
                  'rounded-lg p-3 text-center',
                  score.crowdsec?.found ? 'bg-muted/50' : 'bg-muted/30'
                )}>
                  <p className="text-xs text-muted-foreground mb-1">CrowdSec</p>
                  {score.crowdsec?.found ? (
                    <>
                      <p className={cn(
                        'text-2xl font-bold',
                        (score.crowdsec.normalized_score || 0) >= 50 ? 'text-red-500' : 'text-green-500'
                      )}>
                        {score.crowdsec.normalized_score || 0}
                      </p>
                      <p className={cn(
                        'text-xs',
                        score.crowdsec.reputation === 'malicious' ? 'text-red-500' :
                        score.crowdsec.reputation === 'suspicious' ? 'text-orange-500' : 'text-muted-foreground'
                      )}>
                        {score.crowdsec.reputation || 'unknown'}
                      </p>
                    </>
                  ) : (
                    <>
                      <p className="text-2xl font-bold text-muted-foreground">-</p>
                      <p className="text-xs text-muted-foreground">not queried</p>
                    </>
                  )}
                </div>
              </div>

              {/* CrowdSec Section (v2.9.6) */}
              {score.crowdsec?.found && (
                <div className="border rounded-lg p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Radio className="w-4 h-4 text-blue-500" />
                      <span className="font-medium">CrowdSec CTI</span>
                    </div>
                    <span className={cn(
                      'px-2 py-0.5 text-xs rounded-full font-medium',
                      score.crowdsec.reputation === 'malicious' ? 'bg-red-500/10 text-red-500' :
                      score.crowdsec.reputation === 'suspicious' ? 'bg-orange-500/10 text-orange-500' :
                      'bg-gray-500/10 text-gray-500'
                    )}>
                      {score.crowdsec.reputation || 'unknown'}
                    </span>
                  </div>

                  {/* CrowdSec Scores */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className="text-center">
                      <p className="text-xs text-muted-foreground">Score</p>
                      <p className={cn(
                        'text-xl font-bold',
                        (score.crowdsec.normalized_score || 0) >= 70 ? 'text-red-500' :
                        (score.crowdsec.normalized_score || 0) >= 40 ? 'text-orange-500' : 'text-green-500'
                      )}>
                        {score.crowdsec.normalized_score || 0}
                      </p>
                    </div>
                    <div className="text-center">
                      <p className="text-xs text-muted-foreground">Background Noise</p>
                      <p className={cn(
                        'text-xl font-bold',
                        (score.crowdsec.background_noise_score || 0) >= 7 ? 'text-red-500' :
                        (score.crowdsec.background_noise_score || 0) >= 4 ? 'text-orange-500' : 'text-green-500'
                      )}>
                        {score.crowdsec.background_noise_score || 0}/10
                      </p>
                    </div>
                    <div className="text-center">
                      <p className="text-xs text-muted-foreground">Subnet /24</p>
                      <p className={cn(
                        'text-xl font-bold',
                        (score.crowdsec.ip_range_score || 0) >= 4 ? 'text-red-500' :
                        (score.crowdsec.ip_range_score || 0) >= 2 ? 'text-orange-500' : 'text-green-500'
                      )}>
                        {score.crowdsec.ip_range_score || 0}/5
                      </p>
                    </div>
                  </div>

                  {/* Behaviors */}
                  {score.crowdsec.behaviors && score.crowdsec.behaviors.length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                        <Activity className="w-3 h-3" /> Behaviors
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {score.crowdsec.behaviors.map((b, i) => (
                          <span key={i} className="px-2 py-0.5 text-xs bg-orange-500/10 text-orange-600 dark:text-orange-400 rounded">
                            {b}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* MITRE ATT&CK */}
                  {score.crowdsec.mitre_techniques && score.crowdsec.mitre_techniques.length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                        <Target className="w-3 h-3" /> MITRE ATT&CK
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {score.crowdsec.mitre_techniques.map((t, i) => (
                          <a
                            key={i}
                            href={`https://attack.mitre.org/techniques/${t}/`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-2 py-0.5 text-xs bg-purple-500/10 text-purple-600 dark:text-purple-400 rounded hover:bg-purple-500/20"
                          >
                            {t}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Classifications */}
                  {score.crowdsec.classifications && score.crowdsec.classifications.length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Classifications</p>
                      <div className="flex flex-wrap gap-1">
                        {score.crowdsec.classifications.map((c, i) => (
                          <span key={i} className="px-2 py-0.5 text-xs bg-blue-500/10 text-blue-600 dark:text-blue-400 rounded">
                            {c.replace('connection-type:', '').replace('crowdsec:', '').replace('proxy:', '')}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Details */}
              <div className="space-y-3">
                {/* Badges */}
                <div className="flex flex-wrap gap-2">
                  {isBanned && (
                    <span className={cn(
                      'inline-flex items-center gap-1 px-2 py-1 text-xs rounded-full font-medium',
                      banStatus === 'permanent'
                        ? 'bg-red-500/20 text-red-500'
                        : 'bg-orange-500/20 text-orange-500'
                    )}>
                      <Ban className="w-3 h-3" />
                      {banStatus === 'permanent' ? 'Permanent Ban' : 'Active Ban'}
                    </span>
                  )}
                  {whitelistStatus?.is_whitelisted && (
                    <span className={cn(
                      'inline-flex items-center gap-1 px-2 py-1 text-xs rounded-full font-medium',
                      whitelistStatus.effective_type === 'hard'
                        ? 'bg-green-500/20 text-green-500'
                        : whitelistStatus.effective_type === 'soft'
                        ? 'bg-blue-500/20 text-blue-500'
                        : 'bg-gray-500/20 text-gray-500'
                    )}>
                      <ShieldCheck className="w-3 h-3" />
                      {whitelistStatus.effective_type === 'hard' ? 'Hard Whitelist' :
                       whitelistStatus.effective_type === 'soft' ? 'Soft Whitelist' :
                       'Monitor Only'}
                      {whitelistStatus.effective_type === 'soft' && whitelistStatus.score_modifier > 0 && (
                        <span className="ml-1">(-{whitelistStatus.score_modifier}%)</span>
                      )}
                    </span>
                  )}
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

              {/* Ban History Section */}
              {banHistory.length > 0 && (
                <div className="border rounded-lg p-4 space-y-3">
                  <div className="flex items-center gap-2 mb-3">
                    <History className="w-4 h-4 text-muted-foreground" />
                    <span className="font-medium">Ban History</span>
                    <span className="text-xs text-muted-foreground">({banHistory.length} events)</span>
                  </div>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {banHistory.map((entry) => {
                      // Determine icon and color based on action
                      const actionConfig: Record<string, { icon: typeof Ban; color: string; label: string }> = {
                        ban: { icon: Ban, color: 'text-red-500 bg-red-500/10', label: 'Banned' },
                        unban: { icon: ShieldCheck, color: 'text-green-500 bg-green-500/10', label: 'Unbanned' },
                        unban_immunity: { icon: Shield, color: 'text-blue-500 bg-blue-500/10', label: 'Unbanned (24h immunity)' },
                        extend: { icon: Clock, color: 'text-orange-500 bg-orange-500/10', label: 'Extended' },
                        permanent: { icon: ShieldX, color: 'text-purple-500 bg-purple-500/10', label: 'Made Permanent' },
                        expire: { icon: ShieldOff, color: 'text-gray-500 bg-gray-500/10', label: 'Expired' },
                      }
                      const config = actionConfig[entry.action] || { icon: History, color: 'text-gray-500 bg-gray-500/10', label: entry.action }
                      const Icon = config.icon

                      // Determine source tag based on action and source
                      const getSourceTag = () => {
                        // For unban actions
                        if (entry.action === 'unban' || entry.action === 'unban_immunity') {
                          if (entry.synced_xgs) {
                            return { label: 'XGS Synced', color: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400' }
                          }
                          if (entry.source === 'manual') {
                            return { label: 'VGXUI', color: 'bg-blue-500/10 text-blue-600 dark:text-blue-400' }
                          }
                        }
                        // For expired bans (policy-based unban)
                        if (entry.action === 'expire') {
                          return { label: 'Unb_policiesVGX', color: 'bg-amber-500/10 text-amber-600 dark:text-amber-400' }
                        }
                        // For bans, show the source
                        if (entry.action === 'ban') {
                          if (entry.source === 'detect2ban') {
                            return { label: 'Detect2Ban', color: 'bg-red-500/10 text-red-600 dark:text-red-400' }
                          }
                          if (entry.source === 'manual') {
                            return { label: 'VGXUI', color: 'bg-blue-500/10 text-blue-600 dark:text-blue-400' }
                          }
                          if (entry.source === 'threat_intel') {
                            return { label: 'ThreatIntel', color: 'bg-purple-500/10 text-purple-600 dark:text-purple-400' }
                          }
                        }
                        // Default: show source if available and not manual
                        if (entry.source && entry.source !== 'manual') {
                          return { label: entry.source, color: 'bg-muted text-muted-foreground' }
                        }
                        return null
                      }
                      const sourceTag = getSourceTag()

                      return (
                        <div key={entry.id} className="flex items-start gap-3 text-sm border-b border-border/50 pb-2 last:border-0 last:pb-0">
                          <div className={cn('p-1.5 rounded', config.color.split(' ')[1])}>
                            <Icon className={cn('w-3.5 h-3.5', config.color.split(' ')[0])} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className={cn('font-medium', config.color.split(' ')[0])}>{config.label}</span>
                              {sourceTag && (
                                <span className={cn('text-xs px-1.5 py-0.5 rounded', sourceTag.color)}>{sourceTag.label}</span>
                              )}
                            </div>
                            {entry.reason && (
                              <p className="text-xs text-muted-foreground truncate" title={entry.reason}>{entry.reason}</p>
                            )}
                            <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                              <span>{formatDateTime(entry.timestamp)}</span>
                              {entry.performed_by && (
                                <>
                                  <span>•</span>
                                  <span>by {entry.performed_by}</span>
                                </>
                              )}
                              {entry.duration_hours && entry.duration_hours > 0 && (
                                <>
                                  <span>•</span>
                                  <span>{entry.duration_hours}h</span>
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* External Links */}
              <div className="flex flex-wrap gap-2 pt-2 border-t">
                <a
                  href={`https://www.abuseipdb.com/check/${ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 min-w-[100px] text-center py-2 text-sm bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                >
                  AbuseIPDB <ExternalLink className="inline w-3 h-3 ml-1" />
                </a>
                <a
                  href={`https://www.virustotal.com/gui/ip-address/${ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 min-w-[100px] text-center py-2 text-sm bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                >
                  VirusTotal <ExternalLink className="inline w-3 h-3 ml-1" />
                </a>
                <a
                  href={`https://otx.alienvault.com/indicator/ip/${ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 min-w-[100px] text-center py-2 text-sm bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                >
                  AlienVault <ExternalLink className="inline w-3 h-3 ml-1" />
                </a>
                <a
                  href={`https://app.crowdsec.net/cti/${ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 min-w-[100px] text-center py-2 text-sm bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                >
                  CrowdSec <ExternalLink className="inline w-3 h-3 ml-1" />
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
