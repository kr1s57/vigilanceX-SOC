// v3.57.117: PendingApprovalDetailModal - Full TI + History view for pending ban decisions
// v3.57.118: Added support for False Positive detection type
import { useState, useEffect } from 'react'
import {
  AlertTriangle,
  Globe,
  RefreshCw,
  ExternalLink,
  ShieldAlert,
  Loader2,
  X,
  Activity,
  Target,
  Radio,
  Ban,
  Clock,
  Shield,
  ShieldCheck,
  ShieldX,
  CheckCircle,
  History,
  MapPin,
  FileWarning,
  Link2,
} from 'lucide-react'
import { threatsApi, eventsApi, modsecApi } from '@/lib/api'
import { formatDateTime, getCountryFlag, cn } from '@/lib/utils'
import type { ThreatScore, PendingBan, Event, ModSecLog } from '@/types'

// Threat level colors
const threatLevelColors: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-500', border: 'border-red-500/30' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-500', border: 'border-orange-500/30' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-500', border: 'border-yellow-500/30' },
  low: { bg: 'bg-blue-500/10', text: 'text-blue-500', border: 'border-blue-500/30' },
  minimal: { bg: 'bg-green-500/10', text: 'text-green-500', border: 'border-green-500/30' },
  none: { bg: 'bg-gray-500/10', text: 'text-gray-500', border: 'border-gray-500/30' },
}

interface PendingApprovalDetailModalProps {
  pending: PendingBan | null
  isOpen: boolean
  onClose: () => void
  onApprove: (id: string, ip: string) => Promise<void>
  onReject: (id: string, ip: string) => Promise<void>
}

export function PendingApprovalDetailModal({
  pending,
  isOpen,
  onClose,
  onApprove,
  onReject
}: PendingApprovalDetailModalProps) {
  const [score, setScore] = useState<ThreatScore | null>(null)
  const [loading, setLoading] = useState(false)
  const [checking, setChecking] = useState(false)
  const [attackHistory, setAttackHistory] = useState<Event[]>([])
  const [wafHistory, setWafHistory] = useState<ModSecLog[]>([])
  const [processing, setProcessing] = useState(false)

  useEffect(() => {
    if (isOpen && pending) {
      // Reset state
      setScore(null)
      setLoading(true)
      setAttackHistory([])
      setWafHistory([])

      // Fetch TI score and attack history in parallel
      Promise.all([
        threatsApi.score(pending.ip).catch(() => null),
        eventsApi.list({ src_ip: pending.ip, limit: 50 }).catch(() => ({ data: [], pagination: { total: 0, limit: 50, offset: 0 } })),
        modsecApi.getLogs({ src_ip: pending.ip, limit: 50 }).catch(() => ({ data: [], pagination: { total: 0, limit: 50, offset: 0 } }))
      ]).then(async ([scoreData, eventsData, wafData]) => {
        // v3.57.118: Only auto-scan if NO score exists at all
        // If score exists (even without CrowdSec), show it immediately - user can refresh manually
        if (scoreData) {
          setScore(scoreData)
        } else {
          // No stored score - run full TI scan
          try {
            const fullScore = await threatsApi.check(pending.ip)
            if (fullScore) setScore(fullScore)
          } catch {
            // Failed to scan, keep null score
          }
        }

        if (eventsData?.data) setAttackHistory(eventsData.data)
        if (wafData?.data) setWafHistory(wafData.data)
      }).finally(() => setLoading(false))
    }
  }, [isOpen, pending])

  const handleRefreshTI = async () => {
    if (!pending) return
    setChecking(true)
    try {
      const data = await threatsApi.check(pending.ip)
      setScore(data)
    } catch {
      // Keep existing score
    } finally {
      setChecking(false)
    }
  }

  const handleApprove = async () => {
    if (!pending || processing) return
    setProcessing(true)
    try {
      await onApprove(pending.id, pending.ip)
      onClose()
    } finally {
      setProcessing(false)
    }
  }

  const handleReject = async () => {
    if (!pending || processing) return
    setProcessing(true)
    try {
      await onReject(pending.id, pending.ip)
      onClose()
    } finally {
      setProcessing(false)
    }
  }

  if (!isOpen || !pending) return null

  const colors = score
    ? threatLevelColors[score.threat_level] || threatLevelColors.none
    : threatLevelColors.none

  // Determine threat level color based on pending.threat_score if no full score yet
  const pendingScoreColor = pending.threat_score >= 70 ? 'text-red-500' :
    pending.threat_score >= 30 ? 'text-orange-500' : 'text-green-500'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-card border rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-hidden m-4">
        {/* Header - v3.57.118: Color themed by pending type (FP=purple, Country=amber) */}
        <div className={cn(
          "flex items-center justify-between p-4 border-b",
          pending.pending_type === 'false_positive' ? "bg-purple-500/10" : "bg-amber-500/10"
        )}>
          <div className="flex items-center gap-3">
            <div className={cn(
              "p-2 rounded-lg",
              pending.pending_type === 'false_positive' ? "bg-purple-500/20" : "bg-amber-500/20"
            )}>
              {pending.pending_type === 'false_positive' ? (
                <FileWarning className="w-6 h-6 text-purple-500" />
              ) : (
                <ShieldCheck className="w-6 h-6 text-amber-500" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl" title={pending.country}>
                  {getCountryFlag(pending.country)}
                </span>
                <h2 className="text-xl font-bold font-mono">{pending.ip}</h2>
                <span className={cn(
                  "px-2 py-0.5 rounded text-xs font-medium",
                  pending.pending_type === 'false_positive'
                    ? "bg-purple-500/20 text-purple-600 dark:text-purple-400"
                    : "bg-amber-500/20 text-amber-600 dark:text-amber-400"
                )}>
                  {pending.country}
                </span>
                {/* v3.57.118: Pending type badge */}
                <span className={cn(
                  "px-2 py-0.5 rounded text-xs font-medium",
                  pending.pending_type === 'false_positive'
                    ? "bg-purple-500/10 text-purple-500"
                    : "bg-cyan-500/10 text-cyan-500"
                )}>
                  {pending.pending_type === 'false_positive' ? 'False Positive' : 'Country Policy'}
                </span>
              </div>
              <p className="text-sm text-muted-foreground">
                {pending.pending_type === 'false_positive'
                  ? `Potential false positive - ${pending.trigger_rule}`
                  : `Pending ban approval - ${pending.trigger_rule}`}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleRefreshTI}
              disabled={checking || loading}
              className="p-2 hover:bg-muted rounded-lg transition-colors"
              title="Re-check Threat Intelligence"
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
        <div className="overflow-y-auto max-h-[calc(90vh-200px)] p-4 space-y-4">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-amber-500" />
              <span className="ml-3 text-muted-foreground">Loading Threat Intelligence...</span>
            </div>
          ) : (
            <>
              {/* Quick Stats from Pending Ban */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-muted/50 rounded-lg p-3 text-center">
                  <p className="text-xs text-muted-foreground mb-1">Trigger Rule</p>
                  <p className="font-semibold text-sm">{pending.trigger_rule}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3 text-center">
                  <p className="text-xs text-muted-foreground mb-1">Events Detected</p>
                  <p className="text-2xl font-bold text-orange-500">{pending.event_count}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3 text-center">
                  <p className="text-xs text-muted-foreground mb-1">Initial TI Score</p>
                  <p className={cn('text-2xl font-bold', pendingScoreColor)}>
                    {pending.threat_score}%
                  </p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3 text-center">
                  <p className="text-xs text-muted-foreground mb-1">Last Event</p>
                  <p className="text-sm font-medium">{formatDateTime(pending.last_event)}</p>
                </div>
              </div>

              {/* Reason */}
              <div className="bg-muted/30 rounded-lg p-3 border">
                <p className="text-xs text-muted-foreground mb-1">Detection Reason</p>
                <p className="text-sm">{pending.reason}</p>
              </div>

              {/* v3.57.118: FP-specific details */}
              {pending.pending_type === 'false_positive' && (pending.fp_rule_id || pending.fp_uri) && (
                <div className="bg-purple-500/5 border border-purple-500/20 rounded-lg p-4 space-y-3">
                  <div className="flex items-center gap-2 mb-2">
                    <FileWarning className="w-4 h-4 text-purple-500" />
                    <span className="font-medium text-purple-500">False Positive Pattern Details</span>
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    {pending.fp_rule_id && (
                      <div>
                        <p className="text-xs text-muted-foreground mb-1">ModSec Rule ID</p>
                        <p className="font-mono bg-muted/50 px-2 py-1 rounded">{pending.fp_rule_id}</p>
                      </div>
                    )}
                    {pending.fp_match_count && (
                      <div>
                        <p className="text-xs text-muted-foreground mb-1">Identical Matches</p>
                        <p className="font-bold text-purple-500">{pending.fp_match_count}+ times</p>
                      </div>
                    )}
                  </div>
                  {pending.fp_uri && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                        <Link2 className="w-3 h-3" /> Target URI
                      </p>
                      <p className="font-mono text-sm bg-muted/50 px-2 py-1 rounded truncate" title={pending.fp_uri}>
                        {pending.fp_uri}
                      </p>
                    </div>
                  )}
                  {pending.fp_hostname && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Target Hostname</p>
                      <p className="font-mono text-sm">{pending.fp_hostname}</p>
                    </div>
                  )}
                  <p className="text-xs text-muted-foreground mt-2 italic">
                    This IP triggered the same ModSec rule on the same URI multiple times, suggesting a misconfigured application or overly strict WAF rules.
                  </p>
                </div>
              )}

              {/* Full TI Score if available */}
              {score && (
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

                  {/* CrowdSec Details */}
                  {score.crowdsec?.found && (
                    <div className="border rounded-lg p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Radio className="w-4 h-4 text-blue-500" />
                          <span className="font-medium">CrowdSec CTI Details</span>
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
                    </div>
                  )}

                  {/* Tags and Details */}
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
                          <ShieldX className="w-3 h-3" />
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

                    {/* Network Info */}
                    <div className="grid grid-cols-3 gap-4 text-sm">
                      <div>
                        <p className="text-xs text-muted-foreground">ASN</p>
                        <p className="font-mono truncate" title={score.asn}>{score.asn || '-'}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">ISP</p>
                        <p className="truncate" title={score.isp}>{score.isp || '-'}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Last Checked</p>
                        <p>{formatDateTime(score.last_checked)}</p>
                      </div>
                    </div>
                  </div>
                </>
              )}

              {/* Attack History Section */}
              <div className="border rounded-lg p-4 space-y-3">
                <div className="flex items-center gap-2 mb-3">
                  <History className="w-4 h-4 text-orange-500" />
                  <span className="font-medium">Detection History</span>
                  <span className="text-xs text-muted-foreground">({attackHistory.length + wafHistory.length} events)</span>
                </div>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {/* Combine and sort by timestamp */}
                  {[
                    ...wafHistory.map(log => ({
                      type: 'waf' as const,
                      id: log.id,
                      timestamp: log.timestamp,
                      data: log
                    })),
                    ...attackHistory.map(event => ({
                      type: 'event' as const,
                      id: event.event_id,
                      timestamp: event.timestamp,
                      data: event
                    }))
                  ]
                    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
                    .slice(0, 30)
                    .map((item) => {
                      if (item.type === 'waf') {
                        const log = item.data as ModSecLog
                        const severityColors: Record<string, string> = {
                          CRITICAL: 'text-red-500 bg-red-500/10',
                          WARNING: 'text-orange-500 bg-orange-500/10',
                          NOTICE: 'text-yellow-500 bg-yellow-500/10',
                          INFO: 'text-blue-500 bg-blue-500/10',
                        }
                        const severityColor = severityColors[log.rule_severity] || 'text-orange-500 bg-orange-500/10'

                        return (
                          <div key={`waf-${log.id}`} className="flex items-start gap-3 text-sm border-b border-border/50 pb-2 last:border-0 last:pb-0">
                            <div className={cn('p-1.5 rounded', severityColor.split(' ')[1])}>
                              <Shield className={cn('w-3.5 h-3.5', severityColor.split(' ')[0])} />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className={cn('font-medium text-xs px-1.5 py-0.5 rounded', severityColor)}>
                                  {log.attack_type || 'WAF'}
                                </span>
                                {log.is_blocking && (
                                  <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/10 text-red-500">Blocked</span>
                                )}
                              </div>
                              <p className="text-xs text-muted-foreground mt-1 truncate" title={log.rule_msg}>
                                {log.rule_msg || 'No message'}
                              </p>
                              <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                                <Clock className="w-3 h-3" />
                                <span>{formatDateTime(log.timestamp)}</span>
                              </div>
                            </div>
                          </div>
                        )
                      } else {
                        const event = item.data as Event
                        const isBlocked = event.action === 'drop' || event.action === 'block' || event.action === 'blocked'
                        const eventColor = isBlocked ? 'text-red-500 bg-red-500/10' : 'text-orange-500 bg-orange-500/10'

                        return (
                          <div key={`event-${event.event_id}`} className="flex items-start gap-3 text-sm border-b border-border/50 pb-2 last:border-0 last:pb-0">
                            <div className={cn('p-1.5 rounded', eventColor.split(' ')[1])}>
                              <ShieldAlert className={cn('w-3.5 h-3.5', eventColor.split(' ')[0])} />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className={cn('font-medium text-xs px-1.5 py-0.5 rounded', eventColor)}>
                                  {event.log_type || 'Event'}
                                </span>
                                {isBlocked && (
                                  <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/10 text-red-500">Blocked</span>
                                )}
                              </div>
                              <p className="text-xs text-muted-foreground mt-1 truncate" title={event.rule_name || event.message}>
                                {event.rule_name || event.message || 'No details'}
                              </p>
                              <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                                <Clock className="w-3 h-3" />
                                <span>{formatDateTime(event.timestamp)}</span>
                              </div>
                            </div>
                          </div>
                        )
                      }
                    })}
                  {/* Empty state */}
                  {attackHistory.length === 0 && wafHistory.length === 0 && (
                    <div className="text-center py-6 text-muted-foreground">
                      <AlertTriangle className="w-8 h-8 mx-auto mb-2 opacity-50" />
                      <p className="text-sm">No attack events found</p>
                    </div>
                  )}
                </div>
              </div>

              {/* External Links */}
              <div className="flex flex-wrap gap-2 pt-2 border-t">
                <a
                  href={`https://www.abuseipdb.com/check/${pending.ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 min-w-[80px] text-center py-2 text-xs bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                >
                  AbuseIPDB <ExternalLink className="inline w-3 h-3 ml-1" />
                </a>
                <a
                  href={`https://www.virustotal.com/gui/ip-address/${pending.ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 min-w-[80px] text-center py-2 text-xs bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                >
                  VirusTotal <ExternalLink className="inline w-3 h-3 ml-1" />
                </a>
                <a
                  href={`https://otx.alienvault.com/indicator/ip/${pending.ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 min-w-[80px] text-center py-2 text-xs bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                >
                  AlienVault <ExternalLink className="inline w-3 h-3 ml-1" />
                </a>
                <a
                  href={`https://app.crowdsec.net/cti/${pending.ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 min-w-[80px] text-center py-2 text-xs bg-muted hover:bg-muted/80 rounded-lg transition-colors"
                >
                  CrowdSec <ExternalLink className="inline w-3 h-3 ml-1" />
                </a>
              </div>
            </>
          )}
        </div>

        {/* Footer - Action Buttons */}
        <div className="p-4 border-t bg-muted/30">
          <div className="flex items-center justify-between gap-4">
            <div className="text-sm text-muted-foreground">
              <span className="flex items-center gap-1">
                <MapPin className="w-4 h-4" />
                GeoZone: <span className="font-medium text-foreground">{pending.geo_zone}</span>
                {pending.geo_zone === 'authorized' && (
                  <span className="text-xs text-amber-500 ml-2">(Requires manual approval)</span>
                )}
              </span>
            </div>
            <div className="flex gap-3">
              <button
                onClick={handleReject}
                disabled={processing}
                className="flex items-center justify-center gap-2 px-6 py-2.5 bg-green-500/10 text-green-500 border border-green-500/30 rounded-lg hover:bg-green-500/20 transition-colors font-medium disabled:opacity-50"
              >
                {processing ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <CheckCircle className="w-4 h-4" />
                )}
                Deny Ban (Allow IP)
              </button>
              <button
                onClick={handleApprove}
                disabled={processing}
                className="flex items-center justify-center gap-2 px-6 py-2.5 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors font-medium disabled:opacity-50"
              >
                {processing ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Ban className="w-4 h-4" />
                )}
                Approve Ban
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
