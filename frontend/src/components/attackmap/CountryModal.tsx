import { X, Shield, Users, AlertTriangle, TrendingUp, Skull } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAttackMapStore, getThreatColor, type CountryAttackStats } from '@/stores/attackMapStore'

interface CountryModalProps {
  isOpen: boolean
  onClose: () => void
  countryCode: string | null
  countryName: string
  stats?: CountryAttackStats
}

// Get flag emoji from country code
function getFlagEmoji(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return '🌐'
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0))
  return String.fromCodePoint(...codePoints)
}

// Threat level badge component
function ThreatBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-green-500/20 text-green-400 border-green-500/30',
    minimal: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  }

  return (
    <span className={cn(
      'px-2 py-0.5 text-xs font-medium rounded-full border uppercase',
      colors[level] || colors.minimal
    )}>
      {level}
    </span>
  )
}

export function CountryModal({
  isOpen,
  onClose,
  countryCode,
  countryName,
  stats,
}: CountryModalProps) {
  const { selectedCountryDetails } = useAttackMapStore()

  if (!isOpen || !countryCode) return null

  const topAttackers = selectedCountryDetails?.topAttackers || []
  const attackTypes = selectedCountryDetails?.attackTypes || []

  return (
    <div className="fixed inset-0 z-[2000] flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-full max-w-2xl max-h-[80vh] bg-gray-900 border border-gray-700 rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div
          className="relative px-6 py-4 border-b border-gray-700"
          style={{
            background: stats
              ? `linear-gradient(135deg, ${getThreatColor(stats.threatLevel).replace('0.', '0.1')}, transparent)`
              : undefined,
          }}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <span className="text-4xl">{getFlagEmoji(countryCode)}</span>
              <div>
                <h2 className="text-xl font-bold text-white">{countryName}</h2>
                <p className="text-sm text-gray-400">Country Code: {countryCode}</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Threat level badge */}
          {stats && (
            <div className="absolute top-4 right-14">
              <ThreatBadge level={stats.threatLevel} />
            </div>
          )}
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(80vh-80px)]">
          {/* Stats grid */}
          {stats && (
            <div className="grid grid-cols-2 gap-4 mb-6">
              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                <div className="flex items-center gap-2 text-red-400 mb-2">
                  <Shield className="w-4 h-4" />
                  <span className="text-sm font-medium">Total Attacks</span>
                </div>
                <p className="text-2xl font-bold text-white">
                  {stats.count.toLocaleString()}
                </p>
              </div>
              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                <div className="flex items-center gap-2 text-cyan-400 mb-2">
                  <Users className="w-4 h-4" />
                  <span className="text-sm font-medium">Unique IPs</span>
                </div>
                <p className="text-2xl font-bold text-white">
                  {stats.uniqueIps.toLocaleString()}
                </p>
              </div>
            </div>
          )}

          {/* Top attackers */}
          {topAttackers.length > 0 && (
            <div className="mb-6">
              <h3 className="flex items-center gap-2 text-sm font-medium text-gray-400 mb-3">
                <Skull className="w-4 h-4" />
                Top Attacking IPs
              </h3>
              <div className="space-y-2">
                {topAttackers.slice(0, 10).map((attacker, idx) => (
                  <div
                    key={attacker.ip}
                    className="flex items-center justify-between bg-gray-800/50 rounded-lg px-4 py-3 border border-gray-700"
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-gray-500 w-5">#{idx + 1}</span>
                      <code className="text-sm font-mono text-white">{attacker.ip}</code>
                      {attacker.threatScore !== undefined && attacker.threatScore > 70 && (
                        <AlertTriangle className="w-4 h-4 text-red-400" />
                      )}
                    </div>
                    <div className="flex items-center gap-4 text-sm">
                      <span className="text-red-400">
                        {attacker.attackCount.toLocaleString()} attacks
                      </span>
                      {attacker.blockedCount > 0 && (
                        <span className="text-green-400">
                          {attacker.blockedCount.toLocaleString()} blocked
                        </span>
                      )}
                      {attacker.threatScore !== undefined && (
                        <span className={cn(
                          'px-2 py-0.5 rounded text-xs font-medium',
                          attacker.threatScore > 70 ? 'bg-red-500/20 text-red-400' :
                          attacker.threatScore > 40 ? 'bg-orange-500/20 text-orange-400' :
                          'bg-gray-500/20 text-gray-400'
                        )}>
                          Score: {attacker.threatScore}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Attack types */}
          {attackTypes.length > 0 && (
            <div>
              <h3 className="flex items-center gap-2 text-sm font-medium text-gray-400 mb-3">
                <TrendingUp className="w-4 h-4" />
                Attack Categories
              </h3>
              <div className="flex flex-wrap gap-2">
                {attackTypes.map(({ type, count }) => (
                  <div
                    key={type}
                    className="flex items-center gap-2 bg-gray-800/50 rounded-lg px-3 py-2 border border-gray-700"
                  >
                    <span className="text-sm text-white">{type}</span>
                    <span className="text-xs text-gray-400 bg-gray-700 px-2 py-0.5 rounded">
                      {count.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* No data message */}
          {!stats && topAttackers.length === 0 && (
            <div className="text-center py-8 text-gray-400">
              <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>No attack data available for this country</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
