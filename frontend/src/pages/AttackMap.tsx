import { useEffect, useCallback, useState, useRef } from 'react'
import { MapContainer, TileLayer } from 'react-leaflet'
import { Map as LeafletMap } from 'leaflet'
import 'leaflet/dist/leaflet.css'
import {
  Globe,
  Maximize2,
  Minimize2,
  RefreshCw,
  Wifi,
  WifiOff,
  Activity,
  Shield,
  Zap,
  Calendar,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  useAttackMapStore,
  TARGET_LOCATION,
  COUNTRY_CENTROIDS,
  getThreatLevel,
  getFlowIntensity,
  ATTACK_TYPE_CONFIG,
  type CountryAttackStats,
  type AttackFlow,
  type MapPeriod,
  type AttackType,
} from '@/stores/attackMapStore'
import { geoApi, statsApi } from '@/lib/api'
import { CountryLayer } from '@/components/attackmap/CountryLayer'
import { AttackFlowLayer } from '@/components/attackmap/AttackFlowLayer'
import { TargetMarker } from '@/components/attackmap/TargetMarker'
import { CountryModal } from '@/components/attackmap/CountryModal'
import { AttackMapLegend } from '@/components/attackmap/AttackMapLegend'

// ISO Alpha-3 to Alpha-2 country code mapping
const ALPHA3_TO_ALPHA2: Record<string, string> = {
  'USA': 'US', 'CHN': 'CN', 'RUS': 'RU', 'IND': 'IN', 'BRA': 'BR',
  'DEU': 'DE', 'FRA': 'FR', 'GBR': 'GB', 'NLD': 'NL', 'UKR': 'UA',
  'KOR': 'KR', 'JPN': 'JP', 'IRN': 'IR', 'VNM': 'VN', 'IDN': 'ID',
  'THA': 'TH', 'PAK': 'PK', 'BGD': 'BD', 'NGA': 'NG', 'EGY': 'EG',
  'TUR': 'TR', 'MEX': 'MX', 'ARG': 'AR', 'COL': 'CO', 'ZAF': 'ZA',
  'POL': 'PL', 'ITA': 'IT', 'ESP': 'ES', 'CAN': 'CA', 'AUS': 'AU',
  'SGP': 'SG', 'HKG': 'HK', 'TWN': 'TW', 'MYS': 'MY', 'PHL': 'PH',
  'SAU': 'SA', 'ARE': 'AE', 'ISR': 'IL', 'ROU': 'RO', 'CZE': 'CZ',
  'SWE': 'SE', 'NOR': 'NO', 'FIN': 'FI', 'DNK': 'DK', 'AUT': 'AT',
  'CHE': 'CH', 'BEL': 'BE', 'PRT': 'PT', 'GRC': 'GR', 'HUN': 'HU',
  'BGR': 'BG', 'LUX': 'LU', 'LTU': 'LT', 'LVA': 'LV', 'EST': 'EE',
  'SVK': 'SK', 'SVN': 'SI', 'HRV': 'HR', 'SRB': 'RS', 'UZB': 'UZ',
  'KAZ': 'KZ', 'BLR': 'BY', 'MDA': 'MD', 'GEO': 'GE', 'ARM': 'AM',
  'AZE': 'AZ', 'IRQ': 'IQ', 'SYR': 'SY', 'JOR': 'JO', 'LBN': 'LB',
  'KWT': 'KW', 'QAT': 'QA', 'BHR': 'BH', 'OMN': 'OM', 'YEM': 'YE',
  'AFG': 'AF', 'NPL': 'NP', 'LKA': 'LK', 'MMR': 'MM', 'KHM': 'KH',
  'LAO': 'LA', 'MNG': 'MN', 'PRK': 'KP', 'NZL': 'NZ', 'PER': 'PE',
  'CHL': 'CL', 'VEN': 'VE', 'ECU': 'EC', 'BOL': 'BO', 'PRY': 'PY',
  'URY': 'UY', 'CRI': 'CR', 'PAN': 'PA', 'GTM': 'GT', 'HND': 'HN',
  'SLV': 'SV', 'NIC': 'NI', 'CUB': 'CU', 'DOM': 'DO', 'HTI': 'HT',
  'JAM': 'JM', 'TTO': 'TT', 'MAR': 'MA', 'DZA': 'DZ', 'TUN': 'TN',
  'LBY': 'LY', 'SDN': 'SD', 'ETH': 'ET', 'KEN': 'KE', 'TZA': 'TZ',
  'UGA': 'UG', 'GHA': 'GH', 'CIV': 'CI', 'CMR': 'CM', 'AGO': 'AO',
  'ZWE': 'ZW', 'ZMB': 'ZM', 'MOZ': 'MZ', 'BWA': 'BW', 'NAM': 'NA',
  'SEN': 'SN', 'MLI': 'ML', 'BFA': 'BF', 'NER': 'NE', 'TCD': 'TD',
  'COD': 'CD', 'COG': 'CG', 'GAB': 'GA', 'GNQ': 'GQ', 'RWA': 'RW',
  'BDI': 'BI', 'MWI': 'MW', 'MDG': 'MG', 'MUS': 'MU', 'SYC': 'SC',
  // Special/Reserved
  'R1': 'XX', // Reserved/Private range
  '': 'XX',
}

// Convert country code (handles both alpha-2 and alpha-3)
function toAlpha2(code: string): string {
  if (!code) return 'XX'
  const upper = code.toUpperCase()
  // Already alpha-2
  if (upper.length === 2) return upper
  // Convert alpha-3 to alpha-2
  return ALPHA3_TO_ALPHA2[upper] || 'XX'
}

// Country name mapping (alpha-2 codes)
const COUNTRY_NAMES: Record<string, string> = {
  'US': 'United States',
  'CN': 'China',
  'RU': 'Russia',
  'IN': 'India',
  'BR': 'Brazil',
  'DE': 'Germany',
  'FR': 'France',
  'GB': 'United Kingdom',
  'NL': 'Netherlands',
  'UA': 'Ukraine',
  'KR': 'South Korea',
  'JP': 'Japan',
  'IR': 'Iran',
  'VN': 'Vietnam',
  'ID': 'Indonesia',
  'TH': 'Thailand',
  'PK': 'Pakistan',
  'BD': 'Bangladesh',
  'NG': 'Nigeria',
  'EG': 'Egypt',
  'TR': 'Turkey',
  'MX': 'Mexico',
  'AR': 'Argentina',
  'CO': 'Colombia',
  'ZA': 'South Africa',
  'PL': 'Poland',
  'IT': 'Italy',
  'ES': 'Spain',
  'CA': 'Canada',
  'AU': 'Australia',
  'SG': 'Singapore',
  'HK': 'Hong Kong',
  'TW': 'Taiwan',
  'MY': 'Malaysia',
  'PH': 'Philippines',
  'SA': 'Saudi Arabia',
  'AE': 'UAE',
  'IL': 'Israel',
  'RO': 'Romania',
  'CZ': 'Czech Republic',
  'SE': 'Sweden',
  'NO': 'Norway',
  'FI': 'Finland',
  'DK': 'Denmark',
  'AT': 'Austria',
  'CH': 'Switzerland',
  'BE': 'Belgium',
  'PT': 'Portugal',
  'GR': 'Greece',
  'HU': 'Hungary',
  'BG': 'Bulgaria',
  'LU': 'Luxembourg',
  'LT': 'Lithuania',
  'LV': 'Latvia',
  'EE': 'Estonia',
  'XX': 'Unknown',
}

// Period selector component with custom date support (v3.53.105)
function PeriodSelector({
  period,
  onChange,
  customDate,
  onCustomDateChange,
}: {
  period: MapPeriod | 'custom'
  onChange: (period: MapPeriod) => void
  customDate: string
  onCustomDateChange: (date: string) => void
}) {
  // v3.57.117: Added 8h period
  const periods: { value: MapPeriod; label: string }[] = [
    { value: 'live', label: 'Live' },
    { value: '8h', label: '8h' },
    { value: '24h', label: '24h' },
    { value: '7d', label: '7d' },
    { value: '30d', label: '30d' },
  ]

  const isCustom = customDate !== ''

  return (
    <div className="flex items-center gap-2">
      <div className="flex items-center gap-1 bg-black/60 backdrop-blur-sm rounded-lg p-1">
        {periods.map((p) => (
          <button
            key={p.value}
            onClick={() => {
              onCustomDateChange('') // Clear custom date when selecting preset
              onChange(p.value)
            }}
            className={cn(
              'px-3 py-1.5 text-sm font-medium rounded-md transition-all',
              period === p.value && !isCustom
                ? p.value === 'live'
                  ? 'bg-red-500 text-white shadow-lg shadow-red-500/30'
                  : 'bg-primary text-primary-foreground'
                : 'text-gray-300 hover:text-white hover:bg-white/10'
            )}
          >
            {p.value === 'live' && (
              <span className="inline-block w-2 h-2 bg-white rounded-full mr-1.5 animate-pulse" />
            )}
            {p.label}
          </button>
        ))}
      </div>
      {/* Custom date picker */}
      <div className={cn(
        'flex items-center gap-1 backdrop-blur-sm rounded-lg p-1 transition-all',
        isCustom ? 'bg-cyan-500/20 ring-1 ring-cyan-500/50' : 'bg-black/60'
      )}>
        <div className="relative flex items-center">
          <Calendar className={cn(
            'absolute left-2 w-4 h-4 pointer-events-none z-10',
            isCustom ? 'text-cyan-400' : 'text-gray-400'
          )} />
          <input
            type="date"
            value={customDate}
            onChange={(e) => onCustomDateChange(e.target.value)}
            max={new Date().toISOString().split('T')[0]}
            className={cn(
              'pl-8 pr-2 py-1.5 text-sm font-medium rounded-md transition-all bg-transparent border-0 focus:outline-none focus:ring-0 cursor-pointer',
              isCustom ? 'text-cyan-400' : 'text-gray-400 hover:text-white',
              '[color-scheme:dark]'
            )}
            title="Select a specific date to view attacks"
          />
        </div>
      </div>
    </div>
  )
}

// Attack type filter component
function AttackTypeFilter({
  activeTypes,
  onToggle,
}: {
  activeTypes: Set<AttackType>
  onToggle: (type: AttackType) => void
}) {
  const types: AttackType[] = ['waf', 'ips', 'malware', 'threat']

  return (
    <div className="flex items-center gap-1 bg-black/60 backdrop-blur-sm rounded-lg p-1">
      {types.map((type) => {
        const config = ATTACK_TYPE_CONFIG[type]
        const isActive = activeTypes.has(type)
        return (
          <button
            key={type}
            onClick={() => onToggle(type)}
            className={cn(
              'px-3 py-1.5 text-sm font-medium rounded-md transition-all flex items-center gap-2',
              isActive
                ? 'text-white shadow-lg'
                : 'text-gray-400 hover:text-white hover:bg-white/10'
            )}
            style={isActive ? {
              backgroundColor: config.color.replace('0.8', '0.9'),
              boxShadow: `0 4px 14px ${config.color.replace('0.8', '0.4')}`,
            } : undefined}
            title={config.description}
          >
            <span
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: config.color }}
            />
            {config.label}
          </button>
        )
      })}
    </div>
  )
}

// Stats bar component
function StatsBar({
  totalAttacks,
  uniqueCountries,
  topCountry,
  isLive,
}: {
  totalAttacks: number
  uniqueCountries: number
  topCountry: string | null
  isLive: boolean
}) {
  return (
    <div className="flex items-center gap-6 bg-black/60 backdrop-blur-sm rounded-lg px-4 py-2">
      <div className="flex items-center gap-2">
        <Shield className="w-4 h-4 text-red-400" />
        <div>
          <p className="text-xs text-gray-400">Total Attacks</p>
          <p className="text-lg font-bold text-white">
            {totalAttacks.toLocaleString()}
            {isLive && <Zap className="inline w-3 h-3 ml-1 text-yellow-400 animate-pulse" />}
          </p>
        </div>
      </div>
      <div className="w-px h-8 bg-gray-600" />
      <div className="flex items-center gap-2">
        <Globe className="w-4 h-4 text-cyan-400" />
        <div>
          <p className="text-xs text-gray-400">Countries</p>
          <p className="text-lg font-bold text-white">{uniqueCountries}</p>
        </div>
      </div>
      {topCountry && (
        <>
          <div className="w-px h-8 bg-gray-600" />
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-orange-400" />
            <div>
              <p className="text-xs text-gray-400">Top Source</p>
              <p className="text-lg font-bold text-white">{topCountry}</p>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export function AttackMap() {
  const mapRef = useRef<LeafletMap | null>(null)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const [customDate, setCustomDate] = useState('') // v3.53.105: Custom date selection

  const {
    period,
    setPeriod,
    activeAttackTypes,
    toggleAttackType,
    countryStats,
    setCountryStats,
    attackFlows,
    setAttackFlows,
    loading,
    setLoading,
    isConnected,
    setIsConnected,
    totalAttacks,
    setTotalAttacks,
    selectedCountry,
    setSelectedCountry,
    setSelectedCountryDetails,
  } = useAttackMapStore()

  // Fetch attack data
  // v3.57.108: Enhanced to fetch per-type data for proper color-coding
  const fetchData = useCallback(async () => {
    const attackTypesArray = Array.from(activeAttackTypes)

    // If no filters selected, clear data and show nothing
    if (attackTypesArray.length === 0) {
      setCountryStats([])
      setAttackFlows([])
      setTotalAttacks(0)
      setIsConnected(true)
      return
    }

    setLoading(true)
    try {
      // v3.53.105: Support custom date range
      const apiPeriod = customDate ? '24h' : (period === 'live' ? '1h' : period)
      const dateRange = customDate ? {
        start: `${customDate}T00:00:00Z`,
        end: `${customDate}T23:59:59Z`,
      } : undefined

      // v3.57.108: Fetch data per attack type for proper color-coding
      const typeDataPromises = attackTypesArray.map(type =>
        geoApi.heatmap(apiPeriod, [type], dateRange).then(data => ({ type, data }))
      )

      const typeResults = await Promise.all(typeDataPromises)

      // Build country stats with dominant type tracking
      const countryTypeMap: Record<string, { count: number; type: AttackType }[]> = {}
      const countryStatsMap: Record<string, { count: number; uniqueIps: number; dominantType: AttackType }> = {}

      typeResults.forEach(({ type, data }) => {
        (data || []).forEach((d: { country: string; count: number; unique_ips: number }) => {
          const code = toAlpha2(d.country)
          if (code === 'XX') return

          if (!countryTypeMap[code]) {
            countryTypeMap[code] = []
          }
          countryTypeMap[code].push({ count: d.count, type })

          if (!countryStatsMap[code]) {
            countryStatsMap[code] = { count: 0, uniqueIps: 0, dominantType: type }
          }
          countryStatsMap[code].count += d.count
          countryStatsMap[code].uniqueIps = Math.max(countryStatsMap[code].uniqueIps, d.unique_ips)
        })
      })

      // v3.57.110: Determine dominant type for each country using PRIORITY (not count)
      // Priority order: threat > malware > ips > waf (rare attacks take precedence)
      const TYPE_PRIORITY: Record<AttackType, number> = {
        threat: 4,   // Highest priority - most critical
        malware: 3,  // High priority - dangerous
        ips: 2,      // Medium priority - intrusion attempts
        waf: 1,      // Lowest priority - most common
      }

      Object.keys(countryTypeMap).forEach(code => {
        const types = countryTypeMap[code]
        // Sort by priority (highest first), then by count as tiebreaker
        const dominant = types.reduce((prev, curr) => {
          const prevPriority = TYPE_PRIORITY[prev.type] || 0
          const currPriority = TYPE_PRIORITY[curr.type] || 0
          if (currPriority > prevPriority) return curr
          if (currPriority === prevPriority && curr.count > prev.count) return curr
          return prev
        })
        if (countryStatsMap[code]) {
          countryStatsMap[code].dominantType = dominant.type
        }
      })

      // Transform to CountryAttackStats array
      const maxCount = Math.max(...Object.values(countryStatsMap).map(d => d.count), 1)
      const stats: CountryAttackStats[] = Object.entries(countryStatsMap)
        .map(([code, data]) => ({
          countryCode: code,
          countryName: COUNTRY_NAMES[code] || code,
          count: data.count,
          uniqueIps: data.uniqueIps,
          threatLevel: getThreatLevel(data.count, maxCount),
          centroid: COUNTRY_CENTROIDS[code] || COUNTRY_CENTROIDS['XX'],
        }))
        .filter(d => COUNTRY_CENTROIDS[d.countryCode])
        .sort((a, b) => b.count - a.count)

      setCountryStats(stats)
      setTotalAttacks(stats.reduce((sum, s) => sum + s.count, 0))

      // v3.57.108: Generate flows with attack-type-specific colors (orange=WAF, red=IPS)
      const flows: AttackFlow[] = stats
        .filter(s => s.count > 0 && COUNTRY_CENTROIDS[s.countryCode])
        .slice(0, 30)
        .map(s => {
          const dominantType = countryStatsMap[s.countryCode]?.dominantType || 'waf'
          return {
            id: `${s.countryCode}-${Date.now()}-${Math.random()}`,
            sourceCountry: s.countryCode,
            sourceLat: s.centroid[0],
            sourceLng: s.centroid[1],
            targetLat: TARGET_LOCATION.lat,
            targetLng: TARGET_LOCATION.lng,
            timestamp: new Date(),
            intensity: getFlowIntensity(s.count, maxCount),
            color: ATTACK_TYPE_CONFIG[dominantType].color, // Use attack-type-specific color
          }
        })

      setAttackFlows(flows)
      setIsConnected(true)
    } catch (err) {
      console.error('Failed to fetch attack map data:', err)
      setIsConnected(false)
    } finally {
      setLoading(false)
    }
  }, [period, customDate, activeAttackTypes, setCountryStats, setAttackFlows, setLoading, setIsConnected, setTotalAttacks])

  // Initial fetch and periodic refresh
  useEffect(() => {
    fetchData()

    // v3.53.105: Don't auto-refresh when viewing custom date
    if (customDate) return

    // Refresh interval based on period
    const interval = period === 'live' ? 10000 : 60000
    const timer = setInterval(fetchData, interval)

    return () => clearInterval(timer)
  }, [fetchData, period, customDate])

  // Handle country click
  const handleCountryClick = useCallback(async (countryCode: string) => {
    setSelectedCountry(countryCode)

    // Fetch detailed data for this country
    try {
      const apiPeriod = period === 'live' ? '1h' : period
      const topAttackers = await statsApi.topAttackers(apiPeriod, 20)

      const countryAttackers = topAttackers
        .filter(a => a.country === countryCode)
        .map(a => ({
          ip: a.ip,
          attackCount: a.attack_count,
          blockedCount: a.blocked_count,
          country: a.country,
          threatScore: a.threat_score,
          categories: a.categories || [],
        }))

      // Aggregate attack types from categories
      const attackTypeCounts: Record<string, number> = {}
      countryAttackers.forEach(a => {
        a.categories.forEach(cat => {
          attackTypeCounts[cat] = (attackTypeCounts[cat] || 0) + a.attackCount
        })
      })

      const attackTypes = Object.entries(attackTypeCounts)
        .map(([type, count]) => ({ type, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10)

      setSelectedCountryDetails({ topAttackers: countryAttackers, attackTypes })
    } catch (err) {
      console.error('Failed to fetch country details:', err)
    }
  }, [period, setSelectedCountry, setSelectedCountryDetails])

  // Toggle fullscreen
  const toggleFullscreen = useCallback(() => {
    if (!containerRef.current) return

    if (!isFullscreen) {
      containerRef.current.requestFullscreen?.()
    } else {
      document.exitFullscreen?.()
    }
  }, [isFullscreen])

  // Listen for fullscreen changes
  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement)
    }
    document.addEventListener('fullscreenchange', handleFullscreenChange)
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange)
  }, [])

  // Get stats for display
  const statsArray = Array.from(countryStats.values())
  const uniqueCountries = statsArray.length
  const topCountry = statsArray.sort((a, b) => b.count - a.count)[0]?.countryCode || null

  return (
    <div
      ref={containerRef}
      className={cn(
        'relative w-full bg-gray-900 overflow-hidden',
        isFullscreen ? 'h-screen' : 'h-[calc(100vh-4rem)]'
      )}
    >
      {/* Map */}
      <MapContainer
        center={[30, 10]}
        zoom={2.5}
        minZoom={2}
        maxZoom={8}
        className="w-full h-full"
        zoomControl={false}
        attributionControl={false}
        ref={mapRef}
        worldCopyJump={true}
      >
        {/* Dark map tiles */}
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
        />

        {/* Country layer with attack data */}
        <CountryLayer
          countryStats={countryStats}
          onCountryClick={handleCountryClick}
        />

        {/* Attack flow animations */}
        <AttackFlowLayer flows={attackFlows} isLive={period === 'live'} />

        {/* Target marker */}
        <TargetMarker
          position={[TARGET_LOCATION.lat, TARGET_LOCATION.lng]}
          name={TARGET_LOCATION.name}
        />
      </MapContainer>

      {/* Top controls overlay */}
      <div className="absolute top-4 left-4 right-4 z-[1000] flex items-start justify-between pointer-events-none">
        {/* Left side - Title & Period */}
        <div className="flex flex-col gap-3 pointer-events-auto">
          <div className="flex items-center gap-3 bg-black/60 backdrop-blur-sm rounded-lg px-4 py-2">
            <Globe className="w-6 h-6 text-cyan-400" />
            <div>
              <h1 className="text-xl font-bold text-white">Attack Map</h1>
              <p className="text-xs text-gray-400">
                {customDate
                  ? `Viewing attacks from ${new Date(customDate).toLocaleDateString()}`
                  : 'Real-time threat visualization'}
              </p>
            </div>
          </div>
          <PeriodSelector
            period={customDate ? 'custom' as any : period}
            onChange={setPeriod}
            customDate={customDate}
            onCustomDateChange={setCustomDate}
          />
          <AttackTypeFilter activeTypes={activeAttackTypes} onToggle={toggleAttackType} />
        </div>

        {/* Right side - Stats & Controls */}
        <div className="flex flex-col gap-3 items-end pointer-events-auto">
          <StatsBar
            totalAttacks={totalAttacks}
            uniqueCountries={uniqueCountries}
            topCountry={topCountry ? (COUNTRY_NAMES[topCountry] || topCountry) : null}
            isLive={period === 'live'}
          />
          <div className="flex items-center gap-2">
            {/* Connection status */}
            <div
              className={cn(
                'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm',
                isConnected
                  ? 'bg-green-500/20 text-green-400'
                  : 'bg-red-500/20 text-red-400'
              )}
            >
              {isConnected ? (
                <Wifi className="w-4 h-4" />
              ) : (
                <WifiOff className="w-4 h-4" />
              )}
              {isConnected ? 'Connected' : 'Offline'}
            </div>

            {/* Refresh button */}
            <button
              onClick={() => fetchData()}
              disabled={loading}
              className="p-2 bg-black/60 backdrop-blur-sm rounded-lg text-gray-300 hover:text-white hover:bg-white/10 transition-colors disabled:opacity-50"
              title="Refresh data"
            >
              <RefreshCw className={cn('w-5 h-5', loading && 'animate-spin')} />
            </button>

            {/* Fullscreen button */}
            <button
              onClick={toggleFullscreen}
              className="p-2 bg-black/60 backdrop-blur-sm rounded-lg text-gray-300 hover:text-white hover:bg-white/10 transition-colors"
              title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
            >
              {isFullscreen ? (
                <Minimize2 className="w-5 h-5" />
              ) : (
                <Maximize2 className="w-5 h-5" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Bottom legend */}
      <AttackMapLegend />

      {/* Loading overlay */}
      {loading && countryStats.size === 0 && (
        <div className="absolute inset-0 z-[1000] flex items-center justify-center bg-gray-900/80">
          <div className="flex flex-col items-center gap-4">
            <div className="w-12 h-12 border-4 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            <p className="text-gray-300">Loading attack data...</p>
          </div>
        </div>
      )}

      {/* No filters selected message */}
      {!loading && activeAttackTypes.size === 0 && (
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-[1000] bg-black/80 backdrop-blur-sm rounded-lg p-6 text-center max-w-md">
          <Shield className="w-12 h-12 mx-auto mb-3 text-gray-500" />
          <h3 className="text-lg font-semibold text-white mb-2">Select Attack Types</h3>
          <p className="text-gray-400 text-sm">
            Select one or more attack types (WAF, IPS/IDS, Malware, Threat) to visualize attack flows on the map.
          </p>
        </div>
      )}

      {/* No data for selected filters message */}
      {!loading && activeAttackTypes.size > 0 && countryStats.size === 0 && totalAttacks === 0 && (
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-[1000] bg-black/80 backdrop-blur-sm rounded-lg p-6 text-center max-w-md">
          <Shield className="w-12 h-12 mx-auto mb-3 text-gray-500" />
          <h3 className="text-lg font-semibold text-white mb-2">No Attack Data</h3>
          <p className="text-gray-400 text-sm">
            No attacks found for {Array.from(activeAttackTypes).map(t => ATTACK_TYPE_CONFIG[t].label).join(', ')}
            {' '}in the last {period === 'live' ? 'hour' : period}.
          </p>
          <p className="text-gray-500 text-xs mt-2">
            Try selecting different attack types or extending the time period.
          </p>
        </div>
      )}

      {/* Country detail modal */}
      <CountryModal
        isOpen={!!selectedCountry}
        onClose={() => {
          setSelectedCountry(null)
          setSelectedCountryDetails(null)
        }}
        countryCode={selectedCountry}
        countryName={selectedCountry ? (COUNTRY_NAMES[selectedCountry] || selectedCountry) : ''}
        stats={selectedCountry ? countryStats.get(selectedCountry) : undefined}
      />
    </div>
  )
}
