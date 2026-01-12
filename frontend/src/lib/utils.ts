import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatNumber(num: number): string {
  if (num >= 1000000) {
    return (num / 1000000).toFixed(1) + 'M'
  }
  if (num >= 1000) {
    return (num / 1000).toFixed(1) + 'K'
  }
  return num.toLocaleString()
}

export function formatPercent(num: number): string {
  return num.toFixed(1) + '%'
}

export function formatDateTime(date: string | Date): string {
  const d = new Date(date)
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatDateTimeFull(date: string | Date): string {
  const d = new Date(date)
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatDateOnly(date: string | Date): string {
  const d = new Date(date)
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

export function formatTimeOnly(date: string | Date): string {
  const d = new Date(date)
  return d.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function getSeverityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'text-red-500'
    case 'high':
      return 'text-orange-500'
    case 'medium':
      return 'text-yellow-500'
    case 'low':
      return 'text-blue-500'
    default:
      return 'text-gray-500'
  }
}

export function getSeverityBgColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-red-500/10'
    case 'high':
      return 'bg-orange-500/10'
    case 'medium':
      return 'bg-yellow-500/10'
    case 'low':
      return 'bg-blue-500/10'
    default:
      return 'bg-gray-500/10'
  }
}

export function getThreatLevelColor(level: string): string {
  switch (level.toLowerCase()) {
    case 'critical':
      return 'text-red-500'
    case 'high':
      return 'text-orange-500'
    case 'medium':
      return 'text-yellow-500'
    case 'low':
      return 'text-blue-500'
    case 'minimal':
      return 'text-green-500'
    default:
      return 'text-gray-500'
  }
}

export function getActionColor(action: string): string {
  switch (action.toLowerCase()) {
    case 'drop':
    case 'block':
    case 'reject':
      return 'text-red-400'
    case 'allow':
    case 'pass':
    case 'accept':
      return 'text-green-400'
    default:
      return 'text-gray-400'
  }
}

export function truncateIP(ip: string, maxLength: number = 15): string {
  if (ip.length <= maxLength) return ip
  return ip.substring(0, maxLength - 3) + '...'
}

// ISO 3166-1 alpha-3 to alpha-2 mapping for common countries
const iso3to2: Record<string, string> = {
  'FRA': 'FR', 'LUX': 'LU', 'USA': 'US', 'NLD': 'NL', 'DEU': 'DE', 'GBR': 'GB',
  'BEL': 'BE', 'CHE': 'CH', 'ITA': 'IT', 'ESP': 'ES', 'PRT': 'PT', 'POL': 'PL',
  'AUT': 'AT', 'CZE': 'CZ', 'HUN': 'HU', 'ROU': 'RO', 'BGR': 'BG', 'GRC': 'GR',
  'SWE': 'SE', 'NOR': 'NO', 'DNK': 'DK', 'FIN': 'FI', 'IRL': 'IE', 'CAN': 'CA',
  'AUS': 'AU', 'NZL': 'NZ', 'JPN': 'JP', 'CHN': 'CN', 'KOR': 'KR', 'IND': 'IN',
  'BRA': 'BR', 'ARG': 'AR', 'MEX': 'MX', 'RUS': 'RU', 'UKR': 'UA', 'TUR': 'TR',
  'ISR': 'IL', 'ARE': 'AE', 'SAU': 'SA', 'SGP': 'SG', 'HKG': 'HK', 'TWN': 'TW',
  'THA': 'TH', 'VNM': 'VN', 'IDN': 'ID', 'MYS': 'MY', 'PHL': 'PH', 'ZAF': 'ZA',
}

export function getCountryFlag(countryCode: string): string {
  if (!countryCode) return ''

  // Convert 3-letter to 2-letter code if needed
  let code = countryCode.toUpperCase()
  if (code.length === 3) {
    code = iso3to2[code] || ''
  }

  if (code.length !== 2) return ''

  const codePoints = code
    .split('')
    .map((char) => 127397 + char.charCodeAt(0))

  return String.fromCodePoint(...codePoints)
}

export function getCountryName(countryCode: string): string {
  const names: Record<string, string> = {
    'FRA': 'France', 'FR': 'France',
    'LUX': 'Luxembourg', 'LU': 'Luxembourg',
    'USA': 'United States', 'US': 'United States',
    'NLD': 'Netherlands', 'NL': 'Netherlands',
    'DEU': 'Germany', 'DE': 'Germany',
    'GBR': 'United Kingdom', 'GB': 'United Kingdom',
    'BEL': 'Belgium', 'BE': 'Belgium',
    'CHE': 'Switzerland', 'CH': 'Switzerland',
    'ITA': 'Italy', 'IT': 'Italy',
    'ESP': 'Spain', 'ES': 'Spain',
    'NOR': 'Norway', 'NO': 'Norway',
    'SWE': 'Sweden', 'SE': 'Sweden',
    'DNK': 'Denmark', 'DK': 'Denmark',
    'FIN': 'Finland', 'FI': 'Finland',
    'POL': 'Poland', 'PL': 'Poland',
    'CZE': 'Czech Republic', 'CZ': 'Czech Republic',
    'AUT': 'Austria', 'AT': 'Austria',
    'RUS': 'Russia', 'RU': 'Russia',
    'UKR': 'Ukraine', 'UA': 'Ukraine',
    'CHN': 'China', 'CN': 'China',
    'JPN': 'Japan', 'JP': 'Japan',
    'KOR': 'South Korea', 'KR': 'South Korea',
    'IND': 'India', 'IN': 'India',
    'BRA': 'Brazil', 'BR': 'Brazil',
    'CAN': 'Canada', 'CA': 'Canada',
    'AUS': 'Australia', 'AU': 'Australia',
  }
  return names[countryCode?.toUpperCase()] || countryCode || ''
}
