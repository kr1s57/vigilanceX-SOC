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

export function getCountryFlag(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return ''

  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map((char) => 127397 + char.charCodeAt(0))

  return String.fromCodePoint(...codePoints)
}
