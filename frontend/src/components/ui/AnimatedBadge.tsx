import { ReactNode } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

/**
 * AnimatedBadge - Animated badge component for alerts and status indicators
 * v3.58.108: Uses Tailwind animations + Framer Motion
 */

interface AnimatedBadgeProps {
  children: ReactNode
  variant?: 'default' | 'critical' | 'warning' | 'success' | 'info' | 'neutral'
  size?: 'sm' | 'md' | 'lg'
  animated?: boolean
  pulse?: boolean
  glow?: boolean
  className?: string
}

const variantStyles = {
  default: {
    base: 'bg-muted text-muted-foreground border-border',
    glow: '',
  },
  critical: {
    base: 'bg-red-500/20 text-red-500 border-red-500/30',
    glow: 'shadow-[0_0_10px_rgba(239,68,68,0.3)]',
  },
  warning: {
    base: 'bg-orange-500/20 text-orange-500 border-orange-500/30',
    glow: 'shadow-[0_0_10px_rgba(249,115,22,0.3)]',
  },
  success: {
    base: 'bg-green-500/20 text-green-500 border-green-500/30',
    glow: 'shadow-[0_0_10px_rgba(34,197,94,0.3)]',
  },
  info: {
    base: 'bg-blue-500/20 text-blue-500 border-blue-500/30',
    glow: 'shadow-[0_0_10px_rgba(59,130,246,0.3)]',
  },
  neutral: {
    base: 'bg-gray-500/20 text-gray-500 border-gray-500/30',
    glow: '',
  },
}

const sizeStyles = {
  sm: 'px-1.5 py-0.5 text-xs',
  md: 'px-2 py-1 text-sm',
  lg: 'px-3 py-1.5 text-base',
}

export function AnimatedBadge({
  children,
  variant = 'default',
  size = 'md',
  animated = false,
  pulse = false,
  glow = false,
  className,
}: AnimatedBadgeProps) {
  const styles = variantStyles[variant]

  return (
    <motion.span
      initial={animated ? { opacity: 0, scale: 0.8 } : undefined}
      animate={animated ? { opacity: 1, scale: 1 } : undefined}
      className={cn(
        'inline-flex items-center gap-1.5 font-medium rounded-full border',
        styles.base,
        sizeStyles[size],
        glow && styles.glow,
        pulse && variant === 'critical' && 'animate-pulse',
        className
      )}
    >
      {pulse && variant === 'critical' && (
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
        </span>
      )}
      {children}
    </motion.span>
  )
}

/**
 * StatusDot - Small animated status indicator
 */
interface StatusDotProps {
  status: 'online' | 'offline' | 'warning' | 'error'
  animated?: boolean
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

const statusColors = {
  online: 'bg-green-500',
  offline: 'bg-gray-500',
  warning: 'bg-orange-500',
  error: 'bg-red-500',
}

const dotSizes = {
  sm: 'h-1.5 w-1.5',
  md: 'h-2 w-2',
  lg: 'h-3 w-3',
}

export function StatusDot({ status, animated = true, size = 'md', className }: StatusDotProps) {
  const color = statusColors[status]
  const dotSize = dotSizes[size]

  return (
    <span className={cn('relative flex', dotSize, className)}>
      {animated && (status === 'online' || status === 'error') && (
        <span
          className={cn(
            'animate-ping absolute inline-flex h-full w-full rounded-full opacity-75',
            color
          )}
        />
      )}
      <span className={cn('relative inline-flex rounded-full', dotSize, color)} />
    </span>
  )
}

/**
 * CountBadge - Animated counter badge (for notifications, alerts count)
 */
interface CountBadgeProps {
  count: number
  max?: number
  variant?: 'default' | 'critical' | 'warning'
  className?: string
}

export function CountBadge({ count, max = 99, variant = 'default', className }: CountBadgeProps) {
  const displayCount = count > max ? `${max}+` : count

  if (count === 0) return null

  const variantClasses = {
    default: 'bg-primary text-primary-foreground',
    critical: 'bg-red-500 text-white',
    warning: 'bg-orange-500 text-white',
  }

  return (
    <motion.span
      initial={{ scale: 0 }}
      animate={{ scale: 1 }}
      className={cn(
        'inline-flex items-center justify-center min-w-[1.25rem] h-5 px-1.5 text-xs font-bold rounded-full',
        variantClasses[variant],
        count > 0 && variant === 'critical' && 'animate-pulse',
        className
      )}
    >
      {displayCount}
    </motion.span>
  )
}

/**
 * SeverityBadge - Pre-styled severity indicator
 */
interface SeverityBadgeProps {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  showLabel?: boolean
  className?: string
}

const severityConfig = {
  critical: { label: 'Critical', variant: 'critical' as const },
  high: { label: 'High', variant: 'warning' as const },
  medium: { label: 'Medium', variant: 'info' as const },
  low: { label: 'Low', variant: 'success' as const },
  info: { label: 'Info', variant: 'neutral' as const },
}

export function SeverityBadge({ severity, showLabel = true, className }: SeverityBadgeProps) {
  const config = severityConfig[severity]

  return (
    <AnimatedBadge
      variant={config.variant}
      size="sm"
      pulse={severity === 'critical'}
      glow={severity === 'critical'}
      className={className}
    >
      {showLabel ? config.label : null}
    </AnimatedBadge>
  )
}
