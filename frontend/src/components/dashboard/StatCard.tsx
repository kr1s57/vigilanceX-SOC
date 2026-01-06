import { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { TrendingUp, TrendingDown, Minus } from 'lucide-react'

interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon?: ReactNode
  trend?: {
    value: number
    isPositive?: boolean
  }
  variant?: 'default' | 'critical' | 'warning' | 'success'
  className?: string
}

export function StatCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  variant = 'default',
  className,
}: StatCardProps) {
  const variantStyles = {
    default: 'bg-card',
    critical: 'bg-red-500/10 border-red-500/20',
    warning: 'bg-yellow-500/10 border-yellow-500/20',
    success: 'bg-green-500/10 border-green-500/20',
  }

  return (
    <div
      className={cn(
        'rounded-xl border p-6 transition-all hover:shadow-lg',
        variantStyles[variant],
        className
      )}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-sm font-medium text-muted-foreground">{title}</p>
          <p className="text-3xl font-bold">{value}</p>
          {subtitle && (
            <p className="text-sm text-muted-foreground">{subtitle}</p>
          )}
        </div>
        {icon && (
          <div className="p-2 bg-muted rounded-lg">
            {icon}
          </div>
        )}
      </div>

      {trend && (
        <div className="mt-4 flex items-center gap-2">
          {trend.value > 0 ? (
            <TrendingUp className={cn('w-4 h-4', trend.isPositive ? 'text-green-500' : 'text-red-500')} />
          ) : trend.value < 0 ? (
            <TrendingDown className={cn('w-4 h-4', trend.isPositive ? 'text-red-500' : 'text-green-500')} />
          ) : (
            <Minus className="w-4 h-4 text-muted-foreground" />
          )}
          <span className={cn(
            'text-sm font-medium',
            trend.value > 0
              ? (trend.isPositive ? 'text-green-500' : 'text-red-500')
              : (trend.isPositive ? 'text-red-500' : 'text-green-500')
          )}>
            {trend.value > 0 ? '+' : ''}{trend.value}%
          </span>
          <span className="text-sm text-muted-foreground">vs last period</span>
        </div>
      )}
    </div>
  )
}
