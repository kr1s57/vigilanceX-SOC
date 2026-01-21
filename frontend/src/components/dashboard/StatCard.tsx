import { ReactNode, memo } from 'react'
import { motion } from 'framer-motion'
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
  index?: number // For stagger animation
}

export const StatCard = memo(function StatCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  variant = 'default',
  className,
  index = 0,
}: StatCardProps) {
  const variantStyles = {
    default: 'bg-card',
    critical: 'bg-red-500/10 border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.1)]',
    warning: 'bg-yellow-500/10 border-yellow-500/20 shadow-[0_0_15px_rgba(234,179,8,0.1)]',
    success: 'bg-green-500/10 border-green-500/20 shadow-[0_0_15px_rgba(34,197,94,0.1)]',
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05, duration: 0.2 }}
      whileHover={{ y: -2, transition: { duration: 0.2 } }}
      className={cn(
        'rounded-xl border p-6 transition-shadow hover:shadow-lg',
        variantStyles[variant],
        variant === 'critical' && 'animate-pulse-subtle',
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
    </motion.div>
  )
})
