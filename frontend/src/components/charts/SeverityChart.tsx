import { memo } from 'react'
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Legend,
  Tooltip,
} from 'recharts'
import type { EventStats } from '@/types'

interface SeverityChartProps {
  stats: EventStats
  height?: number
}

const COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#2563eb',
}

export const SeverityChart = memo(function SeverityChart({ stats, height = 250 }: SeverityChartProps) {
  const data = [
    { name: 'Critical', value: stats.critical_events, color: COLORS.critical },
    { name: 'High', value: stats.high_events, color: COLORS.high },
    { name: 'Medium', value: stats.medium_events, color: COLORS.medium },
    { name: 'Low', value: stats.low_events, color: COLORS.low },
  ].filter(item => item.value > 0)

  return (
    <div className="w-full" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            paddingAngle={5}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: 'hsl(var(--card))',
              border: '1px solid hsl(var(--border))',
              borderRadius: '8px',
            }}
            formatter={(value: number) => [value.toLocaleString(), 'Events']}
          />
          <Legend
            verticalAlign="bottom"
            height={36}
            formatter={(value) => (
              <span className="text-sm text-muted-foreground">{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
})
