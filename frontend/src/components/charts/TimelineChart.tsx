import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { format } from 'date-fns'
import type { TimelinePoint } from '@/types'

interface TimelineChartProps {
  data: TimelinePoint[]
  height?: number
}

export function TimelineChart({ data, height = 300 }: TimelineChartProps) {
  const chartData = data.map((point) => ({
    ...point,
    time: new Date(point.time).getTime(),
    allowed: point.total_events - point.blocked_events,
  }))

  return (
    <div className="w-full" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={chartData}
          margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
        >
          <defs>
            <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis
            dataKey="time"
            tickFormatter={(value) => format(new Date(value), 'HH:mm')}
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
          />
          <YAxis
            stroke="hsl(var(--muted-foreground))"
            fontSize={12}
            tickFormatter={(value) => value >= 1000 ? `${(value / 1000).toFixed(1)}k` : value}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'hsl(var(--card))',
              border: '1px solid hsl(var(--border))',
              borderRadius: '8px',
            }}
            labelFormatter={(value) => format(new Date(value), 'MMM d, HH:mm')}
            formatter={(value: number, name: string) => [
              value.toLocaleString(),
              name
            ]}
          />
          <Legend />
          <Area
            type="monotone"
            dataKey="blocked_events"
            name="Blocked"
            stroke="#ef4444"
            fillOpacity={1}
            fill="url(#colorBlocked)"
            stackId="1"
          />
          <Area
            type="monotone"
            dataKey="allowed"
            name="Allowed"
            stroke="#22c55e"
            fillOpacity={1}
            fill="url(#colorAllowed)"
            stackId="1"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
