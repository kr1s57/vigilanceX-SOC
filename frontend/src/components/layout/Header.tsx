import { useState, useEffect } from 'react'
import { Bell, RefreshCw, Wifi, WifiOff } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useWebSocket, useRealtimeEvents } from '@/hooks/useWebSocket'

export function Header() {
  const { isConnected } = useWebSocket()
  const [lastUpdate, setLastUpdate] = useState(new Date())
  const [notifications, setNotifications] = useState(0)

  // Update timestamp when new events arrive
  useRealtimeEvents(() => {
    setLastUpdate(new Date())
  })

  // Periodic fallback update
  useEffect(() => {
    const interval = setInterval(() => {
      setLastUpdate(new Date())
    }, 30000)
    return () => clearInterval(interval)
  }, [])

  return (
    <header className="h-16 bg-card border-b border-border flex items-center justify-between px-6">
      {/* Left side - Page title will be set by each page */}
      <div className="flex items-center gap-4">
        <h2 className="text-lg font-semibold">Security Operations Center</h2>
      </div>

      {/* Right side - Status and actions */}
      <div className="flex items-center gap-4">
        {/* Connection status */}
        <div className={cn(
          'flex items-center gap-2 px-3 py-1.5 rounded-full text-sm',
          isConnected
            ? 'bg-green-500/10 text-green-500'
            : 'bg-red-500/10 text-red-500'
        )}>
          {isConnected ? (
            <>
              <Wifi className="w-4 h-4" />
              <span>Live</span>
            </>
          ) : (
            <>
              <WifiOff className="w-4 h-4" />
              <span>Disconnected</span>
            </>
          )}
        </div>

        {/* Last update */}
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <RefreshCw className="w-4 h-4" />
          <span>Updated {formatTimeAgo(lastUpdate)}</span>
        </div>

        {/* Notifications */}
        <button className="relative p-2 rounded-lg hover:bg-muted transition-colors">
          <Bell className="w-5 h-5" />
          {notifications > 0 && (
            <span className="absolute top-1 right-1 w-4 h-4 bg-red-500 rounded-full text-xs text-white flex items-center justify-center">
              {notifications > 9 ? '9+' : notifications}
            </span>
          )}
        </button>

        {/* User menu placeholder */}
        <div className="w-8 h-8 bg-muted rounded-full flex items-center justify-center text-sm font-medium">
          A
        </div>
      </div>
    </header>
  )
}

function formatTimeAgo(date: Date): string {
  const seconds = Math.floor((new Date().getTime() - date.getTime()) / 1000)

  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}
