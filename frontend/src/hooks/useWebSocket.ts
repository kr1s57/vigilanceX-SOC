import { useEffect, useState, useCallback } from 'react'
import {
  getWebSocketManager,
  connectWebSocket,
  subscribeToConnection,
  type WebSocketMessage,
} from '@/lib/websocket'

export function useWebSocket() {
  const [isConnected, setIsConnected] = useState(false)

  useEffect(() => {
    // Connect on mount
    connectWebSocket()

    // Subscribe to connection status changes
    const unsubscribe = subscribeToConnection((message) => {
      const payload = message.payload as { status: string }
      setIsConnected(payload.status === 'connected')
    })

    // Check initial state
    setIsConnected(getWebSocketManager().isConnected)

    return () => {
      unsubscribe()
    }
  }, [])

  return { isConnected }
}

export function useWebSocketSubscription<T = unknown>(
  type: 'event' | 'ban' | 'alert' | 'stats',
  callback: (data: T) => void
) {
  useEffect(() => {
    const manager = getWebSocketManager()
    const unsubscribe = manager.subscribe(type, (message: WebSocketMessage) => {
      callback(message.payload as T)
    })

    return () => {
      unsubscribe()
    }
  }, [type, callback])
}

export function useRealtimeEvents(onNewEvent: (event: unknown) => void) {
  const stableCallback = useCallback(onNewEvent, [])

  useWebSocketSubscription('event', stableCallback)
}

export function useRealtimeBans(onBanUpdate: (ban: unknown) => void) {
  const stableCallback = useCallback(onBanUpdate, [])

  useWebSocketSubscription('ban', stableCallback)
}

export function useRealtimeAlerts(onAlert: (alert: unknown) => void) {
  const stableCallback = useCallback(onAlert, [])

  useWebSocketSubscription('alert', stableCallback)
}

export function useRealtimeStats(onStatsUpdate: (stats: unknown) => void) {
  const stableCallback = useCallback(onStatsUpdate, [])

  useWebSocketSubscription('stats', stableCallback)
}
