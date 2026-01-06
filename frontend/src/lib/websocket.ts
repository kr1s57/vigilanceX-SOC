type MessageHandler = (data: WebSocketMessage) => void

export interface WebSocketMessage {
  type: 'event' | 'ban' | 'alert' | 'stats' | 'connection'
  payload: unknown
  timestamp: string
}

interface WebSocketOptions {
  url: string
  reconnectInterval?: number
  maxReconnectAttempts?: number
  onConnect?: () => void
  onDisconnect?: () => void
  onError?: (error: Event) => void
}

class WebSocketManager {
  private ws: WebSocket | null = null
  private options: WebSocketOptions
  private handlers: Map<string, Set<MessageHandler>> = new Map()
  private reconnectAttempts = 0
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null
  private isConnecting = false
  private shouldReconnect = true

  constructor(options: WebSocketOptions) {
    this.options = {
      reconnectInterval: 3000,
      maxReconnectAttempts: 10,
      ...options,
    }
  }

  connect(): void {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
      return
    }

    this.isConnecting = true
    this.shouldReconnect = true

    try {
      this.ws = new WebSocket(this.options.url)

      this.ws.onopen = () => {
        this.isConnecting = false
        this.reconnectAttempts = 0
        console.log('[WebSocket] Connected')
        this.options.onConnect?.()

        // Notify handlers of connection
        this.emit({
          type: 'connection',
          payload: { status: 'connected' },
          timestamp: new Date().toISOString(),
        })
      }

      this.ws.onclose = () => {
        this.isConnecting = false
        console.log('[WebSocket] Disconnected')
        this.options.onDisconnect?.()

        // Notify handlers of disconnection
        this.emit({
          type: 'connection',
          payload: { status: 'disconnected' },
          timestamp: new Date().toISOString(),
        })

        this.scheduleReconnect()
      }

      this.ws.onerror = (error) => {
        this.isConnecting = false
        console.error('[WebSocket] Error:', error)
        this.options.onError?.(error)
      }

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as WebSocketMessage
          this.emit(message)
        } catch (err) {
          console.error('[WebSocket] Failed to parse message:', err)
        }
      }
    } catch (err) {
      this.isConnecting = false
      console.error('[WebSocket] Connection failed:', err)
      this.scheduleReconnect()
    }
  }

  private scheduleReconnect(): void {
    if (!this.shouldReconnect) return

    if (this.reconnectAttempts >= (this.options.maxReconnectAttempts || 10)) {
      console.error('[WebSocket] Max reconnect attempts reached')
      return
    }

    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout)
    }

    this.reconnectTimeout = setTimeout(() => {
      this.reconnectAttempts++
      console.log(`[WebSocket] Reconnecting (attempt ${this.reconnectAttempts})...`)
      this.connect()
    }, this.options.reconnectInterval)
  }

  disconnect(): void {
    this.shouldReconnect = false

    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout)
      this.reconnectTimeout = null
    }

    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }

  subscribe(type: string, handler: MessageHandler): () => void {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, new Set())
    }
    this.handlers.get(type)!.add(handler)

    // Return unsubscribe function
    return () => {
      this.handlers.get(type)?.delete(handler)
    }
  }

  subscribeAll(handler: MessageHandler): () => void {
    return this.subscribe('*', handler)
  }

  private emit(message: WebSocketMessage): void {
    // Notify specific type handlers
    this.handlers.get(message.type)?.forEach((handler) => handler(message))

    // Notify wildcard handlers
    this.handlers.get('*')?.forEach((handler) => handler(message))
  }

  send(message: object): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message))
    } else {
      console.warn('[WebSocket] Cannot send - not connected')
    }
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }
}

// Singleton instance
let wsManager: WebSocketManager | null = null

export function getWebSocketManager(): WebSocketManager {
  if (!wsManager) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = import.meta.env.VITE_WS_URL || `${protocol}//${window.location.host}`

    wsManager = new WebSocketManager({
      url: `${host}/api/v1/ws`,
      reconnectInterval: 3000,
      maxReconnectAttempts: 10,
    })
  }
  return wsManager
}

export function connectWebSocket(): void {
  getWebSocketManager().connect()
}

export function disconnectWebSocket(): void {
  getWebSocketManager().disconnect()
}

export function subscribeToEvents(handler: MessageHandler): () => void {
  return getWebSocketManager().subscribe('event', handler)
}

export function subscribeToBans(handler: MessageHandler): () => void {
  return getWebSocketManager().subscribe('ban', handler)
}

export function subscribeToAlerts(handler: MessageHandler): () => void {
  return getWebSocketManager().subscribe('alert', handler)
}

export function subscribeToStats(handler: MessageHandler): () => void {
  return getWebSocketManager().subscribe('stats', handler)
}

export function subscribeToConnection(handler: MessageHandler): () => void {
  return getWebSocketManager().subscribe('connection', handler)
}
