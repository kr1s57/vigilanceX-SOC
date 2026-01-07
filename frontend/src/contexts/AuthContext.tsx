import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { authApi, UserInfo } from '@/lib/api'
import { resetWebSocketManager, connectWebSocket } from '@/lib/websocket'

// Auth context types
interface AuthContextType {
  user: UserInfo | null
  isAuthenticated: boolean
  isLoading: boolean
  isAdmin: boolean
  isAudit: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

const TOKEN_KEY = 'auth_token'
const TOKEN_EXPIRY_KEY = 'auth_token_expiry'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserInfo | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  // Check if user is authenticated
  const isAuthenticated = !!user

  // Role checks
  const isAdmin = user?.role === 'admin'
  const isAudit = user?.role === 'audit'

  // Check token validity and load user on mount
  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem(TOKEN_KEY)
      const expiry = localStorage.getItem(TOKEN_EXPIRY_KEY)

      if (!token) {
        setIsLoading(false)
        return
      }

      // Check if token is expired
      if (expiry && Date.now() / 1000 > parseInt(expiry)) {
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(TOKEN_EXPIRY_KEY)
        setIsLoading(false)
        return
      }

      // Try to load user info
      try {
        const data = await authApi.me()
        setUser(data.user)
      } catch (error) {
        // Token is invalid, clear it
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(TOKEN_EXPIRY_KEY)
      } finally {
        setIsLoading(false)
      }
    }

    initAuth()
  }, [])

  // Login function
  const login = useCallback(async (username: string, password: string) => {
    const response = await authApi.login(username, password)

    // Store token and expiry
    localStorage.setItem(TOKEN_KEY, response.token)
    localStorage.setItem(TOKEN_EXPIRY_KEY, response.expires_at.toString())

    // Set user
    setUser(response.user)

    // Reset and reconnect WebSocket with new token
    resetWebSocketManager()
    connectWebSocket()
  }, [])

  // Logout function
  const logout = useCallback(() => {
    // Disconnect WebSocket
    resetWebSocketManager()

    // Try to call logout API (non-blocking)
    authApi.logout().catch(() => {
      // Ignore errors, we're logging out anyway
    })

    // Clear local storage
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(TOKEN_EXPIRY_KEY)

    // Clear user state
    setUser(null)
  }, [])

  // Refresh user info
  const refreshUser = useCallback(async () => {
    try {
      const data = await authApi.me()
      setUser(data.user)
    } catch (error) {
      // If refresh fails, log out
      logout()
    }
  }, [logout])

  return (
    <AuthContext.Provider value={{
      user,
      isAuthenticated,
      isLoading,
      isAdmin,
      isAudit,
      login,
      logout,
      refreshUser,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

// Helper hook for role-based access
export function useRequireAuth(requiredRole?: 'admin' | 'audit') {
  const { user, isAuthenticated, isLoading } = useAuth()

  const hasAccess = isAuthenticated && (!requiredRole || user?.role === requiredRole)
  const isAdminRequired = requiredRole === 'admin' && user?.role !== 'admin'

  return {
    isLoading,
    isAuthenticated,
    hasAccess,
    isAdminRequired,
    user,
  }
}
