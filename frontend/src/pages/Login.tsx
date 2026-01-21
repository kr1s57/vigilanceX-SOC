import { useState, useEffect, FormEvent } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Eye, EyeOff, Loader2, AlertCircle, LogIn } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { cn } from '@/lib/utils'
import { Logo } from '@/components/Logo'

export default function Login() {
  const navigate = useNavigate()
  const location = useLocation()
  const { login, isAuthenticated, isLoading: authLoading } = useAuth()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)

  // Get the redirect path from location state
  const from = (location.state as { from?: string })?.from || '/'

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated && !authLoading) {
      navigate(from, { replace: true })
    }
  }, [isAuthenticated, authLoading, navigate, from])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setIsLoading(true)

    try {
      await login(username, password)
      navigate(from, { replace: true })
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Authentication failed'
      // Check for axios error response
      if (typeof err === 'object' && err !== null && 'response' in err) {
        const axiosErr = err as { response?: { data?: { error?: string } } }
        setError(axiosErr.response?.data?.error || errorMessage)
      } else {
        setError(errorMessage)
      }
    } finally {
      setIsLoading(false)
    }
  }

  const loading = isLoading || authLoading

  // Show loading while checking auth status
  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-zinc-900 via-zinc-950 to-black">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 text-red-500 animate-spin" />
          <p className="text-zinc-400">Loading...</p>
        </div>
      </div>
    )
  }

  // Don't render login form if already authenticated (will redirect via useEffect)
  if (isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-zinc-900 via-zinc-950 to-black">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 text-red-500 animate-spin" />
          <p className="text-zinc-400">Redirecting...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-zinc-900 via-zinc-950 to-black p-4">
      {/* Background effect */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-red-500/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-blue-500/10 rounded-full blur-3xl" />
      </div>

      {/* Login card */}
      <div className="relative w-full max-w-md">
        <div className="bg-zinc-900/80 backdrop-blur-xl border border-zinc-800 rounded-2xl shadow-2xl p-8">
          {/* Logo and title - v3.57.126: New custom logo */}
          <div className="flex flex-col items-center mb-8">
            <div className="mb-4 relative">
              <Logo size={72} />
              <div className="absolute inset-0 animate-pulse opacity-30 blur-xl">
                <Logo size={72} />
              </div>
            </div>
            <h1 className="text-2xl font-bold text-white tracking-wide">VIGILANCE X</h1>
            <p className="text-zinc-400 text-sm mt-1">Security Operations Center</p>
          </div>

          {/* Error message */}
          {error && (
            <div className="mb-6 p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-red-400 text-sm">{error}</p>
            </div>
          )}

          {/* Login form */}
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Username field */}
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-zinc-300 mb-2">
                Username
              </label>
              <input
                type="text"
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className={cn(
                  "w-full px-4 py-3 bg-zinc-800/50 border rounded-lg text-white",
                  "placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-red-500/50",
                  "transition-all duration-200",
                  error ? "border-red-500/50" : "border-zinc-700 focus:border-red-500"
                )}
                placeholder="Enter your username"
                disabled={loading}
                autoComplete="username"
                autoFocus
                required
              />
            </div>

            {/* Password field */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-zinc-300 mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={cn(
                    "w-full px-4 py-3 pr-12 bg-zinc-800/50 border rounded-lg text-white",
                    "placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-red-500/50",
                    "transition-all duration-200",
                    error ? "border-red-500/50" : "border-zinc-700 focus:border-red-500"
                  )}
                  placeholder="Enter your password"
                  disabled={loading}
                  autoComplete="current-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-300 transition-colors"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {/* Submit button */}
            <button
              type="submit"
              disabled={loading || !username || !password}
              className={cn(
                "w-full py-3 px-4 rounded-lg font-medium flex items-center justify-center gap-2",
                "bg-gradient-to-r from-red-500 to-orange-500 text-white",
                "hover:from-red-600 hover:to-orange-600 transition-all duration-200",
                "disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:from-red-500 disabled:hover:to-orange-500",
                "shadow-lg shadow-red-500/20 hover:shadow-red-500/30"
              )}
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Signing in...
                </>
              ) : (
                <>
                  <LogIn className="w-5 h-5" />
                  Sign In
                </>
              )}
            </button>
          </form>

          {/* Footer */}
          <div className="mt-8 pt-6 border-t border-zinc-800 text-center">
            <p className="text-zinc-600 text-xs">
              VIGILANCE X v3.58.107
            </p>
          </div>
        </div>

        {/* Security notice */}
        <p className="text-center text-zinc-600 text-xs mt-4">
          All login attempts are logged and monitored
        </p>
      </div>
    </div>
  )
}
