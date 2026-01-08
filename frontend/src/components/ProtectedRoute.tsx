import { Navigate, useLocation } from 'react-router-dom'
import { Loader2, ShieldOff, Key } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { useLicense } from '@/contexts/LicenseContext'

interface ProtectedRouteProps {
  element: React.ReactElement
  adminOnly?: boolean
}

export default function ProtectedRoute({ element, adminOnly = false }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading: authLoading, isAdmin } = useAuth()
  const { isLicensed, isLoading: licenseLoading, status } = useLicense()
  const location = useLocation()

  // Show loading state while checking auth or license
  if (authLoading || licenseLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-zinc-950">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 text-red-500 animate-spin" />
          <p className="text-zinc-400">Loading...</p>
        </div>
      </div>
    )
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />
  }

  // Redirect to license activation if not licensed (and not in grace mode)
  // Grace mode allows continued operation while license server is unreachable
  if (!isLicensed && !status?.grace_mode) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-zinc-950">
        <div className="flex flex-col items-center gap-4 text-center max-w-md p-8">
          <div className="w-16 h-16 bg-amber-500/10 rounded-full flex items-center justify-center">
            <Key className="w-8 h-8 text-amber-500" />
          </div>
          <h1 className="text-2xl font-bold text-white">License Required</h1>
          <p className="text-zinc-400">
            {status?.status === 'expired'
              ? 'Your license has expired. Please renew to continue using VIGILANCE X.'
              : status?.status === 'revoked'
                ? 'Your license has been revoked. Please contact support.'
                : 'A valid license is required to access this application.'}
          </p>
          <a
            href="/license"
            className="mt-4 px-6 py-2 bg-amber-500 hover:bg-amber-600 text-white rounded-lg transition-colors"
          >
            Activate License
          </a>
        </div>
      </div>
    )
  }

  // Show forbidden page if admin required but user is not admin
  if (adminOnly && !isAdmin) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-zinc-950">
        <div className="flex flex-col items-center gap-4 text-center max-w-md p-8">
          <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center">
            <ShieldOff className="w-8 h-8 text-red-500" />
          </div>
          <h1 className="text-2xl font-bold text-white">Access Denied</h1>
          <p className="text-zinc-400">
            You don't have permission to access this page.
            This area is restricted to administrators only.
          </p>
          <a
            href="/"
            className="mt-4 px-6 py-2 bg-zinc-800 hover:bg-zinc-700 text-white rounded-lg transition-colors"
          >
            Return to Dashboard
          </a>
        </div>
      </div>
    )
  }

  // Render the protected element
  return element
}
