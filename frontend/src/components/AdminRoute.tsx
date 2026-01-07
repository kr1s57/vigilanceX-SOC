import { Navigate } from 'react-router-dom'
import { ShieldOff } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'

interface AdminRouteProps {
  children: React.ReactNode
}

export default function AdminRoute({ children }: AdminRouteProps) {
  const { isAdmin, isAuthenticated } = useAuth()

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  // Show forbidden page if user is not admin
  if (!isAdmin) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4 text-center max-w-md p-8">
          <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center">
            <ShieldOff className="w-8 h-8 text-red-500" />
          </div>
          <h1 className="text-2xl font-bold">Access Denied</h1>
          <p className="text-muted-foreground">
            You don't have permission to access this page.
            This area is restricted to administrators only.
          </p>
          <a
            href="/"
            className="mt-4 px-6 py-2 bg-muted hover:bg-muted/80 rounded-lg transition-colors"
          >
            Return to Dashboard
          </a>
        </div>
      </div>
    )
  }

  // Render the children if admin
  return <>{children}</>
}
