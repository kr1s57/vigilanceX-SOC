import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Key, Loader2, AlertCircle, CheckCircle, Mail } from 'lucide-react'
import { useLicense } from '@/contexts/LicenseContext'
import { cn } from '@/lib/utils'

export default function LicenseActivation() {
  const navigate = useNavigate()
  const { status, activate, isLoading, error } = useLicense()

  const [licenseKey, setLicenseKey] = useState('')
  const [localError, setLocalError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setLocalError(null)
    setSuccess(false)

    // Validate license key format (XXXX-XXXX-XXXX-XXXX)
    const keyPattern = /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/i
    if (!keyPattern.test(licenseKey.trim())) {
      setLocalError('Invalid license key format. Expected: XXXX-XXXX-XXXX-XXXX')
      return
    }

    try {
      await activate(licenseKey.trim().toUpperCase())
      setSuccess(true)
      // Redirect after successful activation
      setTimeout(() => {
        navigate('/', { replace: true })
      }, 2000)
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Activation failed')
    }
  }

  const displayError = localError || error

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-zinc-900 via-zinc-950 to-black p-4">
      {/* Background effect */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-amber-500/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-red-500/10 rounded-full blur-3xl" />
      </div>

      {/* Activation card */}
      <div className="relative w-full max-w-md">
        <div className="bg-zinc-900/80 backdrop-blur-xl border border-zinc-800 rounded-2xl shadow-2xl p-8">
          {/* Logo and title */}
          <div className="flex flex-col items-center mb-8">
            <div className="w-16 h-16 bg-gradient-to-br from-amber-500 to-orange-500 rounded-2xl flex items-center justify-center mb-4 shadow-lg shadow-amber-500/20">
              <Key className="w-9 h-9 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-white">License Activation</h1>
            <p className="text-zinc-400 text-sm mt-1">Enter your license key to activate VIGILANCE X</p>
          </div>

          {/* Current status */}
          {status && (
            <div className={cn(
              "mb-6 p-4 rounded-lg flex items-start gap-3",
              status.licensed
                ? "bg-green-500/10 border border-green-500/30"
                : status.grace_mode
                  ? "bg-amber-500/10 border border-amber-500/30"
                  : "bg-red-500/10 border border-red-500/30"
            )}>
              {status.licensed ? (
                <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className={cn(
                  "w-5 h-5 flex-shrink-0 mt-0.5",
                  status.grace_mode ? "text-amber-400" : "text-red-400"
                )} />
              )}
              <div>
                <p className={cn(
                  "text-sm font-medium",
                  status.licensed ? "text-green-400" : status.grace_mode ? "text-amber-400" : "text-red-400"
                )}>
                  {status.licensed
                    ? `Licensed to ${status.customer_name || 'Unknown'}`
                    : status.grace_mode
                      ? 'Grace Period Active'
                      : getStatusMessage(status.status)}
                </p>
                {status.licensed && status.days_remaining !== undefined && (
                  <p className="text-zinc-400 text-xs mt-1">
                    {status.days_remaining} days remaining
                  </p>
                )}
                {status.grace_mode && (
                  <p className="text-zinc-400 text-xs mt-1">
                    License server unreachable. Operating in grace mode.
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Success message */}
          {success && (
            <div className="mb-6 p-4 bg-green-500/10 border border-green-500/30 rounded-lg flex items-start gap-3">
              <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-green-400 text-sm font-medium">License activated successfully!</p>
                <p className="text-zinc-400 text-xs mt-1">Redirecting to dashboard...</p>
              </div>
            </div>
          )}

          {/* Error message */}
          {displayError && !success && (
            <div className="mb-6 p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-red-400 text-sm">{displayError}</p>
            </div>
          )}

          {/* Activation form */}
          {!success && (
            <form onSubmit={handleSubmit} className="space-y-5">
              {/* License key field */}
              <div>
                <label htmlFor="licenseKey" className="block text-sm font-medium text-zinc-300 mb-2">
                  License Key
                </label>
                <input
                  type="text"
                  id="licenseKey"
                  value={licenseKey}
                  onChange={(e) => setLicenseKey(e.target.value.toUpperCase())}
                  className={cn(
                    "w-full px-4 py-3 bg-zinc-800/50 border rounded-lg text-white font-mono",
                    "placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-amber-500/50",
                    "transition-all duration-200",
                    displayError ? "border-red-500/50" : "border-zinc-700 focus:border-amber-500"
                  )}
                  placeholder="XXXX-XXXX-XXXX-XXXX"
                  disabled={isLoading}
                  autoComplete="off"
                  autoFocus
                  required
                />
              </div>

              {/* Submit button */}
              <button
                type="submit"
                disabled={isLoading || !licenseKey}
                className={cn(
                  "w-full py-3 px-4 rounded-lg font-medium flex items-center justify-center gap-2",
                  "bg-gradient-to-r from-amber-500 to-orange-500 text-white",
                  "hover:from-amber-600 hover:to-orange-600 transition-all duration-200",
                  "disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:from-amber-500 disabled:hover:to-orange-500",
                  "shadow-lg shadow-amber-500/20 hover:shadow-amber-500/30"
                )}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Activating...
                  </>
                ) : (
                  <>
                    <Key className="w-5 h-5" />
                    Activate License
                  </>
                )}
              </button>
            </form>
          )}

          {/* Footer */}
          <div className="mt-8 pt-6 border-t border-zinc-800">
            <div className="flex flex-col items-center gap-3">
              <div className="flex items-center gap-2 text-zinc-500 text-xs">
                <Shield className="w-4 h-4" />
                <span>VIGILANCE X v2.9.0</span>
              </div>
              <a
                href="mailto:support@vigilancex.io"
                className="flex items-center gap-2 text-zinc-400 hover:text-zinc-300 text-sm transition-colors"
              >
                <Mail className="w-4 h-4" />
                Contact Support
              </a>
            </div>
          </div>
        </div>

        {/* Help text */}
        <p className="text-center text-zinc-600 text-xs mt-4">
          Need a license? Contact your administrator or purchase at vigilancex.io
        </p>
      </div>
    </div>
  )
}

function getStatusMessage(status: string): string {
  switch (status) {
    case 'not_activated':
      return 'License Not Activated'
    case 'expired':
      return 'License Expired'
    case 'revoked':
      return 'License Revoked'
    case 'grace_expired':
      return 'Grace Period Expired'
    case 'disabled':
      return 'License System Disabled'
    case 'error':
      return 'License Check Failed'
    default:
      return 'License Invalid'
  }
}
