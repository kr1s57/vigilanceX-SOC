import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Key, Loader2, AlertCircle, CheckCircle, Mail, RefreshCw, Rocket, Monitor, ArrowUp, Clock } from 'lucide-react'
import { useLicense } from '@/contexts/LicenseContext'
import { cn } from '@/lib/utils'

export default function LicenseActivation() {
  const navigate = useNavigate()
  const {
    status,
    activate,
    isLoading,
    error,
    syncWithServer,
    needsFreshDeploy,
    freshDeploy,
    askProLicense
  } = useLicense()

  // Form states
  const [licenseKey, setLicenseKey] = useState('')
  const [email, setEmail] = useState('')
  const [showManualActivation, setShowManualActivation] = useState(false)

  // UI states
  const [localError, setLocalError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)
  const [isSyncing, setIsSyncing] = useState(false)
  const [syncSuccess, setSyncSuccess] = useState(false)

  const handleSyncLicense = async () => {
    setIsSyncing(true)
    setLocalError(null)
    setSyncSuccess(false)
    try {
      await syncWithServer()
      setSyncSuccess(true)
      setTimeout(() => setSyncSuccess(false), 3000)
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Failed to sync license')
    } finally {
      setIsSyncing(false)
    }
  }

  const handleFreshDeploy = async (e: FormEvent) => {
    e.preventDefault()
    setLocalError(null)
    setSuccess(false)

    // Validate email
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailPattern.test(email.trim())) {
      setLocalError('Please enter a valid email address')
      return
    }

    try {
      await freshDeploy(email.trim())
      setSuccess(true)
      setTimeout(() => {
        navigate('/', { replace: true })
      }, 2000)
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Failed to generate trial license')
    }
  }

  const handleManualActivation = async (e: FormEvent) => {
    e.preventDefault()
    setLocalError(null)
    setSuccess(false)

    // Validate license key format (VX3-XXXX-XXXX-XXXX-XXXX or XXXX-XXXX-XXXX-XXXX)
    const keyPattern = /^(VX3-)?[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}(-[A-Z0-9]{4})?$/i
    if (!keyPattern.test(licenseKey.trim())) {
      setLocalError('Invalid license key format')
      return
    }

    try {
      await activate(licenseKey.trim().toUpperCase())
      setSuccess(true)
      setTimeout(() => {
        navigate('/', { replace: true })
      }, 2000)
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Activation failed')
    }
  }

  const handleAskPro = async () => {
    setLocalError(null)
    try {
      await askProLicense()
      setSyncSuccess(true)
      setTimeout(() => setSyncSuccess(false), 3000)
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Failed to request pro license')
    }
  }

  const displayError = localError || error
  const isTrialActive = status?.status === 'fdeploy' || status?.status === 'trial'
  const isProRequested = status?.status === 'asked'

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
              {needsFreshDeploy && !showManualActivation ? (
                <Rocket className="w-9 h-9 text-white" />
              ) : (
                <Key className="w-9 h-9 text-white" />
              )}
            </div>
            <h1 className="text-2xl font-bold text-white">
              {needsFreshDeploy && !showManualActivation ? 'Get Started' : 'License Activation'}
            </h1>
            <p className="text-zinc-400 text-sm mt-1 text-center">
              {needsFreshDeploy && !showManualActivation
                ? 'Start your 15-day free trial of VIGILANCE X'
                : 'Enter your license key to activate VIGILANCE X'}
            </p>
          </div>

          {/* Success message */}
          {success && (
            <div className="mb-6 p-4 bg-green-500/10 border border-green-500/30 rounded-lg flex items-start gap-3">
              <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-green-400 text-sm font-medium">
                  {needsFreshDeploy ? 'Trial license activated!' : 'License activated successfully!'}
                </p>
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

          {/* ==================== TRIAL ACTIVE SECTION ==================== */}
          {(isTrialActive || isProRequested) && !success && (
            <div className="space-y-4">
              {/* Status badge */}
              <div className={cn(
                "p-4 rounded-lg border",
                isProRequested
                  ? "bg-purple-500/10 border-purple-500/30"
                  : "bg-cyan-500/10 border-cyan-500/30"
              )}>
                <div className="flex items-center justify-between mb-2">
                  <span className={cn(
                    "text-sm font-medium",
                    isProRequested ? "text-purple-400" : "text-cyan-400"
                  )}>
                    {isProRequested ? 'Pro License Requested' : 'Trial Active'}
                  </span>
                  {status?.days_remaining !== undefined && (
                    <span className="flex items-center gap-1 text-xs text-zinc-400">
                      <Clock className="w-3 h-3" />
                      {status.days_remaining} days remaining
                    </span>
                  )}
                </div>
                {status?.customer_name && (
                  <p className="text-zinc-400 text-xs">{status.customer_name}</p>
                )}
              </div>

              {/* Firewall status */}
              <div className={cn(
                "p-4 rounded-lg border",
                status?.firewall_detected
                  ? "bg-green-500/10 border-green-500/30"
                  : "bg-zinc-800/50 border-zinc-700"
              )}>
                <div className="flex items-center gap-3">
                  <Monitor className={cn(
                    "w-5 h-5",
                    status?.firewall_detected ? "text-green-400" : "text-zinc-500"
                  )} />
                  <div>
                    <p className={cn(
                      "text-sm font-medium",
                      status?.firewall_detected ? "text-green-400" : "text-zinc-400"
                    )}>
                      {status?.firewall_detected
                        ? `XGS Connected: ${status.firewall_model || 'Sophos XGS'}`
                        : 'Waiting for XGS Connection...'}
                    </p>
                    {status?.firewall_detected && status?.firewall_serial && (
                      <p className="text-xs text-zinc-500">{status.firewall_serial}</p>
                    )}
                    {!status?.firewall_detected && (
                      <p className="text-xs text-zinc-500">Configure syslog on your Sophos XGS</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Action buttons */}
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={handleSyncLicense}
                  disabled={isSyncing || isLoading}
                  className={cn(
                    "flex-1 py-2.5 px-4 rounded-lg font-medium flex items-center justify-center gap-2",
                    "bg-zinc-800 border border-zinc-700 text-zinc-300",
                    "hover:bg-zinc-700 hover:border-zinc-600",
                    "disabled:opacity-50 disabled:cursor-not-allowed",
                    "transition-all duration-200"
                  )}
                >
                  <RefreshCw className={cn("w-4 h-4", isSyncing && "animate-spin")} />
                  {isSyncing ? 'Syncing...' : 'Sync'}
                </button>

                {status?.ask_pro_available && !isProRequested && (
                  <button
                    type="button"
                    onClick={handleAskPro}
                    disabled={isLoading}
                    className={cn(
                      "flex-1 py-2.5 px-4 rounded-lg font-medium flex items-center justify-center gap-2",
                      "bg-gradient-to-r from-amber-500 to-orange-500 text-white",
                      "hover:from-amber-600 hover:to-orange-600",
                      "disabled:opacity-50 disabled:cursor-not-allowed",
                      "transition-all duration-200"
                    )}
                  >
                    <ArrowUp className="w-4 h-4" />
                    Request Pro License
                  </button>
                )}
              </div>

              {syncSuccess && (
                <p className="text-center text-xs text-green-400">
                  Synced successfully
                </p>
              )}

              {isProRequested && (
                <p className="text-center text-sm text-purple-400/80">
                  Your request has been submitted. Our team will contact you shortly.
                </p>
              )}

              {/* Link to manual activation */}
              <p className="text-center text-xs text-zinc-500 mt-4">
                Have a license key?{' '}
                <button
                  type="button"
                  onClick={() => setShowManualActivation(true)}
                  className="text-amber-400 hover:text-amber-300"
                >
                  Activate manually
                </button>
              </p>
            </div>
          )}

          {/* ==================== FRESH DEPLOY SECTION ==================== */}
          {needsFreshDeploy && !showManualActivation && !success && (
            <form onSubmit={handleFreshDeploy} className="space-y-5">
              {/* Email field */}
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-zinc-300 mb-2">
                  Email Address
                </label>
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={cn(
                    "w-full px-4 py-3 bg-zinc-800/50 border rounded-lg text-white",
                    "placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-amber-500/50",
                    "transition-all duration-200",
                    displayError ? "border-red-500/50" : "border-zinc-700 focus:border-amber-500"
                  )}
                  placeholder="your@email.com"
                  disabled={isLoading}
                  autoComplete="email"
                  autoFocus
                  required
                />
                <p className="text-xs text-zinc-500 mt-2">
                  We'll send license updates to this email
                </p>
              </div>

              {/* Submit button */}
              <button
                type="submit"
                disabled={isLoading || !email}
                className={cn(
                  "w-full py-3 px-4 rounded-lg font-medium flex items-center justify-center gap-2",
                  "bg-gradient-to-r from-amber-500 to-orange-500 text-white",
                  "hover:from-amber-600 hover:to-orange-600 transition-all duration-200",
                  "disabled:opacity-50 disabled:cursor-not-allowed",
                  "shadow-lg shadow-amber-500/20 hover:shadow-amber-500/30"
                )}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Rocket className="w-5 h-5" />
                    Start 15-Day Trial
                  </>
                )}
              </button>

              {/* Link to manual activation */}
              <p className="text-center text-sm text-zinc-500">
                Already have a license key?{' '}
                <button
                  type="button"
                  onClick={() => setShowManualActivation(true)}
                  className="text-amber-400 hover:text-amber-300"
                >
                  Activate manually
                </button>
              </p>
            </form>
          )}

          {/* ==================== MANUAL ACTIVATION SECTION ==================== */}
          {(showManualActivation || (!needsFreshDeploy && !isTrialActive && !isProRequested)) && !success && (
            <form onSubmit={handleManualActivation} className="space-y-5">
              {/* Sync button */}
              <button
                type="button"
                onClick={handleSyncLicense}
                disabled={isSyncing || isLoading}
                className={cn(
                  "w-full mb-2 py-2.5 px-4 rounded-lg font-medium flex items-center justify-center gap-2",
                  "transition-all duration-200",
                  "disabled:opacity-50 disabled:cursor-not-allowed",
                  syncSuccess
                    ? "bg-green-500/20 border border-green-500/50 text-green-400"
                    : "bg-zinc-800 border border-zinc-700 text-zinc-300 hover:bg-zinc-700 hover:border-zinc-600"
                )}
              >
                {syncSuccess ? (
                  <>
                    <CheckCircle className="w-4 h-4" />
                    Synced
                  </>
                ) : (
                  <>
                    <RefreshCw className={cn("w-4 h-4", isSyncing && "animate-spin")} />
                    {isSyncing ? 'Syncing...' : 'Sync License Status'}
                  </>
                )}
              </button>

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
                  placeholder="VX3-XXXX-XXXX-XXXX-XXXX"
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
                  "disabled:opacity-50 disabled:cursor-not-allowed",
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

              {/* Link back to trial */}
              {needsFreshDeploy && (
                <p className="text-center text-sm text-zinc-500">
                  Don't have a license?{' '}
                  <button
                    type="button"
                    onClick={() => setShowManualActivation(false)}
                    className="text-amber-400 hover:text-amber-300"
                  >
                    Start free trial
                  </button>
                </p>
              )}
            </form>
          )}

          {/* Footer */}
          <div className="mt-8 pt-6 border-t border-zinc-800">
            <div className="flex flex-col items-center gap-3">
              <div className="flex items-center gap-2 text-zinc-500 text-xs">
                <Shield className="w-4 h-4" />
                <span>VIGILANCE X v3.57.120</span>
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
          Need help? Contact support@vigilancex.io
        </p>
      </div>
    </div>
  )
}
