import { lazy, Suspense, ComponentType } from 'react'
import { Loader2 } from 'lucide-react'

/**
 * LazyModals - Lazy-loaded modal components for VIGILANCE X
 * v3.58.108: React 18/19 Suspense boundaries for heavy modals
 *
 * Benefits:
 * - Reduces initial bundle size
 * - Loads modal code only when needed
 * - Provides smooth loading fallback
 */

// Loading fallback for modals
function ModalLoadingFallback() {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-card rounded-xl p-8 flex flex-col items-center gap-4">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Loading...</p>
      </div>
    </div>
  )
}

// Lazy load IPThreatModal
const LazyIPThreatModalComponent = lazy(() =>
  import('@/components/IPThreatModal').then(module => ({
    default: module.IPThreatModal
  }))
)

// Lazy load WAFServerModal
const LazyWAFServerModalComponent = lazy(() =>
  import('@/components/WAFServerModal').then(module => ({
    default: module.WAFServerModal
  }))
)

// Type definitions for modal props
interface IPThreatModalProps {
  ip: string | null
  isOpen: boolean
  onClose: () => void
}

interface WAFServerModalProps {
  isOpen: boolean
  onClose: () => void
  onServersUpdated?: () => void
}

/**
 * Lazy-loaded IPThreatModal with Suspense boundary
 * Use this instead of direct import for better performance
 */
export function LazyIPThreatModal(props: IPThreatModalProps) {
  // Don't render anything if modal is closed (saves resources)
  if (!props.isOpen) return null

  return (
    <Suspense fallback={<ModalLoadingFallback />}>
      <LazyIPThreatModalComponent {...props} />
    </Suspense>
  )
}

/**
 * Lazy-loaded WAFServerModal with Suspense boundary
 */
export function LazyWAFServerModal(props: WAFServerModalProps) {
  if (!props.isOpen) return null

  return (
    <Suspense fallback={<ModalLoadingFallback />}>
      <LazyWAFServerModalComponent {...props} />
    </Suspense>
  )
}

/**
 * HOC to wrap any modal component with Suspense
 * Usage: const LazyMyModal = withSuspense(lazy(() => import('./MyModal')))
 */
export function withModalSuspense<P extends object>(
  LazyComponent: ComponentType<P>
) {
  return function SuspendedModal(props: P & { isOpen?: boolean }) {
    if (!props.isOpen) return null

    return (
      <Suspense fallback={<ModalLoadingFallback />}>
        <LazyComponent {...props} />
      </Suspense>
    )
  }
}
