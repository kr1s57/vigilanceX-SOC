import { ReactNode, useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'

/**
 * GlassModal - Modern glassmorphism modal component
 * v3.57.106: UI Modernization
 *
 * Features:
 * - Frosted glass effect with backdrop blur
 * - Smooth CSS transitions (no extra dependencies)
 * - ESC key to close
 * - Click outside to close
 * - Responsive sizing
 */

interface GlassModalProps {
  isOpen: boolean
  onClose: () => void
  title?: string
  subtitle?: string
  icon?: ReactNode
  children: ReactNode
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full'
  className?: string
  showCloseButton?: boolean
  closeOnOverlayClick?: boolean
  closeOnEsc?: boolean
}

const sizeClasses = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
  full: 'max-w-[95vw] w-full',
}

export function GlassModal({
  isOpen,
  onClose,
  title,
  subtitle,
  icon,
  children,
  size = 'lg',
  className,
  showCloseButton = true,
  closeOnOverlayClick = true,
  closeOnEsc = true,
}: GlassModalProps) {
  const modalRef = useRef<HTMLDivElement>(null)
  const [visible, setVisible] = useState(false)
  const [animating, setAnimating] = useState(false)

  // Handle open/close animations
  useEffect(() => {
    if (isOpen) {
      setAnimating(true)
      // Small delay to trigger CSS transition
      requestAnimationFrame(() => {
        setVisible(true)
      })
    } else {
      setVisible(false)
      const timer = setTimeout(() => setAnimating(false), 200)
      return () => clearTimeout(timer)
    }
  }, [isOpen])

  // Handle ESC key
  useEffect(() => {
    if (!closeOnEsc) return

    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    }

    document.addEventListener('keydown', handleEsc)
    return () => document.removeEventListener('keydown', handleEsc)
  }, [isOpen, onClose, closeOnEsc])

  // Lock body scroll when modal is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => {
      document.body.style.overflow = ''
    }
  }, [isOpen])

  if (!isOpen && !animating) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop with blur */}
      <div
        className={cn(
          'absolute inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-200',
          visible ? 'opacity-100' : 'opacity-0'
        )}
        onClick={closeOnOverlayClick ? onClose : undefined}
      />

      {/* Modal content with glassmorphism */}
      <div
        ref={modalRef}
        className={cn(
          'relative w-full rounded-2xl overflow-hidden transition-all duration-200',
          visible
            ? 'opacity-100 scale-100 translate-y-0'
            : 'opacity-0 scale-95 translate-y-4',
          // Glassmorphism effect
          'bg-gradient-to-br from-white/10 via-white/5 to-transparent',
          'dark:from-white/10 dark:via-white/5 dark:to-transparent',
          'backdrop-blur-xl',
          // Border with subtle glow
          'border border-white/20 dark:border-white/10',
          'shadow-[0_8px_32px_rgba(0,0,0,0.3)]',
          sizeClasses[size],
          className
        )}
      >
        {/* Header */}
        {(title || showCloseButton) && (
          <div className="relative flex items-center justify-between p-5 border-b border-white/10">
            <div className="flex items-center gap-3">
              {icon && (
                <div className="p-2.5 rounded-xl bg-white/10 backdrop-blur-sm">
                  {icon}
                </div>
              )}
              <div>
                {title && (
                  <h2 className="text-lg font-semibold text-foreground">
                    {title}
                  </h2>
                )}
                {subtitle && (
                  <p className="text-sm text-muted-foreground mt-0.5">
                    {subtitle}
                  </p>
                )}
              </div>
            </div>
            {showCloseButton && (
              <button
                onClick={onClose}
                className={cn(
                  'p-2 rounded-xl transition-all duration-200',
                  'hover:bg-white/10 active:bg-white/20',
                  'text-muted-foreground hover:text-foreground'
                )}
              >
                <X className="w-5 h-5" />
              </button>
            )}
          </div>
        )}

        {/* Content */}
        <div className="relative max-h-[calc(85vh-100px)] overflow-y-auto">
          {children}
        </div>
      </div>
    </div>
  )
}

// Glass card component for use inside modals or standalone
interface GlassCardProps {
  children: ReactNode
  className?: string
  variant?: 'default' | 'danger' | 'success' | 'warning' | 'info'
  hover?: boolean
}

const variantClasses = {
  default: 'from-white/10 via-white/5 to-transparent border-white/10',
  danger: 'from-red-500/20 via-red-500/10 to-transparent border-red-500/20',
  success: 'from-green-500/20 via-green-500/10 to-transparent border-green-500/20',
  warning: 'from-orange-500/20 via-orange-500/10 to-transparent border-orange-500/20',
  info: 'from-blue-500/20 via-blue-500/10 to-transparent border-blue-500/20',
}

export function GlassCard({
  children,
  className,
  variant = 'default',
  hover = false,
}: GlassCardProps) {
  return (
    <div
      className={cn(
        'rounded-xl overflow-hidden',
        'bg-gradient-to-br backdrop-blur-lg',
        'border',
        'shadow-lg',
        variantClasses[variant],
        hover && 'transition-all duration-200 hover:scale-[1.02] hover:shadow-xl',
        className
      )}
    >
      {children}
    </div>
  )
}

// Glass button component
interface GlassButtonProps {
  children: ReactNode
  onClick?: () => void
  variant?: 'default' | 'danger' | 'success' | 'primary'
  size?: 'sm' | 'md' | 'lg'
  disabled?: boolean
  className?: string
}

const buttonVariants = {
  default: 'bg-white/10 hover:bg-white/20 text-white/90',
  danger: 'bg-red-500/20 hover:bg-red-500/30 text-red-300',
  success: 'bg-green-500/20 hover:bg-green-500/30 text-green-300',
  primary: 'bg-primary/20 hover:bg-primary/30 text-primary',
}

const buttonSizes = {
  sm: 'px-3 py-1.5 text-sm',
  md: 'px-4 py-2 text-sm',
  lg: 'px-6 py-3 text-base',
}

export function GlassButton({
  children,
  onClick,
  variant = 'default',
  size = 'md',
  disabled = false,
  className,
}: GlassButtonProps) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'rounded-xl font-medium',
        'backdrop-blur-sm border border-white/10',
        'transition-all duration-200',
        'active:scale-[0.98]',
        'disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100',
        buttonVariants[variant],
        buttonSizes[size],
        className
      )}
    >
      {children}
    </button>
  )
}
