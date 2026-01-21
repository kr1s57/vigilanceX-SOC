import { ReactNode, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'

/**
 * GlassModal - Modern glassmorphism modal component
 * v3.57.106: UI Modernization
 * v3.58.108: Enhanced with Framer Motion animations
 *
 * Features:
 * - Frosted glass effect with backdrop blur
 * - Smooth Framer Motion animations
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

// Animation variants
const overlayVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1 },
}

const modalVariants = {
  hidden: {
    opacity: 0,
    scale: 0.95,
    y: 10,
  },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: {
      type: 'spring' as const,
      damping: 25,
      stiffness: 300,
    },
  },
  exit: {
    opacity: 0,
    scale: 0.95,
    y: 10,
    transition: {
      duration: 0.15,
    },
  },
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

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          {/* Backdrop with blur */}
          <motion.div
            className="absolute inset-0 bg-black/50 backdrop-blur-sm"
            variants={overlayVariants}
            initial="hidden"
            animate="visible"
            exit="hidden"
            transition={{ duration: 0.2 }}
            onClick={closeOnOverlayClick ? onClose : undefined}
          />

          {/* Modal content with glassmorphism */}
          <motion.div
            className={cn(
              'relative w-full rounded-2xl overflow-hidden',
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
            variants={modalVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
          >
            {/* Header */}
            {(title || showCloseButton) && (
              <div className="relative flex items-center justify-between p-5 border-b border-white/10">
                <div className="flex items-center gap-3">
                  {icon && (
                    <motion.div
                      className="p-2.5 rounded-xl bg-white/10 backdrop-blur-sm"
                      initial={{ scale: 0.8, opacity: 0 }}
                      animate={{ scale: 1, opacity: 1 }}
                      transition={{ delay: 0.1 }}
                    >
                      {icon}
                    </motion.div>
                  )}
                  <div>
                    {title && (
                      <motion.h2
                        className="text-lg font-semibold text-foreground"
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: 0.1 }}
                      >
                        {title}
                      </motion.h2>
                    )}
                    {subtitle && (
                      <motion.p
                        className="text-sm text-muted-foreground mt-0.5"
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: 0.15 }}
                      >
                        {subtitle}
                      </motion.p>
                    )}
                  </div>
                </div>
                {showCloseButton && (
                  <motion.button
                    onClick={onClose}
                    className={cn(
                      'p-2 rounded-xl transition-all duration-200',
                      'hover:bg-white/10 active:bg-white/20',
                      'text-muted-foreground hover:text-foreground'
                    )}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <X className="w-5 h-5" />
                  </motion.button>
                )}
              </div>
            )}

            {/* Content */}
            <motion.div
              className="relative max-h-[calc(85vh-100px)] overflow-y-auto"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.1 }}
            >
              {children}
            </motion.div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
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
  if (hover) {
    return (
      <motion.div
        className={cn(
          'rounded-xl overflow-hidden cursor-pointer',
          'bg-gradient-to-br backdrop-blur-lg',
          'border',
          'shadow-lg',
          variantClasses[variant],
          className
        )}
        whileHover={{ scale: 1.02, y: -2 }}
        transition={{ type: 'spring' as const, stiffness: 300 }}
      >
        {children}
      </motion.div>
    )
  }

  return (
    <div
      className={cn(
        'rounded-xl overflow-hidden',
        'bg-gradient-to-br backdrop-blur-lg',
        'border',
        'shadow-lg',
        variantClasses[variant],
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
    <motion.button
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'rounded-xl font-medium',
        'backdrop-blur-sm border border-white/10',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        buttonVariants[variant],
        buttonSizes[size],
        className
      )}
      whileHover={disabled ? {} : { scale: 1.02 }}
      whileTap={disabled ? {} : { scale: 0.98 }}
      transition={{ type: 'spring', stiffness: 400, damping: 17 }}
    >
      {children}
    </motion.button>
  )
}

// Animated list item for stagger effects
interface AnimatedListItemProps {
  children: ReactNode
  index?: number
  className?: string
}

export function AnimatedListItem({ children, index = 0, className }: AnimatedListItemProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      transition={{
        delay: index * 0.05,
        duration: 0.2,
      }}
      className={className}
    >
      {children}
    </motion.div>
  )
}
