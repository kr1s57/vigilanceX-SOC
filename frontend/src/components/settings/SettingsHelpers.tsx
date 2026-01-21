import { ReactNode } from 'react'
import { ChevronDown, ChevronUp, Lock } from 'lucide-react'
import { cn } from '@/lib/utils'

interface SettingsSectionProps {
  title: string
  description: string
  icon: ReactNode
  children: ReactNode
  disabled?: boolean
  isCollapsed?: boolean
  onToggle?: () => void
}

export function SettingsSection({
  title,
  description,
  icon,
  children,
  disabled = false,
  isCollapsed = false,
  onToggle,
}: SettingsSectionProps) {
  return (
    <div className={cn("bg-card rounded-xl border relative", disabled && "opacity-60")}>
      <div
        className={cn(
          "flex items-center gap-3 px-6 py-4",
          !isCollapsed && "border-b border-border",
          onToggle && "cursor-pointer hover:bg-muted/50 transition-colors"
        )}
        onClick={onToggle}
      >
        <div className={cn("p-2 rounded-lg", disabled ? "bg-muted text-muted-foreground" : "bg-primary/10 text-primary")}>
          {icon}
        </div>
        <div className="flex-1">
          <h2 className="font-semibold flex items-center gap-2">
            {title}
            {disabled && <Lock className="w-4 h-4 text-muted-foreground" />}
          </h2>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
        {onToggle && (
          <div className="p-2 text-muted-foreground">
            {isCollapsed ? <ChevronDown className="w-5 h-5" /> : <ChevronUp className="w-5 h-5" />}
          </div>
        )}
      </div>
      {!isCollapsed && (
        <div className={cn("divide-y divide-border", disabled && "pointer-events-none")}>{children}</div>
      )}
    </div>
  )
}

interface SettingRowProps {
  label: string
  description: string
  icon: ReactNode
  children: ReactNode
}

export function SettingRow({
  label,
  description,
  icon,
  children,
}: SettingRowProps) {
  return (
    <div className="flex items-center justify-between px-6 py-4">
      <div className="flex items-center gap-3">
        <div className="text-muted-foreground">{icon}</div>
        <div>
          <p className="font-medium">{label}</p>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
      </div>
      <div>{children}</div>
    </div>
  )
}

interface ToggleGroupOption {
  value: string
  label: string
  icon?: ReactNode
}

interface ToggleGroupProps {
  value: string
  onChange: (value: string) => void
  options: ToggleGroupOption[]
  disabled?: boolean
}

export function ToggleGroup({
  value,
  onChange,
  options,
  disabled,
}: ToggleGroupProps) {
  return (
    <div className={cn('flex bg-muted rounded-lg p-1', disabled && 'opacity-50 pointer-events-none')}>
      {options.map((option) => (
        <button
          key={option.value}
          onClick={() => onChange(option.value)}
          className={cn(
            'flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
            value === option.value
              ? 'bg-background text-foreground shadow-sm'
              : 'text-muted-foreground hover:text-foreground'
          )}
        >
          {option.icon}
          {option.label}
        </button>
      ))}
    </div>
  )
}

interface ToggleSwitchProps {
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
}

export function ToggleSwitch({
  checked,
  onChange,
  disabled,
}: ToggleSwitchProps) {
  return (
    <button
      onClick={() => onChange(!checked)}
      disabled={disabled}
      className={cn(
        'relative w-12 h-6 rounded-full transition-colors',
        checked ? 'bg-primary' : 'bg-muted',
        disabled && 'opacity-50 cursor-not-allowed'
      )}
    >
      <span
        className={cn(
          'absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform',
          checked && 'translate-x-6'
        )}
      />
    </button>
  )
}
