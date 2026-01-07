import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Shield,
  ShieldCheck,
  Swords,
  AlertTriangle,
  Network,
  Ban,
  Globe,
  Activity,
  FileText,
  Settings,
  LucideIcon,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useSettings } from '@/contexts/SettingsContext'

interface NavItem {
  name: string
  href: string
  icon: LucideIcon
  colorClass: string // Color for 'color' icon style
}

const navigation: NavItem[] = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard, colorClass: 'text-blue-500' },
  { name: 'WAF Explorer', href: '/waf', icon: Shield, colorClass: 'text-emerald-500' },
  { name: 'Attacks Analyzer', href: '/attacks', icon: Swords, colorClass: 'text-red-500' },
  { name: 'Advanced Threat', href: '/threats', icon: AlertTriangle, colorClass: 'text-orange-500' },
  { name: 'VPN & Network', href: '/vpn', icon: Network, colorClass: 'text-purple-500' },
  { name: 'Active Bans', href: '/bans', icon: Ban, colorClass: 'text-red-600' },
  { name: 'Geoblocking', href: '/geoblocking', icon: Globe, colorClass: 'text-cyan-500' },
  { name: 'Whitelist', href: '/whitelist', icon: ShieldCheck, colorClass: 'text-green-500' },
  { name: 'Risk Scoring', href: '/scoring', icon: Activity, colorClass: 'text-yellow-500' },
  { name: 'Reports', href: '/reports', icon: FileText, colorClass: 'text-indigo-500' },
]

export function Sidebar() {
  const { settings } = useSettings()
  const useColorIcons = settings.iconStyle === 'color'

  return (
    <aside className="w-64 bg-card border-r border-border flex flex-col">
      {/* Logo */}
      <div className="h-16 flex items-center px-6 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
            <Shield className="w-5 h-5 text-primary-foreground" />
          </div>
          <div>
            <h1 className="font-bold text-lg">VIGILANCE X</h1>
            <p className="text-xs text-muted-foreground">Security Operations</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:bg-muted hover:text-foreground'
              )
            }
          >
            {({ isActive }) => (
              <>
                <item.icon
                  className={cn(
                    'w-5 h-5 transition-colors',
                    useColorIcons && !isActive ? item.colorClass : ''
                  )}
                />
                {item.name}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Settings */}
      <div className="px-3 py-4 border-t border-border">
        <NavLink
          to="/settings"
          className={({ isActive }) =>
            cn(
              'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
              isActive
                ? 'bg-primary/10 text-primary'
                : 'text-muted-foreground hover:bg-muted hover:text-foreground'
            )
          }
        >
          {({ isActive }) => (
            <>
              <Settings
                className={cn(
                  'w-5 h-5 transition-colors',
                  useColorIcons && !isActive ? 'text-gray-400' : ''
                )}
              />
              Settings
            </>
          )}
        </NavLink>
      </div>
    </aside>
  )
}
