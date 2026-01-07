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
} from 'lucide-react'
import { cn } from '@/lib/utils'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'WAF Explorer', href: '/waf', icon: Shield },
  { name: 'Attacks Analyzer', href: '/attacks', icon: Swords },
  { name: 'Advanced Threat', href: '/threats', icon: AlertTriangle },
  { name: 'VPN & Network', href: '/vpn', icon: Network },
  { name: 'Active Bans', href: '/bans', icon: Ban },
  { name: 'Geoblocking', href: '/geoblocking', icon: Globe },
  { name: 'Whitelist', href: '/whitelist', icon: ShieldCheck },
  { name: 'Risk Scoring', href: '/scoring', icon: Activity },
  { name: 'Reports', href: '/reports', icon: FileText },
]

export function Sidebar() {
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
            <item.icon className="w-5 h-5" />
            {item.name}
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
          <Settings className="w-5 h-5" />
          Settings
        </NavLink>
      </div>
    </aside>
  )
}
