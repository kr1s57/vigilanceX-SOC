import { NavLink, useNavigate } from 'react-router-dom'
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
  Users,
  LogOut,
  LucideIcon,
  Key,
  AlertCircle,
  Map,
  Brain,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useSettings } from '@/contexts/SettingsContext'
import { useAuth } from '@/contexts/AuthContext'
import { useLicense } from '@/contexts/LicenseContext'

interface NavItem {
  name: string
  href: string
  icon: LucideIcon
  colorClass: string // Color for 'color' icon style
  adminOnly?: boolean // Only show for admin users
}

const navigation: NavItem[] = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard, colorClass: 'text-blue-500' },
  { name: 'Attack Map', href: '/attack-map', icon: Map, colorClass: 'text-rose-500' },
  { name: 'WAF Explorer', href: '/waf', icon: Shield, colorClass: 'text-emerald-500' },
  { name: 'Attacks Analyzer', href: '/attacks', icon: Swords, colorClass: 'text-red-500' },
  { name: 'Advanced Threat', href: '/threats', icon: AlertTriangle, colorClass: 'text-orange-500' },
  { name: 'VPN & Network', href: '/vpn', icon: Network, colorClass: 'text-purple-500' },
  { name: 'Active Bans', href: '/bans', icon: Ban, colorClass: 'text-red-600' },
  { name: 'Geoblocking', href: '/geoblocking', icon: Globe, colorClass: 'text-cyan-500' },
  { name: 'Whitelist', href: '/whitelist', icon: ShieldCheck, colorClass: 'text-green-500' },
  { name: 'Risk Scoring', href: '/scoring', icon: Activity, colorClass: 'text-yellow-500' },
  { name: 'CrowdSec BL', href: '/crowdsec-bl', icon: Shield, colorClass: 'text-orange-500' },
  { name: 'Neural-Sync', href: '/neural-sync', icon: Brain, colorClass: 'text-purple-500' },
  { name: 'Reports', href: '/reports', icon: FileText, colorClass: 'text-indigo-500', adminOnly: true },
]

export function Sidebar() {
  const navigate = useNavigate()
  const { settings } = useSettings()
  const { user, isAdmin, logout } = useAuth()
  const { status: licenseStatus, isLicensed } = useLicense()
  const useColorIcons = settings.iconStyle === 'color'

  // Filter navigation based on user role
  const filteredNavigation = navigation.filter(item => !item.adminOnly || isAdmin)

  const handleLogout = () => {
    // Navigate first, then logout to prevent flickering from ProtectedRoute redirect
    navigate('/login', { replace: true })
    // Small delay to ensure navigation starts before state changes
    setTimeout(() => logout(), 50)
  }

  return (
    <aside className="w-64 bg-card border-r border-border flex flex-col">
      {/* Logo */}
      <div className="h-16 flex items-center px-6 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
            {/* Geometric Eye - Abstract Iris */}
            <svg
              viewBox="0 0 24 24"
              className="w-5 h-5 text-primary-foreground"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              {/* Outer eye shape */}
              <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
              {/* Inner iris - geometric hexagon */}
              <polygon points="12,8 15,10 15,14 12,16 9,14 9,10" />
              {/* Center pupil */}
              <circle cx="12" cy="12" r="1.5" fill="currentColor" />
            </svg>
          </div>
          <div>
            <h1 className="font-bold text-lg">VIGILANCE X</h1>
            <p className="text-xs text-muted-foreground">Security Operations</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {filteredNavigation.map((item) => (
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

      {/* License Status & Settings */}
      <div className="px-3 py-4 border-t border-border space-y-1">
        {/* License Status Indicator */}
        <div className={cn(
          "flex items-center gap-3 px-3 py-2 rounded-lg text-sm",
          isLicensed
            ? "bg-green-500/10 text-green-400"
            : licenseStatus?.grace_mode
              ? "bg-amber-500/10 text-amber-400"
              : "bg-red-500/10 text-red-400"
        )}>
          {isLicensed ? (
            <Key className="w-4 h-4" />
          ) : (
            <AlertCircle className="w-4 h-4" />
          )}
          <div className="flex-1 min-w-0">
            <p className="font-medium truncate">
              {isLicensed
                ? 'Licensed'
                : licenseStatus?.grace_mode
                  ? 'Grace Mode'
                  : 'Unlicensed'}
            </p>
            {isLicensed && licenseStatus?.days_remaining !== undefined && (
              <p className="text-xs opacity-75">
                {licenseStatus.days_remaining} days remaining
              </p>
            )}
            {licenseStatus?.grace_mode && (
              <p className="text-xs opacity-75">
                Server unreachable
              </p>
            )}
          </div>
          {isAdmin && (
            <NavLink
              to="/license"
              className="p-1 hover:bg-white/10 rounded transition-colors"
              title="Manage License"
            >
              <Settings className="w-3 h-3" />
            </NavLink>
          )}
        </div>

        {/* Users - Admin only */}
        {isAdmin && (
          <NavLink
            to="/users"
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
                <Users
                  className={cn(
                    'w-5 h-5 transition-colors',
                    useColorIcons && !isActive ? 'text-sky-500' : ''
                  )}
                />
                Users
              </>
            )}
          </NavLink>
        )}

        {/* Settings - Admin only */}
        {isAdmin && (
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
        )}

        {/* User info & logout */}
        <div className="pt-3 mt-3 border-t border-border">
          <div className="flex items-center gap-3 px-3 py-2">
            <div className={cn(
              "w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold",
              isAdmin ? "bg-amber-500/20 text-amber-400" : "bg-blue-500/20 text-blue-400"
            )}>
              {user?.username?.charAt(0).toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-foreground truncate">{user?.username}</p>
              <p className="text-xs text-muted-foreground capitalize">{user?.role}</p>
            </div>
            <button
              onClick={handleLogout}
              className="p-2 text-muted-foreground hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </aside>
  )
}
