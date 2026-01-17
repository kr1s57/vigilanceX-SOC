import { useState } from 'react'
import { NavLink, useNavigate, useLocation, Link } from 'react-router-dom'
import {
  LayoutDashboard,
  Shield,
  ShieldCheck,
  ShieldAlert,
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
  ChevronDown,
  BarChart3,
  Radar,
  ListX,
  Mail,
  Search,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useSettings } from '@/contexts/SettingsContext'
import { useAuth } from '@/contexts/AuthContext'
import { useLicense } from '@/contexts/LicenseContext'

interface NavItem {
  name: string
  href: string
  icon: LucideIcon
  colorClass: string
  adminOnly?: boolean
}

interface NavCategory {
  name: string
  icon: LucideIcon
  colorClass: string
  items: NavItem[]
}

// Dashboard seul en haut
const standaloneItems: NavItem[] = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard, colorClass: 'text-blue-500' },
]

// Catégories avec sous-menus
const categories: NavCategory[] = [
  {
    name: 'Analytics',
    icon: BarChart3,
    colorClass: 'text-rose-500',
    items: [
      { name: 'Attack Map', href: '/attack-map', icon: Map, colorClass: 'text-rose-500' },
      { name: 'Reports', href: '/reports', icon: FileText, colorClass: 'text-indigo-500', adminOnly: true },
    ]
  },
  {
    name: 'Detection',
    icon: Radar,
    colorClass: 'text-emerald-500',
    items: [
      { name: 'WAF Explorer', href: '/waf', icon: Shield, colorClass: 'text-emerald-500' },
      { name: 'Attacks Analyzer', href: '/attacks', icon: Swords, colorClass: 'text-red-500' },
      { name: 'Advanced Threat', href: '/threats', icon: AlertTriangle, colorClass: 'text-orange-500' },
      { name: 'Vigimail Checker', href: '/vigimail', icon: Mail, colorClass: 'text-teal-500' },
    ]
  },
  {
    name: 'Protection',
    icon: ShieldAlert,
    colorClass: 'text-red-500',
    items: [
      { name: 'Active2Ban', href: '/bans', icon: Ban, colorClass: 'text-red-600' },
      { name: 'Geoblocking', href: '/geoblocking', icon: Globe, colorClass: 'text-cyan-500' },
      { name: 'Whitelist', href: '/whitelist', icon: ShieldCheck, colorClass: 'text-green-500' },
    ]
  },
  {
    name: 'Blocklists',
    icon: ListX,
    colorClass: 'text-orange-500',
    items: [
      { name: 'CrowdSec BL', href: '/crowdsec-bl', icon: Shield, colorClass: 'text-orange-500' },
      { name: 'Neural-Sync', href: '/neural-sync', icon: Brain, colorClass: 'text-purple-500' },
    ]
  },
  {
    name: 'Network',
    icon: Network,
    colorClass: 'text-purple-500',
    items: [
      { name: 'VPN & Network', href: '/vpn', icon: Network, colorClass: 'text-purple-500' },
      { name: 'Track IP', href: '/track-ip', icon: Search, colorClass: 'text-blue-500' },
      { name: 'Risk Scoring', href: '/scoring', icon: Activity, colorClass: 'text-yellow-500' },
    ]
  },
]

// Composant pour afficher un item de navigation simple
function NavItemComponent({ item, useColorIcons }: { item: NavItem; useColorIcons: boolean }) {
  return (
    <NavLink
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
  )
}

// Composant pour une catégorie avec sous-menus
function CategoryItem({
  category,
  isOpen,
  onToggle,
  useColorIcons,
  isAdmin,
}: {
  category: NavCategory
  isOpen: boolean
  onToggle: () => void
  useColorIcons: boolean
  isAdmin: boolean
}) {
  const location = useLocation()

  // Filtrer les items selon le rôle admin
  const visibleItems = category.items.filter(item => !item.adminOnly || isAdmin)

  // Ne pas afficher la catégorie si aucun item visible
  if (visibleItems.length === 0) return null

  const hasActiveChild = visibleItems.some(item => item.href === location.pathname)

  return (
    <div>
      {/* Header de catégorie (cliquable) */}
      <button
        onClick={onToggle}
        className={cn(
          'w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
          hasActiveChild
            ? 'bg-primary/5 text-primary'
            : 'text-muted-foreground hover:bg-muted hover:text-foreground'
        )}
      >
        <category.icon
          className={cn(
            'w-5 h-5 transition-colors',
            useColorIcons ? category.colorClass : ''
          )}
        />
        <span className="flex-1 text-left">{category.name}</span>
        <ChevronDown
          className={cn(
            'w-4 h-4 transition-transform duration-200',
            isOpen ? 'rotate-180' : ''
          )}
        />
      </button>

      {/* Sous-menus (avec animation) */}
      <div
        className={cn(
          'overflow-hidden transition-all duration-200',
          isOpen ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'
        )}
      >
        <div className="ml-4 mt-1 space-y-0.5 border-l border-border pl-3">
          {visibleItems.map((item) => (
            <NavLink
              key={item.href}
              to={item.href}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-3 py-1.5 rounded-lg text-sm transition-colors',
                  isActive
                    ? 'bg-primary/10 text-primary font-medium'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                )
              }
            >
              {({ isActive }) => (
                <>
                  <item.icon
                    className={cn(
                      'w-4 h-4 transition-colors',
                      useColorIcons && !isActive ? item.colorClass : ''
                    )}
                  />
                  {item.name}
                </>
              )}
            </NavLink>
          ))}
        </div>
      </div>
    </div>
  )
}

export function Sidebar() {
  const navigate = useNavigate()
  const location = useLocation()
  const { settings } = useSettings()
  const { user, isAdmin, logout } = useAuth()
  const { status: licenseStatus, isLicensed } = useLicense()
  const useColorIcons = settings.iconStyle === 'color'

  // State pour tracker les catégories ouvertes
  const [openCategories, setOpenCategories] = useState<Set<string>>(() => {
    // Par défaut, ouvrir la catégorie contenant la route active
    const currentPath = location.pathname
    const initialOpen = new Set<string>()

    categories.forEach(cat => {
      if (cat.items.some(item => item.href === currentPath)) {
        initialOpen.add(cat.name)
      }
    })

    return initialOpen
  })

  const toggleCategory = (categoryName: string) => {
    setOpenCategories(prev => {
      const next = new Set(prev)
      if (next.has(categoryName)) {
        next.delete(categoryName)
      } else {
        next.add(categoryName)
      }
      return next
    })
  }

  const handleLogout = () => {
    navigate('/login', { replace: true })
    setTimeout(() => logout(), 50)
  }

  return (
    <aside className="w-64 bg-card border-r border-border flex flex-col">
      {/* Logo - Clickable to Dashboard */}
      <div className="h-16 flex items-center px-6 border-b border-border">
        <Link to="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
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
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {/* Items standalone (Dashboard) */}
        {standaloneItems.map((item) => (
          <NavItemComponent key={item.href} item={item} useColorIcons={useColorIcons} />
        ))}

        {/* Séparateur visuel */}
        <div className="my-2 border-t border-border/50" />

        {/* Catégories avec sous-menus */}
        {categories.map((category) => (
          <CategoryItem
            key={category.name}
            category={category}
            isOpen={openCategories.has(category.name)}
            onToggle={() => toggleCategory(category.name)}
            useColorIcons={useColorIcons}
            isAdmin={isAdmin}
          />
        ))}
      </nav>

      {/* License Status & Settings */}
      <div className="px-3 py-4 border-t border-border space-y-1">
        {/* License Status Indicator - v3.55.116: Color based on days remaining */}
        {(() => {
          const days = licenseStatus?.days_remaining
          const getLicenseColor = () => {
            if (!isLicensed) {
              return licenseStatus?.grace_mode
                ? "bg-amber-500/10 text-amber-400"
                : "bg-red-500/10 text-red-400"
            }
            // Licensed - check days remaining
            if (days !== undefined && days <= 15) return "bg-red-500/10 text-red-400"
            if (days !== undefined && days <= 30) return "bg-orange-500/10 text-orange-400"
            return "bg-green-500/10 text-green-400"
          }
          return (
            <div className={cn("flex items-center gap-3 px-3 py-2 rounded-lg text-sm", getLicenseColor())}>
              {isLicensed ? (
                <Key className="w-4 h-4" />
              ) : (
                <AlertCircle className="w-4 h-4" />
              )}
              <div className="flex-1 min-w-0">
                <p className="font-medium truncate">
                  {isLicensed
                    ? days !== undefined && days <= 15
                      ? `License expiring!`
                      : days !== undefined && days <= 30
                        ? `License expiring`
                        : 'Licensed'
                    : licenseStatus?.grace_mode
                      ? 'Grace Mode'
                      : 'Unlicensed'}
                </p>
                {isLicensed && days !== undefined && (
                  <p className="text-xs opacity-75">
                    {days} days remaining
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
          )
        })()}

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
