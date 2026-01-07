import { useState, useEffect } from 'react'
import {
  Settings as SettingsIcon,
  Monitor,
  Bell,
  Shield,
  Plug,
  RotateCcw,
  Sun,
  Moon,
  Laptop,
  Check,
  RefreshCw,
  Clock,
  Eye,
  EyeOff,
  Volume2,
  VolumeX,
  Globe,
  Hash,
  Calendar,
  Users,
  Zap,
  Lock,
  Server,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  Pencil,
  X,
  Key,
  Save,
} from 'lucide-react'
import { useSettings, type AppSettings } from '@/contexts/SettingsContext'
import { threatsApi, bansApi, modsecApi, statusApi } from '@/lib/api'
import { cn } from '@/lib/utils'

interface ThreatProvider {
  name: string
  configured: boolean
  description: string
}

interface IntegrationStatus {
  sophosApi: { connected: boolean; host: string; groupCount: number }
  sophosSsh: { connected: boolean; lastSync: string | null; message: string }
  sophosSyslog: { connected: boolean; lastEvent: string | null; eventsPerMinute: number }
  threatProviders: ThreatProvider[]
}

interface PluginConfig {
  id: string
  name: string
  type: 'sophos' | 'threat_intel' | 'syslog'
  fields: { key: string; label: string; type: 'text' | 'password' | 'number'; value: string; placeholder?: string }[]
}

// Plugin configurations (would come from backend in production)
const defaultPluginConfigs: PluginConfig[] = [
  {
    id: 'sophos_api',
    name: 'Sophos XGS - API',
    type: 'sophos',
    fields: [
      { key: 'SOPHOS_HOST', label: 'Host/IP', type: 'text', value: '', placeholder: '192.168.1.1' },
      { key: 'SOPHOS_PORT', label: 'Port', type: 'number', value: '4444', placeholder: '4444' },
      { key: 'SOPHOS_USER', label: 'Username', type: 'text', value: '', placeholder: 'admin' },
      { key: 'SOPHOS_PASSWORD', label: 'Password', type: 'password', value: '', placeholder: '********' },
    ],
  },
  {
    id: 'sophos_ssh',
    name: 'Sophos XGS - SSH',
    type: 'sophos',
    fields: [
      { key: 'SSH_HOST', label: 'Host/IP', type: 'text', value: '', placeholder: '192.168.1.1' },
      { key: 'SSH_PORT', label: 'Port', type: 'number', value: '22', placeholder: '22' },
      { key: 'SSH_USER', label: 'Username', type: 'text', value: '', placeholder: 'root' },
      { key: 'SSH_KEY_PATH', label: 'SSH Key Path', type: 'text', value: '', placeholder: '/root/.ssh/id_rsa' },
    ],
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    type: 'threat_intel',
    fields: [
      { key: 'ABUSEIPDB_API_KEY', label: 'API Key', type: 'password', value: '', placeholder: 'Enter API key...' },
    ],
  },
  {
    id: 'virustotal',
    name: 'VirusTotal',
    type: 'threat_intel',
    fields: [
      { key: 'VIRUSTOTAL_API_KEY', label: 'API Key', type: 'password', value: '', placeholder: 'Enter API key...' },
    ],
  },
  {
    id: 'alienvault',
    name: 'AlienVault OTX',
    type: 'threat_intel',
    fields: [
      { key: 'ALIENVAULT_API_KEY', label: 'API Key', type: 'password', value: '', placeholder: 'Enter API key...' },
    ],
  },
  {
    id: 'greynoise',
    name: 'GreyNoise',
    type: 'threat_intel',
    fields: [
      { key: 'GREYNOISE_API_KEY', label: 'API Key', type: 'password', value: '', placeholder: 'Enter API key...' },
    ],
  },
  {
    id: 'criminalip',
    name: 'Criminal IP',
    type: 'threat_intel',
    fields: [
      { key: 'CRIMINALIP_API_KEY', label: 'API Key', type: 'password', value: '', placeholder: 'Enter API key...' },
    ],
  },
  {
    id: 'pulsedive',
    name: 'Pulsedive',
    type: 'threat_intel',
    fields: [
      { key: 'PULSEDIVE_API_KEY', label: 'API Key', type: 'password', value: '', placeholder: 'Enter API key...' },
    ],
  },
]

export function Settings() {
  const { settings, updateSettings, resetSettings } = useSettings()
  const [integrations, setIntegrations] = useState<IntegrationStatus | null>(null)
  const [loadingIntegrations, setLoadingIntegrations] = useState(true)
  const [saved, setSaved] = useState(false)

  // Plugin editor state
  const [editingPlugin, setEditingPlugin] = useState<PluginConfig | null>(null)
  const [pluginFormData, setPluginFormData] = useState<Record<string, string>>({})
  const [savingPlugin, setSavingPlugin] = useState(false)

  // Fetch integration status
  useEffect(() => {
    async function fetchIntegrations() {
      setLoadingIntegrations(true)
      try {
        const [providers, xgsStatus, modsecStats, sshTest, syslogStatus] = await Promise.all([
          threatsApi.providers(),
          bansApi.xgsStatus().catch(() => ({ connected: false, host: '', total_in_group: 0 })),
          modsecApi.getStats().catch(() => ({ last_sync: null, is_configured: false })),
          modsecApi.testConnection().catch(() => ({ status: 'error', message: 'Connection failed' })),
          statusApi.syslog().catch(() => ({ is_receiving: false, last_event_time: '', events_last_hour: 0, seconds_since_last: 0 })),
        ])

        // Calculate events per minute from events_last_hour
        const eventsPerMin = Math.round((syslogStatus.events_last_hour || 0) / 60)

        setIntegrations({
          sophosApi: {
            connected: xgsStatus.connected || false,
            host: xgsStatus.host || 'Non configure',
            groupCount: xgsStatus.total_in_group || 0,
          },
          sophosSsh: {
            connected: sshTest.status === 'ok',
            lastSync: modsecStats.last_sync || null,
            message: sshTest.message || '',
          },
          sophosSyslog: {
            connected: syslogStatus.is_receiving || false,
            lastEvent: syslogStatus.last_event_time || null,
            eventsPerMinute: eventsPerMin,
          },
          // v1.6: Store all 7 threat intel providers dynamically
          threatProviders: providers.map(p => ({
            name: p.name,
            configured: p.configured,
            description: p.description || '',
          })),
        })
      } catch (err) {
        console.error('Failed to fetch integrations:', err)
      } finally {
        setLoadingIntegrations(false)
      }
    }

    fetchIntegrations()
  }, [])

  // Show saved indicator
  const handleChange = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    updateSettings({ [key]: value })
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  // Plugin editor functions
  const handleEditPlugin = (pluginId: string) => {
    const plugin = defaultPluginConfigs.find(p => p.id === pluginId)
    if (plugin) {
      setEditingPlugin(plugin)
      // Initialize form data with current values
      const initialData: Record<string, string> = {}
      plugin.fields.forEach(field => {
        initialData[field.key] = field.value
      })
      setPluginFormData(initialData)
    }
  }

  const handlePluginFieldChange = (key: string, value: string) => {
    setPluginFormData(prev => ({ ...prev, [key]: value }))
  }

  const handleSavePlugin = async () => {
    if (!editingPlugin) return
    setSavingPlugin(true)
    try {
      // In production, this would call a backend API to save the config
      // For now, we just show a success message
      console.log('Saving plugin config:', editingPlugin.id, pluginFormData)
      await new Promise(resolve => setTimeout(resolve, 500)) // Simulate API call
      setEditingPlugin(null)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      console.error('Failed to save plugin config:', err)
    } finally {
      setSavingPlugin(false)
    }
  }

  // Find plugin by provider name
  const findPluginByName = (name: string): string | null => {
    const nameMap: Record<string, string> = {
      'AbuseIPDB': 'abuseipdb',
      'VirusTotal': 'virustotal',
      'AlienVault OTX': 'alienvault',
      'GreyNoise': 'greynoise',
      'Criminal IP': 'criminalip',
      'Pulsedive': 'pulsedive',
      'IPSum': null as unknown as string, // No API key needed
    }
    return nameMap[name] || null
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <SettingsIcon className="w-7 h-7" />
            Settings
          </h1>
          <p className="text-muted-foreground">Configure your VIGILANCE X experience</p>
        </div>
        <div className="flex items-center gap-3">
          {saved && (
            <span className="flex items-center gap-2 text-sm text-green-500 animate-in fade-in">
              <Check className="w-4 h-4" />
              Saved
            </span>
          )}
          <button
            onClick={resetSettings}
            className="flex items-center gap-2 px-4 py-2 text-sm bg-muted hover:bg-muted/80 rounded-lg transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
            Reset to defaults
          </button>
        </div>
      </div>

      {/* Display Settings */}
      <SettingsSection
        title="Display"
        description="Appearance and formatting preferences"
        icon={<Monitor className="w-5 h-5" />}
      >
        {/* Theme */}
        <SettingRow
          label="Theme"
          description="Choose the color theme for the interface"
          icon={<Sun className="w-4 h-4" />}
        >
          <ToggleGroup
            value={settings.theme}
            onChange={(v) => handleChange('theme', v as AppSettings['theme'])}
            options={[
              { value: 'light', label: 'Light', icon: <Sun className="w-4 h-4" /> },
              { value: 'dark', label: 'Dark', icon: <Moon className="w-4 h-4" /> },
              { value: 'system', label: 'System', icon: <Laptop className="w-4 h-4" /> },
            ]}
          />
        </SettingRow>

        {/* Language */}
        <SettingRow
          label="Language"
          description="Interface language"
          icon={<Globe className="w-4 h-4" />}
        >
          <ToggleGroup
            value={settings.language}
            onChange={(v) => handleChange('language', v as AppSettings['language'])}
            options={[
              { value: 'fr', label: 'Francais' },
              { value: 'en', label: 'English' },
            ]}
          />
        </SettingRow>

        {/* Date Format */}
        <SettingRow
          label="Time format"
          description="How times are displayed"
          icon={<Clock className="w-4 h-4" />}
        >
          <ToggleGroup
            value={settings.dateFormat}
            onChange={(v) => handleChange('dateFormat', v as AppSettings['dateFormat'])}
            options={[
              { value: '24h', label: '24h (14:30)' },
              { value: '12h', label: '12h (2:30 PM)' },
            ]}
          />
        </SettingRow>

        {/* Number Format */}
        <SettingRow
          label="Number format"
          description="Thousands separator style"
          icon={<Hash className="w-4 h-4" />}
        >
          <ToggleGroup
            value={settings.numberFormat}
            onChange={(v) => handleChange('numberFormat', v as AppSettings['numberFormat'])}
            options={[
              { value: 'fr', label: '1 234,56' },
              { value: 'en', label: '1,234.56' },
            ]}
          />
        </SettingRow>

        {/* Default Period */}
        <SettingRow
          label="Default time period"
          description="Default filter for dashboards and charts"
          icon={<Calendar className="w-4 h-4" />}
        >
          <ToggleGroup
            value={settings.defaultPeriod}
            onChange={(v) => handleChange('defaultPeriod', v as AppSettings['defaultPeriod'])}
            options={[
              { value: '1h', label: '1h' },
              { value: '24h', label: '24h' },
              { value: '7d', label: '7d' },
              { value: '30d', label: '30d' },
            ]}
          />
        </SettingRow>
      </SettingsSection>

      {/* Dashboard & Refresh Settings */}
      <SettingsSection
        title="Dashboard & Refresh"
        description="Data refresh and display options"
        icon={<RefreshCw className="w-5 h-5" />}
      >
        {/* Refresh Interval */}
        <SettingRow
          label="Auto-refresh interval"
          description="How often to refresh data automatically"
          icon={<RefreshCw className="w-4 h-4" />}
        >
          <ToggleGroup
            value={String(settings.refreshInterval)}
            onChange={(v) => handleChange('refreshInterval', Number(v) as AppSettings['refreshInterval'])}
            options={[
              { value: '15', label: '15s' },
              { value: '30', label: '30s' },
              { value: '60', label: '60s' },
              { value: '0', label: 'Manual' },
            ]}
          />
        </SettingRow>

        {/* Top Attackers Count */}
        <SettingRow
          label="Top Attackers displayed"
          description="Number of top attackers shown on dashboard"
          icon={<Users className="w-4 h-4" />}
        >
          <ToggleGroup
            value={String(settings.topAttackersCount)}
            onChange={(v) => handleChange('topAttackersCount', Number(v) as AppSettings['topAttackersCount'])}
            options={[
              { value: '5', label: '5' },
              { value: '10', label: '10' },
              { value: '20', label: '20' },
            ]}
          />
        </SettingRow>

        {/* Animations */}
        <SettingRow
          label="Animations"
          description="Enable smooth transitions and animations"
          icon={<Zap className="w-4 h-4" />}
        >
          <ToggleSwitch
            checked={settings.animationsEnabled}
            onChange={(v) => handleChange('animationsEnabled', v)}
          />
        </SettingRow>
      </SettingsSection>

      {/* Notifications Settings */}
      <SettingsSection
        title="Notifications"
        description="Alert and notification preferences"
        icon={<Bell className="w-5 h-5" />}
      >
        {/* Notifications Enabled */}
        <SettingRow
          label="Enable notifications"
          description="Show notifications for security alerts"
          icon={<Bell className="w-4 h-4" />}
        >
          <ToggleSwitch
            checked={settings.notificationsEnabled}
            onChange={(v) => handleChange('notificationsEnabled', v)}
          />
        </SettingRow>

        {/* Sound Enabled */}
        <SettingRow
          label="Alert sound"
          description="Play sound for critical alerts"
          icon={settings.soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
        >
          <ToggleSwitch
            checked={settings.soundEnabled}
            onChange={(v) => handleChange('soundEnabled', v)}
            disabled={!settings.notificationsEnabled}
          />
        </SettingRow>

        {/* Alert Threshold */}
        <SettingRow
          label="Alert threshold"
          description="Which severity levels trigger notifications"
          icon={<AlertTriangle className="w-4 h-4" />}
        >
          <ToggleGroup
            value={settings.alertThreshold}
            onChange={(v) => handleChange('alertThreshold', v as AppSettings['alertThreshold'])}
            options={[
              { value: 'critical', label: 'Critical only' },
              { value: 'critical+high', label: 'Critical + High' },
            ]}
            disabled={!settings.notificationsEnabled}
          />
        </SettingRow>
      </SettingsSection>

      {/* Security Settings */}
      <SettingsSection
        title="Security & Privacy"
        description="Security and data display options"
        icon={<Shield className="w-5 h-5" />}
      >
        {/* Session Timeout */}
        <SettingRow
          label="Session timeout"
          description="Auto logout after inactivity (not implemented)"
          icon={<Lock className="w-4 h-4" />}
        >
          <ToggleGroup
            value={String(settings.sessionTimeout)}
            onChange={(v) => handleChange('sessionTimeout', Number(v) as AppSettings['sessionTimeout'])}
            options={[
              { value: '15', label: '15 min' },
              { value: '30', label: '30 min' },
              { value: '60', label: '1 hour' },
              { value: '0', label: 'Never' },
            ]}
          />
        </SettingRow>

        {/* Mask Sensitive IPs */}
        <SettingRow
          label="Mask sensitive IPs"
          description="Partially hide IP addresses (e.g., 192.168.1.***)"
          icon={settings.maskSensitiveIPs ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
        >
          <ToggleSwitch
            checked={settings.maskSensitiveIPs}
            onChange={(v) => handleChange('maskSensitiveIPs', v)}
          />
        </SettingRow>
      </SettingsSection>

      {/* Integrations Status */}
      <SettingsSection
        title="Integrations"
        description="Status and configuration of external services"
        icon={<Plug className="w-5 h-5" />}
      >
        {loadingIntegrations ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <>
            {/* Sophos XGS Syslog */}
            <IntegrationRow
              name="Sophos XGS - Syslog"
              description={
                integrations?.sophosSyslog.connected
                  ? `Receiving logs (~${integrations.sophosSyslog.eventsPerMinute}/min)`
                  : 'Not receiving logs'
              }
              connected={integrations?.sophosSyslog.connected || false}
              icon={<Server className="w-4 h-4" />}
            />

            {/* Sophos XGS SSH */}
            <IntegrationRow
              name="Sophos XGS - SSH"
              description={
                integrations?.sophosSsh.connected
                  ? integrations.sophosSsh.lastSync
                    ? `ModSec sync: ${new Date(integrations.sophosSsh.lastSync).toLocaleString()}`
                    : 'SSH connected - Never synced'
                  : integrations?.sophosSsh.message || 'SSH not configured'
              }
              connected={integrations?.sophosSsh.connected || false}
              icon={<RefreshCw className="w-4 h-4" />}
              onEdit={() => handleEditPlugin('sophos_ssh')}
            />

            {/* Sophos XGS API */}
            <IntegrationRow
              name="Sophos XGS - API"
              description={
                integrations?.sophosApi.connected
                  ? `${integrations.sophosApi.host} (${integrations.sophosApi.groupCount} bans in group)`
                  : 'API not configured'
              }
              connected={integrations?.sophosApi.connected || false}
              icon={<Plug className="w-4 h-4" />}
              onEdit={() => handleEditPlugin('sophos_api')}
            />

            {/* Threat Intel Providers */}
            {integrations?.threatProviders.map((provider) => {
              const pluginId = findPluginByName(provider.name)
              return (
                <IntegrationRow
                  key={provider.name}
                  name={provider.name}
                  description={provider.description}
                  connected={provider.configured}
                  icon={<Shield className="w-4 h-4" />}
                  onEdit={pluginId ? () => handleEditPlugin(pluginId) : undefined}
                />
              )
            })}
          </>
        )}
      </SettingsSection>

      {/* Plugin Edit Modal */}
      {editingPlugin && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-xl border p-6 w-full max-w-md shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-primary/10 rounded-lg">
                  <Key className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold">{editingPlugin.name}</h3>
                  <p className="text-sm text-muted-foreground">Configure integration settings</p>
                </div>
              </div>
              <button
                onClick={() => setEditingPlugin(null)}
                className="p-1 hover:bg-muted rounded"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              {editingPlugin.fields.map((field) => (
                <div key={field.key}>
                  <label className="block text-sm font-medium mb-1">{field.label}</label>
                  <input
                    type={field.type}
                    value={pluginFormData[field.key] || ''}
                    onChange={(e) => handlePluginFieldChange(field.key, e.target.value)}
                    placeholder={field.placeholder}
                    className="w-full px-3 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary text-sm"
                  />
                </div>
              ))}

              <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3 mt-4">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-500 mt-0.5" />
                  <div className="text-sm text-yellow-600 dark:text-yellow-400">
                    <p className="font-medium">Environment variables required</p>
                    <p className="text-xs mt-1 opacity-80">
                      Changes must be applied to your .env file and the service restarted for them to take effect.
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setEditingPlugin(null)}
                  className="flex-1 px-4 py-2 bg-muted rounded-lg hover:bg-muted/80 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSavePlugin}
                  disabled={savingPlugin}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50"
                >
                  {savingPlugin ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Save className="w-4 h-4" />
                  )}
                  Save Configuration
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Version Info */}
      <div className="text-center text-sm text-muted-foreground py-4 border-t border-border">
        <p>VIGILANCE X v2.3.0</p>
        <p className="mt-1">Security Operations Center - Enhanced OSINT Stack</p>
      </div>
    </div>
  )
}

// Helper Components

function SettingsSection({
  title,
  description,
  icon,
  children,
}: {
  title: string
  description: string
  icon: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="bg-card rounded-xl border">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-border">
        <div className="p-2 bg-primary/10 text-primary rounded-lg">{icon}</div>
        <div>
          <h2 className="font-semibold">{title}</h2>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
      </div>
      <div className="divide-y divide-border">{children}</div>
    </div>
  )
}

function SettingRow({
  label,
  description,
  icon,
  children,
}: {
  label: string
  description: string
  icon: React.ReactNode
  children: React.ReactNode
}) {
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

function ToggleGroup({
  value,
  onChange,
  options,
  disabled,
}: {
  value: string
  onChange: (value: string) => void
  options: { value: string; label: string; icon?: React.ReactNode }[]
  disabled?: boolean
}) {
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

function ToggleSwitch({
  checked,
  onChange,
  disabled,
}: {
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
}) {
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

function IntegrationRow({
  name,
  description,
  connected,
  icon,
  onEdit,
}: {
  name: string
  description: string
  connected: boolean
  icon: React.ReactNode
  onEdit?: () => void
}) {
  return (
    <div className="flex items-center justify-between px-6 py-4">
      <div className="flex items-center gap-3">
        <div className="text-muted-foreground">{icon}</div>
        <div>
          <p className="font-medium">{name}</p>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
      </div>
      <div className="flex items-center gap-3">
        {onEdit && (
          <button
            onClick={onEdit}
            className="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors"
            title="Edit configuration"
          >
            <Pencil className="w-4 h-4" />
          </button>
        )}
        <div
          className={cn(
            'flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium',
            connected ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500'
          )}
        >
          {connected ? (
            <>
              <CheckCircle className="w-4 h-4" />
              Connected
            </>
          ) : (
            <>
              <XCircle className="w-4 h-4" />
              Not configured
            </>
          )}
        </div>
      </div>
    </div>
  )
}
