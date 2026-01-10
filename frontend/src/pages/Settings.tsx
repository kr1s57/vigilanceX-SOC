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
  Palette,
  ChevronDown,
  ChevronUp,
  ChevronsUpDown,
  Mail,
  Send,
} from 'lucide-react'
import { useSettings, type AppSettings } from '@/contexts/SettingsContext'
import { useAuth } from '@/contexts/AuthContext'
import { threatsApi, bansApi, modsecApi, statusApi, configApi, licenseApi, notificationsApi, type LicenseStatus, type NotificationSettings } from '@/lib/api'
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
    id: 'sophos_syslog',
    name: 'Sophos XGS - Syslog',
    type: 'syslog',
    fields: [
      { key: 'SYSLOG_SOURCE_IP', label: 'Firewall IP', type: 'text', value: '', placeholder: '10.56.125.254' },
      { key: 'SYSLOG_PORT', label: 'Syslog Port (TCP)', type: 'number', value: '1514', placeholder: '1514' },
    ],
  },
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
      { key: 'SSH_HOST', label: 'Host/IP', type: 'text', value: '', placeholder: '10.56.125.254' },
      { key: 'SSH_PORT', label: 'Port', type: 'number', value: '22', placeholder: '22' },
      { key: 'SSH_USER', label: 'Username', type: 'text', value: '', placeholder: 'admin' },
      { key: 'SSH_KEY_PATH', label: 'SSH Key Path', type: 'text', value: '/app/.ssh/id_rsa_xgs', placeholder: '/app/.ssh/id_rsa_xgs' },
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
    id: 'crowdsec',
    name: 'CrowdSec',
    type: 'threat_intel',
    fields: [
      { key: 'CROWDSEC_API_KEY', label: 'CTI API Key', type: 'password', value: '', placeholder: 'Enter CrowdSec CTI API key...' },
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
  {
    id: 'smtp',
    name: 'SMTP Email',
    type: 'email' as any,
    fields: [
      { key: 'SMTP_HOST', label: 'SMTP Server', type: 'text', value: '', placeholder: 'smtp.office365.com' },
      { key: 'SMTP_PORT', label: 'Port', type: 'number', value: '587', placeholder: '587' },
      { key: 'SMTP_SECURITY', label: 'Security', type: 'text', value: 'tls', placeholder: 'tls, ssl, or none' },
      { key: 'SMTP_FROM_EMAIL', label: 'From Email', type: 'text', value: '', placeholder: 'noreply@company.com' },
      { key: 'SMTP_USERNAME', label: 'Username', type: 'text', value: '', placeholder: 'user@company.com' },
      { key: 'SMTP_PASSWORD', label: 'Password', type: 'password', value: '', placeholder: '********' },
      { key: 'SMTP_RECIPIENTS', label: 'Recipients', type: 'text', value: '', placeholder: 'admin@company.com, soc@company.com' },
    ],
  },
]

export function Settings() {
  const { settings, updateSettings, resetSettings } = useSettings()
  const { isAdmin } = useAuth()
  const [integrations, setIntegrations] = useState<IntegrationStatus | null>(null)
  const [loadingIntegrations, setLoadingIntegrations] = useState(true)
  const [saved, setSaved] = useState(false)

  // License status state
  const [licenseStatus, setLicenseStatus] = useState<LicenseStatus | null>(null)
  const [loadingLicense, setLoadingLicense] = useState(true)

  // Email notification settings state
  const [notifSettings, setNotifSettings] = useState<NotificationSettings | null>(null)
  const [loadingNotifSettings, setLoadingNotifSettings] = useState(true)
  const [savingNotifSettings, setSavingNotifSettings] = useState(false)
  const [sendingTestEmail, setSendingTestEmail] = useState(false)
  const [testEmailResult, setTestEmailResult] = useState<{ success: boolean; message: string } | null>(null)

  // Collapsible sections state - all collapsed by default
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({
    display: true,
    dashboard: true,
    notifications: true,
    email_notifications: true,
    security: true,
    license: true,
    integrations: true,
  })

  const toggleSection = (sectionId: string) => {
    setCollapsedSections(prev => ({
      ...prev,
      [sectionId]: !prev[sectionId]
    }))
  }

  const toggleAllSections = (collapse: boolean) => {
    const sections = ['display', 'dashboard', 'notifications', 'email_notifications', 'security', 'license', 'integrations']
    setCollapsedSections(
      sections.reduce((acc, section) => ({ ...acc, [section]: collapse }), {})
    )
  }

  const allCollapsed = Object.values(collapsedSections).every(Boolean)

  // Plugin editor state
  const [editingPlugin, setEditingPlugin] = useState<PluginConfig | null>(null)
  const [pluginFormData, setPluginFormData] = useState<Record<string, string>>({})
  const [savingPlugin, setSavingPlugin] = useState(false)
  const [saveResult, setSaveResult] = useState<{ success: boolean; message: string } | null>(null)

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

  // Fetch license status
  useEffect(() => {
    async function fetchLicenseStatus() {
      setLoadingLicense(true)
      try {
        const status = await licenseApi.getStatus()
        setLicenseStatus(status)
      } catch (err) {
        console.error('Failed to fetch license status:', err)
      } finally {
        setLoadingLicense(false)
      }
    }

    fetchLicenseStatus()
  }, [])

  // Fetch notification settings
  useEffect(() => {
    async function fetchNotificationSettings() {
      setLoadingNotifSettings(true)
      try {
        const settings = await notificationsApi.getSettings()
        setNotifSettings(settings)
      } catch (err) {
        console.error('Failed to fetch notification settings:', err)
      } finally {
        setLoadingNotifSettings(false)
      }
    }

    fetchNotificationSettings()
  }, [])

  // Handle notification settings change
  const handleNotifSettingChange = async <K extends keyof NotificationSettings>(key: K, value: NotificationSettings[K]) => {
    if (!notifSettings) return

    const newSettings = { ...notifSettings, [key]: value }
    setNotifSettings(newSettings)

    setSavingNotifSettings(true)
    try {
      await notificationsApi.updateSettings({ [key]: value })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      console.error('Failed to update notification setting:', err)
      // Revert on error
      setNotifSettings(notifSettings)
    } finally {
      setSavingNotifSettings(false)
    }
  }

  // Handle send test email
  const handleSendTestEmail = async () => {
    setSendingTestEmail(true)
    setTestEmailResult(null)
    try {
      const result = await notificationsApi.sendTestEmail()
      setTestEmailResult(result)
      setTimeout(() => setTestEmailResult(null), 5000)
    } catch (err: any) {
      setTestEmailResult({
        success: false,
        message: err.response?.data?.error || 'Failed to send test email'
      })
      setTimeout(() => setTestEmailResult(null), 5000)
    } finally {
      setSendingTestEmail(false)
    }
  }

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
    setSaveResult(null)
    try {
      const result = await configApi.save(editingPlugin.id, pluginFormData)
      setSaveResult({
        success: result.test.success,
        message: result.message,
      })
      // Keep modal open to show result, auto-close after 3s on success
      if (result.test.success) {
        setTimeout(() => {
          setEditingPlugin(null)
          setSaveResult(null)
          // Refresh integrations status
          window.location.reload()
        }, 2000)
      }
    } catch (err: any) {
      setSaveResult({
        success: false,
        message: err.response?.data?.error || 'Failed to save configuration',
      })
    } finally {
      setSavingPlugin(false)
    }
  }

  const handleClosePluginModal = () => {
    setEditingPlugin(null)
    setSaveResult(null)
  }

  // Find plugin by provider name
  const findPluginByName = (name: string): string | null => {
    const nameMap: Record<string, string> = {
      'AbuseIPDB': 'abuseipdb',
      'VirusTotal': 'virustotal',
      'AlienVault OTX': 'alienvault',
      'GreyNoise': 'greynoise',
      'CrowdSec': 'crowdsec', // v2.9.6
      'Criminal IP': 'criminalip',
      'Pulsedive': 'pulsedive',
      'IPSum': null as unknown as string, // No API key needed
      'ThreatFox': null as unknown as string, // No API key needed
      'URLhaus': null as unknown as string, // No API key needed
      'Shodan InternetDB': null as unknown as string, // No API key needed
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
            onClick={() => toggleAllSections(!allCollapsed)}
            className="flex items-center gap-2 px-4 py-2 text-sm bg-muted hover:bg-muted/80 rounded-lg transition-colors"
          >
            <ChevronsUpDown className="w-4 h-4" />
            {allCollapsed ? 'Expand all' : 'Collapse all'}
          </button>
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
        isCollapsed={collapsedSections['display']}
        onToggle={() => toggleSection('display')}
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

        {/* Icon Style */}
        <SettingRow
          label="Icon style"
          description="Sidebar icon appearance"
          icon={<Palette className="w-4 h-4" />}
        >
          <ToggleGroup
            value={settings.iconStyle}
            onChange={(v) => handleChange('iconStyle', v as AppSettings['iconStyle'])}
            options={[
              { value: 'mono', label: 'Monochrome' },
              { value: 'color', label: 'Color' },
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
        isCollapsed={collapsedSections['dashboard']}
        onToggle={() => toggleSection('dashboard')}
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
        isCollapsed={collapsedSections['notifications']}
        onToggle={() => toggleSection('notifications')}
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

      {/* Email Notifications (v3.3) */}
      <SettingsSection
        title="Email Notifications"
        description="SMTP configuration and scheduled email alerts"
        icon={<Mail className="w-5 h-5" />}
        isCollapsed={collapsedSections['email_notifications']}
        onToggle={() => toggleSection('email_notifications')}
      >
        {loadingNotifSettings ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <>
            {/* SMTP Status */}
            <div className="flex items-center justify-between px-6 py-4">
              <div className="flex items-center gap-3">
                <div className="text-muted-foreground">
                  <Server className="w-4 h-4" />
                </div>
                <div>
                  <p className="font-medium">SMTP Server</p>
                  <p className="text-sm text-muted-foreground">
                    {notifSettings?.smtp_configured ? 'Configured' : 'Not configured'}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                {isAdmin && (
                  <button
                    onClick={() => handleEditPlugin('smtp')}
                    className="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors"
                    title="Configure SMTP"
                  >
                    <Pencil className="w-4 h-4" />
                  </button>
                )}
                <div
                  className={cn(
                    'flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium',
                    notifSettings?.smtp_configured ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500'
                  )}
                >
                  {notifSettings?.smtp_configured ? (
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

            {/* Test Email Button */}
            {notifSettings?.smtp_configured && (
              <div className="flex items-center justify-between px-6 py-4">
                <div className="flex items-center gap-3">
                  <div className="text-muted-foreground">
                    <Send className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="font-medium">Send Test Email</p>
                    <p className="text-sm text-muted-foreground">Verify email delivery</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {testEmailResult && (
                    <span className={cn(
                      'text-sm',
                      testEmailResult.success ? 'text-green-500' : 'text-red-500'
                    )}>
                      {testEmailResult.message}
                    </span>
                  )}
                  <button
                    onClick={handleSendTestEmail}
                    disabled={sendingTestEmail}
                    className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50"
                  >
                    {sendingTestEmail ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Send className="w-4 h-4" />
                    )}
                    {sendingTestEmail ? 'Sending...' : 'Send Test'}
                  </button>
                </div>
              </div>
            )}

            {/* Scheduled Reports Section */}
            <div className="px-6 py-3 bg-muted/30 border-t border-b">
              <p className="text-sm font-medium text-muted-foreground">Scheduled Reports</p>
            </div>

            {/* Daily Report */}
            <SettingRow
              label="Daily Report"
              description={`Send daily summary at ${notifSettings?.daily_report_time || '08:00'}`}
              icon={<Calendar className="w-4 h-4" />}
            >
              <div className="flex items-center gap-3">
                <input
                  type="time"
                  value={notifSettings?.daily_report_time || '08:00'}
                  onChange={(e) => handleNotifSettingChange('daily_report_time', e.target.value)}
                  disabled={!notifSettings?.smtp_configured || savingNotifSettings}
                  className="px-2 py-1 bg-background border rounded text-sm disabled:opacity-50"
                />
                <ToggleSwitch
                  checked={notifSettings?.daily_report_enabled || false}
                  onChange={(v) => handleNotifSettingChange('daily_report_enabled', v)}
                  disabled={!notifSettings?.smtp_configured || savingNotifSettings}
                />
              </div>
            </SettingRow>

            {/* Weekly Report */}
            <SettingRow
              label="Weekly Report"
              description="Send weekly summary"
              icon={<Calendar className="w-4 h-4" />}
            >
              <div className="flex items-center gap-3">
                <select
                  value={notifSettings?.weekly_report_day ?? 1}
                  onChange={(e) => handleNotifSettingChange('weekly_report_day', parseInt(e.target.value))}
                  disabled={!notifSettings?.smtp_configured || savingNotifSettings}
                  className="px-2 py-1 bg-background border rounded text-sm disabled:opacity-50"
                >
                  <option value={0}>Sunday</option>
                  <option value={1}>Monday</option>
                  <option value={2}>Tuesday</option>
                  <option value={3}>Wednesday</option>
                  <option value={4}>Thursday</option>
                  <option value={5}>Friday</option>
                  <option value={6}>Saturday</option>
                </select>
                <input
                  type="time"
                  value={notifSettings?.weekly_report_time || '08:00'}
                  onChange={(e) => handleNotifSettingChange('weekly_report_time', e.target.value)}
                  disabled={!notifSettings?.smtp_configured || savingNotifSettings}
                  className="px-2 py-1 bg-background border rounded text-sm disabled:opacity-50"
                />
                <ToggleSwitch
                  checked={notifSettings?.weekly_report_enabled || false}
                  onChange={(v) => handleNotifSettingChange('weekly_report_enabled', v)}
                  disabled={!notifSettings?.smtp_configured || savingNotifSettings}
                />
              </div>
            </SettingRow>

            {/* Monthly Report */}
            <SettingRow
              label="Monthly Report"
              description="Send monthly summary"
              icon={<Calendar className="w-4 h-4" />}
            >
              <div className="flex items-center gap-3">
                <select
                  value={notifSettings?.monthly_report_day ?? 1}
                  onChange={(e) => handleNotifSettingChange('monthly_report_day', parseInt(e.target.value))}
                  disabled={!notifSettings?.smtp_configured || savingNotifSettings}
                  className="px-2 py-1 bg-background border rounded text-sm disabled:opacity-50"
                >
                  {Array.from({ length: 28 }, (_, i) => i + 1).map(day => (
                    <option key={day} value={day}>Day {day}</option>
                  ))}
                </select>
                <input
                  type="time"
                  value={notifSettings?.monthly_report_time || '08:00'}
                  onChange={(e) => handleNotifSettingChange('monthly_report_time', e.target.value)}
                  disabled={!notifSettings?.smtp_configured || savingNotifSettings}
                  className="px-2 py-1 bg-background border rounded text-sm disabled:opacity-50"
                />
                <ToggleSwitch
                  checked={notifSettings?.monthly_report_enabled || false}
                  onChange={(v) => handleNotifSettingChange('monthly_report_enabled', v)}
                  disabled={!notifSettings?.smtp_configured || savingNotifSettings}
                />
              </div>
            </SettingRow>

            {/* Real-time Alerts Section */}
            <div className="px-6 py-3 bg-muted/30 border-t border-b">
              <p className="text-sm font-medium text-muted-foreground">Real-time Alerts</p>
            </div>

            {/* WAF Detection */}
            <SettingRow
              label="WAF Detection"
              description="Alert on WAF threat detection events"
              icon={<Shield className="w-4 h-4" />}
            >
              <ToggleSwitch
                checked={notifSettings?.waf_detection_enabled || false}
                onChange={(v) => handleNotifSettingChange('waf_detection_enabled', v)}
                disabled={!notifSettings?.smtp_configured || savingNotifSettings}
              />
            </SettingRow>

            {/* WAF Blocked */}
            <SettingRow
              label="WAF Blocked"
              description="Alert when requests are blocked by WAF"
              icon={<Shield className="w-4 h-4" />}
            >
              <ToggleSwitch
                checked={notifSettings?.waf_blocked_enabled || false}
                onChange={(v) => handleNotifSettingChange('waf_blocked_enabled', v)}
                disabled={!notifSettings?.smtp_configured || savingNotifSettings}
              />
            </SettingRow>

            {/* New Bans */}
            <SettingRow
              label="New IP Bans"
              description="Alert when new IPs are banned"
              icon={<AlertTriangle className="w-4 h-4" />}
            >
              <ToggleSwitch
                checked={notifSettings?.new_ban_enabled || false}
                onChange={(v) => handleNotifSettingChange('new_ban_enabled', v)}
                disabled={!notifSettings?.smtp_configured || savingNotifSettings}
              />
            </SettingRow>

            {/* Critical Alerts */}
            <SettingRow
              label="Critical Alerts"
              description="Alert on critical security events"
              icon={<AlertTriangle className="w-4 h-4" />}
            >
              <ToggleSwitch
                checked={notifSettings?.critical_alert_enabled || false}
                onChange={(v) => handleNotifSettingChange('critical_alert_enabled', v)}
                disabled={!notifSettings?.smtp_configured || savingNotifSettings}
              />
            </SettingRow>

            {/* Severity Threshold */}
            <SettingRow
              label="Minimum Severity"
              description="Only send alerts at or above this level"
              icon={<Zap className="w-4 h-4" />}
            >
              <ToggleGroup
                value={notifSettings?.min_severity_level || 'critical'}
                onChange={(v) => handleNotifSettingChange('min_severity_level', v)}
                options={[
                  { value: 'critical', label: 'Critical' },
                  { value: 'high', label: 'High' },
                  { value: 'medium', label: 'Medium' },
                  { value: 'low', label: 'Low' },
                ]}
                disabled={!notifSettings?.smtp_configured || savingNotifSettings}
              />
            </SettingRow>
          </>
        )}
      </SettingsSection>

      {/* Security Settings */}
      <SettingsSection
        title="Security & Privacy"
        description="Security and data display options"
        icon={<Shield className="w-5 h-5" />}
        isCollapsed={collapsedSections['security']}
        onToggle={() => toggleSection('security')}
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

        {/* Hide System IPs */}
        <SettingRow
          label="Hide system IPs"
          description="Filter out legitimate IPs from logs (DNS, CDN, health checks)"
          icon={<Shield className="w-4 h-4" />}
        >
          <ToggleSwitch
            checked={settings.hideSystemIPs}
            onChange={(v) => handleChange('hideSystemIPs', v)}
          />
        </SettingRow>
      </SettingsSection>

      {/* License Status Section */}
      <SettingsSection
        title="License"
        description="License status and subscription information"
        icon={<Key className="w-5 h-5" />}
        isCollapsed={collapsedSections['license']}
        onToggle={() => toggleSection('license')}
      >
        {loadingLicense ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : licenseStatus ? (
          <>
            {/* License Status */}
            <div className="flex items-center justify-between px-6 py-4">
              <div className="flex items-center gap-3">
                <div className="text-muted-foreground">
                  <Shield className="w-4 h-4" />
                </div>
                <div>
                  <p className="font-medium">Status</p>
                  <p className="text-sm text-muted-foreground">Current license status</p>
                </div>
              </div>
              <div
                className={cn(
                  'flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium',
                  licenseStatus.licensed
                    ? licenseStatus.grace_mode
                      ? 'bg-yellow-500/10 text-yellow-500'
                      : 'bg-green-500/10 text-green-500'
                    : 'bg-red-500/10 text-red-500'
                )}
              >
                {licenseStatus.licensed ? (
                  licenseStatus.grace_mode ? (
                    <>
                      <AlertTriangle className="w-4 h-4" />
                      Grace Mode
                    </>
                  ) : (
                    <>
                      <CheckCircle className="w-4 h-4" />
                      Active
                    </>
                  )
                ) : (
                  <>
                    <XCircle className="w-4 h-4" />
                    {licenseStatus.status === 'not_activated' ? 'Not Activated' : 'Invalid'}
                  </>
                )}
              </div>
            </div>

            {/* Customer Name */}
            {licenseStatus.customer_name && (
              <div className="flex items-center justify-between px-6 py-4">
                <div className="flex items-center gap-3">
                  <div className="text-muted-foreground">
                    <Users className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="font-medium">Customer</p>
                    <p className="text-sm text-muted-foreground">Licensed organization</p>
                  </div>
                </div>
                <p className="font-medium">{licenseStatus.customer_name}</p>
              </div>
            )}

            {/* Expiration Date */}
            {licenseStatus.expires_at && (
              <div className="flex items-center justify-between px-6 py-4">
                <div className="flex items-center gap-3">
                  <div className="text-muted-foreground">
                    <Calendar className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="font-medium">Expiration</p>
                    <p className="text-sm text-muted-foreground">License valid until</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="font-medium">
                    {new Date(licenseStatus.expires_at).toLocaleDateString()}
                  </p>
                  {licenseStatus.days_remaining !== undefined && licenseStatus.days_remaining > 0 && (
                    <p className={cn(
                      "text-sm",
                      licenseStatus.days_remaining > 30
                        ? "text-muted-foreground"
                        : licenseStatus.days_remaining > 7
                          ? "text-yellow-500"
                          : "text-red-500"
                    )}>
                      {licenseStatus.days_remaining} days remaining
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Features */}
            {licenseStatus.features && licenseStatus.features.length > 0 && (
              <div className="flex items-center justify-between px-6 py-4">
                <div className="flex items-center gap-3">
                  <div className="text-muted-foreground">
                    <Zap className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="font-medium">Features</p>
                    <p className="text-sm text-muted-foreground">Enabled capabilities</p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2 justify-end">
                  {licenseStatus.features.map((feature) => (
                    <span
                      key={feature}
                      className="px-2 py-1 bg-primary/10 text-primary rounded text-xs font-medium"
                    >
                      {feature}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Hardware ID (for support) */}
            {licenseStatus.hardware_id && (
              <div className="flex items-center justify-between px-6 py-4">
                <div className="flex items-center gap-3">
                  <div className="text-muted-foreground">
                    <Server className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="font-medium">Hardware ID</p>
                    <p className="text-sm text-muted-foreground">Machine identifier (for support)</p>
                  </div>
                </div>
                <p className="font-mono text-xs text-muted-foreground">
                  {licenseStatus.hardware_id.substring(0, 16)}...
                </p>
              </div>
            )}
          </>
        ) : (
          <div className="px-6 py-8 text-center text-muted-foreground">
            <p>Unable to retrieve license information</p>
          </div>
        )}
      </SettingsSection>

      {/* Integrations Status */}
      <SettingsSection
        title="Integrations"
        description={isAdmin ? "Status and configuration of external services" : "Admin access required to modify integrations"}
        icon={<Plug className="w-5 h-5" />}
        disabled={!isAdmin}
        isCollapsed={collapsedSections['integrations']}
        onToggle={() => toggleSection('integrations')}
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
              onEdit={isAdmin ? () => handleEditPlugin('sophos_syslog') : undefined}
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
              onEdit={isAdmin ? () => handleEditPlugin('sophos_ssh') : undefined}
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
              onEdit={isAdmin ? () => handleEditPlugin('sophos_api') : undefined}
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
                  onEdit={isAdmin && pluginId ? () => handleEditPlugin(pluginId) : undefined}
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
                onClick={handleClosePluginModal}
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
                    disabled={savingPlugin}
                  />
                </div>
              ))}

              {/* Result feedback */}
              {saveResult && (
                <div className={cn(
                  'rounded-lg p-3 border',
                  saveResult.success
                    ? 'bg-green-500/10 border-green-500/20'
                    : 'bg-red-500/10 border-red-500/20'
                )}>
                  <div className="flex items-start gap-2">
                    {saveResult.success ? (
                      <CheckCircle className="w-4 h-4 text-green-500 mt-0.5" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-500 mt-0.5" />
                    )}
                    <div className={cn(
                      'text-sm',
                      saveResult.success ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'
                    )}>
                      <p className="font-medium">{saveResult.success ? 'Connected' : 'Connection Failed'}</p>
                      <p className="text-xs mt-1 opacity-80">{saveResult.message}</p>
                    </div>
                  </div>
                </div>
              )}

              {!saveResult && (
                <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3">
                  <div className="flex items-start gap-2">
                    <Server className="w-4 h-4 text-blue-500 mt-0.5" />
                    <div className="text-sm text-blue-600 dark:text-blue-400">
                      <p className="font-medium">Test & Apply Configuration</p>
                      <p className="text-xs mt-1 opacity-80">
                        The connection will be tested and configuration saved. Service will reload automatically.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={handleClosePluginModal}
                  disabled={savingPlugin}
                  className="flex-1 px-4 py-2 bg-muted rounded-lg hover:bg-muted/80 transition-colors disabled:opacity-50"
                >
                  {saveResult ? 'Close' : 'Cancel'}
                </button>
                {!saveResult?.success && (
                  <button
                    onClick={handleSavePlugin}
                    disabled={savingPlugin}
                    className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50"
                  >
                    {savingPlugin ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <RefreshCw className="w-4 h-4" />
                    )}
                    {savingPlugin ? 'Testing...' : 'Save & Restart'}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Version Info */}
      <div className="text-center text-sm text-muted-foreground py-4 border-t border-border">
        <p>VIGILANCE X v3.3.100</p>
        <p className="mt-1">Security Operations Center - Licensed Edition</p>
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
  disabled = false,
  isCollapsed = false,
  onToggle,
}: {
  title: string
  description: string
  icon: React.ReactNode
  children: React.ReactNode
  disabled?: boolean
  isCollapsed?: boolean
  onToggle?: () => void
}) {
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
