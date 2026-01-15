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
  MapPin,
  Plus,
  HardDrive,
  Trash2,
  Database,
  Brain,
  Sparkles,
} from 'lucide-react'
import { useSettings, type AppSettings } from '@/contexts/SettingsContext'
import { useAuth } from '@/contexts/AuthContext'
import { threatsApi, bansApi, modsecApi, statusApi, configApi, licenseApi, notificationsApi, geozoneApi, retentionApi, integrationsApi, crowdsecBlocklistApi, type LicenseStatus, type NotificationSettings, type GeoZoneConfig, type RetentionSettings, type StorageStats, type APIProviderStatus, type CrowdSecBlocklistConfig } from '@/lib/api'
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
    name: 'CrowdSec CTI',
    type: 'threat_intel',
    fields: [
      { key: 'CROWDSEC_API_KEY', label: 'CTI API Key', type: 'password', value: '', placeholder: 'Enter CrowdSec CTI API key...' },
    ],
  },
  {
    id: 'crowdsec_blocklist',
    name: 'CrowdSec Blocklist',
    type: 'threat_intel',
    fields: [
      { key: 'CROWDSEC_BLOCKLIST_API_KEY', label: 'Service API Key', type: 'password', value: '', placeholder: 'Enter CrowdSec Service API key (Blocklist scope)...' },
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
      { key: 'SMTP_SECURITY', label: 'Security', type: 'text', value: 'starttls', placeholder: 'starttls, ssl, or none' },
      { key: 'SMTP_FROM_EMAIL', label: 'From Email', type: 'text', value: '', placeholder: 'noreply@company.com' },
      { key: 'SMTP_USERNAME', label: 'Username', type: 'text', value: '', placeholder: 'user@company.com' },
      { key: 'SMTP_PASSWORD', label: 'Password', type: 'password', value: '', placeholder: '********' },
      { key: 'SMTP_RECIPIENTS', label: 'Recipients', type: 'text', value: '', placeholder: 'admin@company.com, soc@company.com' },
    ],
  },
  {
    id: 'neural_sync',
    name: 'VGX Neural-Sync',
    type: 'neural_sync' as any,
    fields: [
      { key: 'NEURAL_SYNC_SERVER_URL', label: 'VigilanceKey Server URL', type: 'text', value: '', placeholder: 'https://vgxkey.vigilancex.lu' },
      { key: 'NEURAL_SYNC_LICENSE_KEY', label: 'License Key', type: 'password', value: '', placeholder: 'VX3-XXXX-XXXX-XXXX-XXXX' },
      { key: 'NEURAL_SYNC_HARDWARE_ID', label: 'Hardware ID', type: 'text', value: '', placeholder: 'Auto-filled from license' },
    ],
  },
]

export function Settings() {
  const { settings, updateSettings, resetSettings } = useSettings()
  const { isAdmin } = useAuth()
  const [integrations, setIntegrations] = useState<IntegrationStatus | null>(null)
  const [loadingIntegrations, setLoadingIntegrations] = useState(true)
  const [saved, setSaved] = useState(false)

  // v3.53: API Provider status with quotas
  const [apiProviders, setApiProviders] = useState<APIProviderStatus[]>([])

  // v3.53: CrowdSec Blocklist config (separate from CTI)
  const [crowdsecBlocklistConfig, setCrowdsecBlocklistConfig] = useState<CrowdSecBlocklistConfig | null>(null)

  // License status state
  const [licenseStatus, setLicenseStatus] = useState<LicenseStatus | null>(null)
  const [loadingLicense, setLoadingLicense] = useState(true)

  // Email notification settings state
  const [notifSettings, setNotifSettings] = useState<NotificationSettings | null>(null)
  const [loadingNotifSettings, setLoadingNotifSettings] = useState(true)
  const [savingNotifSettings, setSavingNotifSettings] = useState(false)
  const [sendingTestEmail, setSendingTestEmail] = useState(false)
  const [testEmailResult, setTestEmailResult] = useState<{ success: boolean; message: string } | null>(null)

  // GeoZone settings state (D2B v2)
  const [geozoneConfig, setGeozoneConfig] = useState<GeoZoneConfig | null>(null)
  const [loadingGeozone, setLoadingGeozone] = useState(true)
  const [savingGeozone, setSavingGeozone] = useState(false)
  const [newAuthorizedCountry, setNewAuthorizedCountry] = useState('')
  const [newHostileCountry, setNewHostileCountry] = useState('')

  // Retention settings state (v3.52)
  const [retentionSettings, setRetentionSettings] = useState<RetentionSettings | null>(null)
  const [storageStats, setStorageStats] = useState<StorageStats | null>(null)
  const [loadingRetention, setLoadingRetention] = useState(true)
  const [savingRetention, setSavingRetention] = useState(false)
  const [runningCleanup, setRunningCleanup] = useState(false)

  // v3.53.105: Local input states to prevent cursor jumping
  const [recipientsInput, setRecipientsInput] = useState('')
  const [retentionInputs, setRetentionInputs] = useState<Record<string, string>>({})

  // Collapsible sections state - all collapsed by default
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({
    display: true,
    dashboard: true,
    notifications: true,
    email_notifications: true,
    security: true,
    geozone: true,
    retention: true,
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
    const sections = ['display', 'dashboard', 'notifications', 'email_notifications', 'security', 'geozone', 'license', 'integrations']
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
  const [savedConfigs, setSavedConfigs] = useState<Record<string, Record<string, string>>>({})

  // Fetch saved configs on mount
  useEffect(() => {
    async function fetchSavedConfigs() {
      try {
        const configs = await configApi.get()
        setSavedConfigs(configs || {})
      } catch (err) {
        console.error('Failed to fetch saved configs:', err)
      }
    }
    fetchSavedConfigs()
  }, [])

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

  // v3.53: Fetch API providers status with quotas
  useEffect(() => {
    async function fetchApiProviders() {
      try {
        const response = await integrationsApi.getProviders()
        setApiProviders(response.providers || [])
      } catch (err) {
        console.error('Failed to fetch API providers:', err)
      }
    }
    fetchApiProviders()
  }, [])

  // v3.53: Fetch CrowdSec Blocklist config (separate integration)
  useEffect(() => {
    async function fetchCrowdsecBlocklist() {
      try {
        const config = await crowdsecBlocklistApi.getConfig()
        setCrowdsecBlocklistConfig(config)
      } catch (err) {
        console.error('Failed to fetch CrowdSec Blocklist config:', err)
      }
    }
    fetchCrowdsecBlocklist()
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

  // Fetch GeoZone config (D2B v2)
  useEffect(() => {
    async function fetchGeozoneConfig() {
      setLoadingGeozone(true)
      try {
        const config = await geozoneApi.getConfig()
        setGeozoneConfig(config)
      } catch (err) {
        console.error('Failed to fetch GeoZone config:', err)
      } finally {
        setLoadingGeozone(false)
      }
    }

    fetchGeozoneConfig()
  }, [])

  // Fetch Retention settings (v3.52)
  useEffect(() => {
    async function fetchRetentionSettings() {
      setLoadingRetention(true)
      try {
        const [settings, storage] = await Promise.all([
          retentionApi.getSettings(),
          retentionApi.getStorageStats()
        ])
        setRetentionSettings(settings)
        setStorageStats(storage)
      } catch (err) {
        console.error('Failed to fetch retention settings:', err)
      } finally {
        setLoadingRetention(false)
      }
    }

    fetchRetentionSettings()
  }, [])

  // v3.53.105: Sync local inputs with notification settings
  useEffect(() => {
    if (notifSettings?.report_recipients) {
      setRecipientsInput(notifSettings.report_recipients.join(', '))
    }
  }, [notifSettings?.report_recipients])

  // v3.53.105: Sync local inputs with retention settings
  useEffect(() => {
    if (retentionSettings) {
      setRetentionInputs({
        events_retention_days: String(retentionSettings.events_retention_days || 30),
        modsec_logs_retention_days: String(retentionSettings.modsec_logs_retention_days || 30),
        vpn_events_retention_days: String(retentionSettings.vpn_events_retention_days || 30),
        atp_events_retention_days: String(retentionSettings.atp_events_retention_days || 90),
        antivirus_events_retention_days: String(retentionSettings.antivirus_events_retention_days || 90),
        ban_history_retention_days: String(retentionSettings.ban_history_retention_days || 365),
        audit_log_retention_days: String(retentionSettings.audit_log_retention_days || 365),
      })
    }
  }, [retentionSettings])

  // Handle retention settings change (for toggles and selects - immediate save)
  const handleRetentionChange = async <K extends keyof RetentionSettings>(key: K, value: RetentionSettings[K]) => {
    if (!retentionSettings) return

    const newSettings = { ...retentionSettings, [key]: value }
    setRetentionSettings(newSettings)

    setSavingRetention(true)
    try {
      await retentionApi.updateSettings({ [key]: value })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      console.error('Failed to update retention setting:', err)
      setRetentionSettings(retentionSettings)
    } finally {
      setSavingRetention(false)
    }
  }

  // v3.53.105: Handle local retention input change (no API call)
  const handleRetentionInputChange = (key: string, value: string) => {
    setRetentionInputs(prev => ({ ...prev, [key]: value }))
  }

  // v3.53.105: Handle retention input blur - save to API
  const handleRetentionInputBlur = async (key: keyof RetentionSettings) => {
    if (!retentionSettings) return
    const value = parseInt(retentionInputs[key] || '0') || 0
    if (value === retentionSettings[key]) return // No change
    await handleRetentionChange(key, value as RetentionSettings[typeof key])
  }

  // v3.53.105: Handle recipients input blur - save to API
  const handleRecipientsBlur = async () => {
    const emails = recipientsInput
      .split(',')
      .map(email => email.trim())
      .filter(email => email.length > 0)

    // Check if changed
    const currentEmails = notifSettings?.report_recipients || []
    if (JSON.stringify(emails) === JSON.stringify(currentEmails)) return

    await handleNotifSettingChange('report_recipients', emails)
  }

  // Handle manual cleanup
  const handleRunCleanup = async () => {
    setRunningCleanup(true)
    try {
      const result = await retentionApi.runCleanup()
      if (result.success) {
        setSaved(true)
        setTimeout(() => setSaved(false), 2000)
        // Refresh storage stats after cleanup
        const storage = await retentionApi.getStorageStats()
        setStorageStats(storage)
      }
    } catch (err) {
      console.error('Failed to run cleanup:', err)
    } finally {
      setRunningCleanup(false)
    }
  }

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

  // Handle GeoZone config update
  const handleGeozoneChange = async <K extends keyof GeoZoneConfig>(key: K, value: GeoZoneConfig[K]) => {
    if (!geozoneConfig) return

    const newConfig = { ...geozoneConfig, [key]: value }
    setGeozoneConfig(newConfig)

    setSavingGeozone(true)
    try {
      await geozoneApi.updateConfig({ [key]: value })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      console.error('Failed to update GeoZone config:', err)
      // Revert on error
      setGeozoneConfig(geozoneConfig)
    } finally {
      setSavingGeozone(false)
    }
  }

  // Handle adding authorized country
  const handleAddAuthorizedCountry = async () => {
    if (!newAuthorizedCountry || newAuthorizedCountry.length !== 2) return

    setSavingGeozone(true)
    try {
      await geozoneApi.addAuthorizedCountry(newAuthorizedCountry.toUpperCase())
      // Refresh config
      const config = await geozoneApi.getConfig()
      setGeozoneConfig(config)
      setNewAuthorizedCountry('')
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      console.error('Failed to add authorized country:', err)
    } finally {
      setSavingGeozone(false)
    }
  }

  // Handle removing authorized country
  const handleRemoveAuthorizedCountry = async (country: string) => {
    setSavingGeozone(true)
    try {
      await geozoneApi.removeAuthorizedCountry(country)
      // Refresh config
      const config = await geozoneApi.getConfig()
      setGeozoneConfig(config)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      console.error('Failed to remove authorized country:', err)
    } finally {
      setSavingGeozone(false)
    }
  }

  // Handle adding hostile country
  const handleAddHostileCountry = async () => {
    if (!newHostileCountry || newHostileCountry.length !== 2) return

    setSavingGeozone(true)
    try {
      await geozoneApi.addHostileCountry(newHostileCountry.toUpperCase())
      // Refresh config
      const config = await geozoneApi.getConfig()
      setGeozoneConfig(config)
      setNewHostileCountry('')
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      console.error('Failed to add hostile country:', err)
    } finally {
      setSavingGeozone(false)
    }
  }

  // Plugin editor functions
  const handleEditPlugin = async (pluginId: string) => {
    const plugin = defaultPluginConfigs.find(p => p.id === pluginId)
    if (plugin) {
      // v3.53.105: Fetch configs BEFORE opening modal so disconnect button works
      try {
        // v3.53.105: Special case for CrowdSec Blocklist - stored in ClickHouse
        if (pluginId === 'crowdsec_blocklist') {
          const blConfig = await crowdsecBlocklistApi.getConfig()
          setCrowdsecBlocklistConfig(blConfig)
          const initialData: Record<string, string> = {}
          plugin.fields.forEach(field => {
            if (field.key === 'api_key' && blConfig.api_key) {
              initialData[field.key] = blConfig.api_key
            } else {
              initialData[field.key] = field.value
            }
          })
          setPluginFormData(initialData)
          setEditingPlugin(plugin)
          return
        }

        const freshConfigs = await configApi.get()
        setSavedConfigs(freshConfigs || {})
        const saved = (freshConfigs && freshConfigs[pluginId]) || {}
        const initialData: Record<string, string> = {}
        plugin.fields.forEach(field => {
          // Use saved value if exists, otherwise use default
          if (saved[field.key] !== undefined && saved[field.key] !== '') {
            initialData[field.key] = saved[field.key]
          } else {
            initialData[field.key] = field.value
          }
        })
        setPluginFormData(initialData)
        // Open modal AFTER configs are loaded
        setEditingPlugin(plugin)
      } catch (err) {
        console.error('Failed to fetch configs:', err)
        // Fallback to cached or default values
        const saved = savedConfigs[pluginId] || {}
        const initialData: Record<string, string> = {}
        plugin.fields.forEach(field => {
          if (saved[field.key] !== undefined && saved[field.key] !== '') {
            initialData[field.key] = saved[field.key]
          } else {
            initialData[field.key] = field.value
          }
        })
        setPluginFormData(initialData)
        // Open modal even on error
        setEditingPlugin(plugin)
      }
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
      // v3.53.105: Special case for CrowdSec Blocklist - stored in ClickHouse
      if (editingPlugin.id === 'crowdsec_blocklist') {
        const apiKey = pluginFormData['api_key'] || ''
        // Skip if masked (no change)
        if (apiKey.includes('****')) {
          setSaveResult({ success: true, message: 'No changes to save' })
          setTimeout(() => {
            setEditingPlugin(null)
            setSaveResult(null)
          }, 1500)
          return
        }
        // Update config with new API key and enable
        await crowdsecBlocklistApi.updateConfig({ api_key: apiKey, enabled: !!apiKey })
        // Test connection
        const testResult = await crowdsecBlocklistApi.testConnection()
        setSaveResult({
          success: testResult.success,
          message: testResult.message,
        })
        // Refresh config
        const newConfig = await crowdsecBlocklistApi.getConfig()
        setCrowdsecBlocklistConfig(newConfig)

        if (testResult.success) {
          setTimeout(() => {
            setEditingPlugin(null)
            setSaveResult(null)
            window.location.reload()
          }, 2000)
        }
        return
      }

      // Filter out masked password fields (containing ****)
      // Only send password if user entered a new value
      const dataToSave: Record<string, string> = {}

      editingPlugin.fields.forEach(field => {
        const value = pluginFormData[field.key] || ''
        // If it's a password field and contains ****, skip it - backend preserves existing
        if (field.type === 'password' && value.includes('****')) {
          // Skip masked passwords entirely - backend preserves existing
        } else {
          dataToSave[field.key] = value
        }
      })

      const result = await configApi.save(editingPlugin.id, dataToSave)
      setSaveResult({
        success: result.test.success,
        message: result.message,
      })
      // Refresh saved configs
      const newConfigs = await configApi.get()
      setSavedConfigs(newConfigs || {})

      // Keep modal open to show result, auto-close after 2s on success
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
        message: err.response?.data?.details || err.response?.data?.error || 'Failed to save configuration',
      })
    } finally {
      setSavingPlugin(false)
    }
  }

  const handleClosePluginModal = () => {
    setEditingPlugin(null)
    setSaveResult(null)
  }

  // v3.53.104 - Disconnect/clear plugin configuration
  const [disconnecting, setDisconnecting] = useState(false)

  const handleDisconnectPlugin = async () => {
    if (!editingPlugin) return
    setDisconnecting(true)
    try {
      // v3.53.105: Special case for CrowdSec Blocklist - stored in ClickHouse
      if (editingPlugin.id === 'crowdsec_blocklist') {
        await crowdsecBlocklistApi.updateConfig({ api_key: '', enabled: false })
        // Refresh CrowdSec Blocklist config
        const newConfig = await crowdsecBlocklistApi.getConfig()
        setCrowdsecBlocklistConfig(newConfig)
      } else {
        await configApi.clear(editingPlugin.id)
        // Refresh saved configs
        const newConfigs = await configApi.get()
        setSavedConfigs(newConfigs || {})
      }
      setSaveResult({
        success: true,
        message: 'Configuration cleared successfully. Service will reload.',
      })
      setTimeout(() => {
        setEditingPlugin(null)
        setSaveResult(null)
        window.location.reload()
      }, 1500)
    } catch (err: any) {
      setSaveResult({
        success: false,
        message: err.response?.data?.error || 'Failed to clear configuration',
      })
    } finally {
      setDisconnecting(false)
    }
  }

  // Check if plugin is currently configured (has any saved values)
  const isPluginConfigured = (pluginId: string): boolean => {
    // v3.53.105: Special case for CrowdSec Blocklist - config stored in ClickHouse, not integrations.json
    if (pluginId === 'crowdsec_blocklist') {
      return !!crowdsecBlocklistConfig?.api_key
    }

    const config = savedConfigs[pluginId]
    if (!config) return false
    // Return true if any field has a non-empty value (masked or real)
    return Object.values(config).some(v => v && v.trim() !== '')
  }

  // Find plugin by provider name
  const findPluginByName = (name: string): string | null => {
    const nameMap: Record<string, string> = {
      'AbuseIPDB': 'abuseipdb',
      'VirusTotal': 'virustotal',
      'AlienVault OTX': 'alienvault',
      'GreyNoise': 'greynoise',
      'CrowdSec': 'crowdsec', // v2.9.6 - CTI API
      'CrowdSec CTI': 'crowdsec', // v3.53 - alias
      'CrowdSec Blocklist': 'crowdsec_blocklist', // v3.53 - Blocklist API
      'CriminalIP': 'criminalip', // No space - API returns CriminalIP
      'Criminal IP': 'criminalip', // Legacy alias
      'Pulsedive': 'pulsedive',
      'IPSum': null as unknown as string, // No API key needed
      'ThreatFox': null as unknown as string, // No API key needed
      'URLhaus': null as unknown as string, // No API key needed
      'Shodan InternetDB': null as unknown as string, // No API key needed
    }
    return nameMap[name] || null
  }

  // v3.53: Map provider display name to API provider_id
  const getApiProviderId = (name: string): string | null => {
    const idMap: Record<string, string> = {
      'AbuseIPDB': 'abuseipdb',
      'VirusTotal': 'virustotal',
      'AlienVault OTX': 'otx',
      'GreyNoise': 'greynoise',
      'CrowdSec': 'crowdsec_cti',
      'CrowdSec CTI': 'crowdsec_cti',
      'CrowdSec Blocklist': 'crowdsec_blocklist',
      'CriminalIP': 'criminalip', // No space - API returns CriminalIP
      'Criminal IP': 'criminalip', // Legacy alias
      'Pulsedive': 'pulsedive',
      'IPSum': 'ipsum',
      'ThreatFox': 'threatfox',
      'URLhaus': 'urlhaus',
      'Shodan InternetDB': 'shodan_internetdb',
    }
    return idMap[name] || null
  }

  // v3.53: Get API provider status by provider_id
  const getApiProviderStatus = (name: string): APIProviderStatus | undefined => {
    const providerId = getApiProviderId(name)
    if (!providerId) return undefined
    return apiProviders.find(p => p.config.provider_id === providerId)
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

        {/* Timezone */}
        <SettingRow
          label="Timezone"
          description="System timezone for dates and times"
          icon={<Globe className="w-4 h-4" />}
        >
          <select
            value={settings.timezone}
            onChange={(e) => handleChange('timezone', e.target.value)}
            className="px-3 py-2 bg-muted border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary text-sm min-w-[200px]"
          >
            <option value="Europe/Paris">Europe/Paris (CET)</option>
            <option value="Europe/London">Europe/London (GMT)</option>
            <option value="Europe/Berlin">Europe/Berlin (CET)</option>
            <option value="Europe/Luxembourg">Europe/Luxembourg (CET)</option>
            <option value="Europe/Brussels">Europe/Brussels (CET)</option>
            <option value="America/New_York">America/New_York (EST)</option>
            <option value="America/Los_Angeles">America/Los_Angeles (PST)</option>
            <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
            <option value="UTC">UTC</option>
          </select>
        </SettingRow>

        {/* Dashboard Clock */}
        <SettingRow
          label="Show clock on dashboard"
          description="Display current time in dashboard header"
          icon={<Clock className="w-4 h-4" />}
        >
          <ToggleSwitch
            checked={settings.showDashboardClock}
            onChange={(v) => handleChange('showDashboardClock', v)}
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

            {/* Report Recipients */}
            <SettingRow
              label="Report Recipients"
              description="Email addresses to receive scheduled reports (comma-separated)"
              icon={<Mail className="w-4 h-4" />}
            >
              <div className="flex items-center gap-2 w-full max-w-md">
                <input
                  type="text"
                  value={recipientsInput}
                  onChange={(e) => setRecipientsInput(e.target.value)}
                  onBlur={handleRecipientsBlur}
                  placeholder="admin@company.com, security@company.com"
                  disabled={!notifSettings?.smtp_configured || savingNotifSettings}
                  className="flex-1 px-3 py-2 bg-background border rounded-lg text-sm disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-primary"
                />
              </div>
            </SettingRow>

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

      {/* GeoZone Settings (D2B v2) */}
      <SettingsSection
        title="GeoZone (D2B v2)"
        description="Geographic zone classification for automatic ban decisions"
        icon={<MapPin className="w-5 h-5" />}
        isCollapsed={collapsedSections['geozone']}
        onToggle={() => toggleSection('geozone')}
      >
        {loadingGeozone ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <>
            {/* Enable GeoZone */}
            <SettingRow
              label="Enable GeoZone"
              description="Activate geographic zone-based ban decisions"
              icon={<MapPin className="w-4 h-4" />}
            >
              <ToggleSwitch
                checked={geozoneConfig?.enabled || false}
                onChange={(v) => handleGeozoneChange('enabled', v)}
                disabled={savingGeozone}
              />
            </SettingRow>

            {/* Default Policy */}
            <SettingRow
              label="Default Policy"
              description="How to treat countries not in authorized/hostile lists"
              icon={<Globe className="w-4 h-4" />}
            >
              <ToggleGroup
                value={geozoneConfig?.default_policy || 'neutral'}
                onChange={(v) => handleGeozoneChange('default_policy', v as 'authorized' | 'hostile' | 'neutral')}
                options={[
                  { value: 'authorized', label: 'Trusted' },
                  { value: 'neutral', label: 'Neutral' },
                  { value: 'hostile', label: 'Hostile' },
                ]}
                disabled={savingGeozone}
              />
            </SettingRow>

            {/* WAF Threshold - Hostile Zone */}
            <SettingRow
              label="WAF Threshold (Hostile)"
              description="WAF events before auto-ban for hostile zone IPs"
              icon={<Zap className="w-4 h-4" />}
            >
              <ToggleGroup
                value={String(geozoneConfig?.waf_threshold_hzone || 1)}
                onChange={(v) => handleGeozoneChange('waf_threshold_hzone', Number(v))}
                options={[
                  { value: '1', label: '1' },
                  { value: '2', label: '2' },
                  { value: '3', label: '3' },
                  { value: '5', label: '5' },
                ]}
                disabled={savingGeozone}
              />
            </SettingRow>

            {/* WAF Threshold - Authorized Zone */}
            <SettingRow
              label="WAF Threshold (Authorized)"
              description="WAF events before TI check for authorized zone IPs"
              icon={<Zap className="w-4 h-4" />}
            >
              <ToggleGroup
                value={String(geozoneConfig?.waf_threshold_zone || 3)}
                onChange={(v) => handleGeozoneChange('waf_threshold_zone', Number(v))}
                options={[
                  { value: '3', label: '3' },
                  { value: '5', label: '5' },
                  { value: '10', label: '10' },
                  { value: '15', label: '15' },
                ]}
                disabled={savingGeozone}
              />
            </SettingRow>

            {/* Threat Score Threshold */}
            <SettingRow
              label="Threat Score Threshold"
              description="Minimum TI score to auto-ban (0-100)"
              icon={<AlertTriangle className="w-4 h-4" />}
            >
              <ToggleGroup
                value={String(geozoneConfig?.threat_score_threshold || 50)}
                onChange={(v) => handleGeozoneChange('threat_score_threshold', Number(v))}
                options={[
                  { value: '30', label: '30' },
                  { value: '50', label: '50' },
                  { value: '70', label: '70' },
                  { value: '90', label: '90' },
                ]}
                disabled={savingGeozone}
              />
            </SettingRow>

            {/* Authorized Countries Section */}
            <div className="px-6 py-3 bg-muted/30 border-t border-b">
              <p className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                Authorized Countries (TI check before ban)
              </p>
            </div>

            <div className="px-6 py-4">
              <div className="flex flex-wrap gap-2 mb-3">
                {(geozoneConfig?.authorized_countries || []).map((country) => (
                  <span
                    key={country}
                    className="inline-flex items-center gap-1 px-2 py-1 bg-green-500/10 text-green-600 dark:text-green-400 rounded text-sm font-medium"
                  >
                    {country}
                    <button
                      onClick={() => handleRemoveAuthorizedCountry(country)}
                      disabled={savingGeozone}
                      className="ml-1 p-0.5 hover:bg-green-500/20 rounded disabled:opacity-50"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
                {(geozoneConfig?.authorized_countries || []).length === 0 && (
                  <span className="text-sm text-muted-foreground">No authorized countries configured</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={newAuthorizedCountry}
                  onChange={(e) => setNewAuthorizedCountry(e.target.value.toUpperCase().slice(0, 2))}
                  placeholder="CC"
                  maxLength={2}
                  disabled={savingGeozone}
                  className="w-16 px-2 py-1 bg-background border rounded text-sm uppercase disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-primary"
                />
                <button
                  onClick={handleAddAuthorizedCountry}
                  disabled={savingGeozone || newAuthorizedCountry.length !== 2}
                  className="flex items-center gap-1 px-3 py-1 bg-green-500/10 text-green-600 dark:text-green-400 rounded text-sm font-medium hover:bg-green-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Plus className="w-3 h-3" />
                  Add
                </button>
              </div>
            </div>

            {/* Hostile Countries Section */}
            <div className="px-6 py-3 bg-muted/30 border-t border-b">
              <p className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <XCircle className="w-4 h-4 text-red-500" />
                Hostile Countries (Immediate ban on first WAF event)
              </p>
            </div>

            <div className="px-6 py-4">
              <div className="flex flex-wrap gap-2 mb-3">
                {(geozoneConfig?.hostile_countries || []).map((country) => (
                  <span
                    key={country}
                    className="inline-flex items-center gap-1 px-2 py-1 bg-red-500/10 text-red-600 dark:text-red-400 rounded text-sm font-medium"
                  >
                    {country}
                    <button
                      onClick={async () => {
                        // Remove hostile country (use update config)
                        if (!geozoneConfig) return
                        const newHostile = geozoneConfig.hostile_countries.filter(c => c !== country)
                        handleGeozoneChange('hostile_countries', newHostile)
                      }}
                      disabled={savingGeozone}
                      className="ml-1 p-0.5 hover:bg-red-500/20 rounded disabled:opacity-50"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
                {(geozoneConfig?.hostile_countries || []).length === 0 && (
                  <span className="text-sm text-muted-foreground">No hostile countries configured</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={newHostileCountry}
                  onChange={(e) => setNewHostileCountry(e.target.value.toUpperCase().slice(0, 2))}
                  placeholder="CC"
                  maxLength={2}
                  disabled={savingGeozone}
                  className="w-16 px-2 py-1 bg-background border rounded text-sm uppercase disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-primary"
                />
                <button
                  onClick={handleAddHostileCountry}
                  disabled={savingGeozone || newHostileCountry.length !== 2}
                  className="flex items-center gap-1 px-3 py-1 bg-red-500/10 text-red-600 dark:text-red-400 rounded text-sm font-medium hover:bg-red-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Plus className="w-3 h-3" />
                  Add
                </button>
              </div>
            </div>
          </>
        )}
      </SettingsSection>

      {/* Log Retention Settings (v3.52) */}
      <SettingsSection
        title="Log Retention"
        description="Configure log retention periods and storage cleanup"
        icon={<Database className="w-5 h-5" />}
        isCollapsed={collapsedSections['retention']}
        onToggle={() => toggleSection('retention')}
      >
        {loadingRetention ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <>
            {/* Storage Usage */}
            {storageStats && (
              <div className="px-6 py-4 border-b border-border/50">
                <div className="flex items-center gap-3 mb-3">
                  <HardDrive className="w-4 h-4 text-muted-foreground" />
                  <span className="font-medium">Storage Usage</span>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Database Size</span>
                    <span>{(storageStats.used_bytes / (1024 * 1024)).toFixed(1)} MB</span>
                  </div>
                  {storageStats.total_bytes > 0 && (
                    <>
                      <div className="h-2 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full bg-blue-500 rounded-full"
                          style={{ width: `${Math.min(storageStats.used_percent, 100)}%` }}
                        />
                      </div>
                      <div className="flex justify-between text-xs text-muted-foreground">
                        <span>{storageStats.used_percent.toFixed(1)}% used</span>
                        <span>{(storageStats.available_bytes / (1024 * 1024 * 1024)).toFixed(1)} GB free</span>
                      </div>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* Enable Retention */}
            <SettingRow
              label="Enable Auto-Cleanup"
              description="Automatically delete old logs based on retention periods"
              icon={<Trash2 className="w-4 h-4" />}
            >
              <ToggleSwitch
                checked={retentionSettings?.retention_enabled || false}
                onChange={(v) => handleRetentionChange('retention_enabled', v)}
                disabled={savingRetention}
              />
            </SettingRow>

            {/* Main Events Retention */}
            <SettingRow
              label="Events Retention"
              description="Days to keep WAF/IPS/ATP events"
              icon={<Calendar className="w-4 h-4" />}
            >
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min="1"
                  max="365"
                  value={retentionInputs.events_retention_days || '30'}
                  onChange={(e) => handleRetentionInputChange('events_retention_days', e.target.value)}
                  onBlur={() => handleRetentionInputBlur('events_retention_days')}
                  className="w-20 px-2 py-1 text-center rounded border border-border bg-background"
                  disabled={savingRetention}
                />
                <span className="text-sm text-muted-foreground">days</span>
              </div>
            </SettingRow>

            {/* ModSec Logs Retention */}
            <SettingRow
              label="ModSec Logs"
              description="Days to keep ModSecurity detection logs"
              icon={<Shield className="w-4 h-4" />}
            >
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min="1"
                  max="365"
                  value={retentionInputs.modsec_logs_retention_days || '30'}
                  onChange={(e) => handleRetentionInputChange('modsec_logs_retention_days', e.target.value)}
                  onBlur={() => handleRetentionInputBlur('modsec_logs_retention_days')}
                  className="w-20 px-2 py-1 text-center rounded border border-border bg-background"
                  disabled={savingRetention}
                />
                <span className="text-sm text-muted-foreground">days</span>
              </div>
            </SettingRow>

            {/* VPN Events Retention */}
            <SettingRow
              label="VPN Events"
              description="Days to keep VPN session logs"
              icon={<Lock className="w-4 h-4" />}
            >
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min="1"
                  max="365"
                  value={retentionInputs.vpn_events_retention_days || '30'}
                  onChange={(e) => handleRetentionInputChange('vpn_events_retention_days', e.target.value)}
                  onBlur={() => handleRetentionInputBlur('vpn_events_retention_days')}
                  className="w-20 px-2 py-1 text-center rounded border border-border bg-background"
                  disabled={savingRetention}
                />
                <span className="text-sm text-muted-foreground">days</span>
              </div>
            </SettingRow>

            {/* Ban History Retention */}
            <SettingRow
              label="Ban History"
              description="Days to keep ban/unban audit trail"
              icon={<AlertTriangle className="w-4 h-4" />}
            >
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min="30"
                  max="3650"
                  value={retentionInputs.ban_history_retention_days || '365'}
                  onChange={(e) => handleRetentionInputChange('ban_history_retention_days', e.target.value)}
                  onBlur={() => handleRetentionInputBlur('ban_history_retention_days')}
                  className="w-20 px-2 py-1 text-center rounded border border-border bg-background"
                  disabled={savingRetention}
                />
                <span className="text-sm text-muted-foreground">days</span>
              </div>
            </SettingRow>

            {/* Cleanup Interval */}
            <SettingRow
              label="Cleanup Interval"
              description="How often to run automatic cleanup"
              icon={<Clock className="w-4 h-4" />}
            >
              <ToggleGroup
                value={String(retentionSettings?.cleanup_interval_hours || 6)}
                onChange={(v) => handleRetentionChange('cleanup_interval_hours', Number(v))}
                options={[
                  { value: '1', label: '1h' },
                  { value: '6', label: '6h' },
                  { value: '12', label: '12h' },
                  { value: '24', label: '24h' },
                ]}
                disabled={savingRetention}
              />
            </SettingRow>

            {/* Manual Cleanup Button */}
            <div className="px-6 py-4 border-t border-border/50">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Manual Cleanup</p>
                  <p className="text-sm text-muted-foreground">
                    Run cleanup now based on current retention settings
                  </p>
                </div>
                <button
                  onClick={handleRunCleanup}
                  disabled={runningCleanup}
                  className="flex items-center gap-2 px-4 py-2 bg-red-500/10 text-red-600 dark:text-red-400 rounded-lg font-medium hover:bg-red-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {runningCleanup ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Trash2 className="w-4 h-4" />
                  )}
                  {runningCleanup ? 'Cleaning...' : 'Run Cleanup'}
                </button>
              </div>
            </div>
          </>
        )}
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
            {/* Sophos Firewall Category */}
            <IntegrationCategory
              name="Sophos Firewall"
              icon={<Server className="w-4 h-4" />}
              colorClass="text-blue-500"
              defaultOpen={true}
            >
              <IntegrationRow
                name="Syslog Receiver"
                description={
                  integrations?.sophosSyslog.connected
                    ? `Receiving logs (~${integrations.sophosSyslog.eventsPerMinute}/min)`
                    : 'Not receiving logs'
                }
                connected={integrations?.sophosSyslog.connected || false}
                icon={<Server className="w-4 h-4" />}
                onEdit={isAdmin ? () => handleEditPlugin('sophos_syslog') : undefined}
              />
              <IntegrationRow
                name="SSH (ModSec Sync)"
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
              <IntegrationRow
                name="API (Ban/Unban)"
                description={
                  integrations?.sophosApi.connected
                    ? `${integrations.sophosApi.host} (${integrations.sophosApi.groupCount} bans in group)`
                    : 'API not configured'
                }
                connected={integrations?.sophosApi.connected || false}
                icon={<Plug className="w-4 h-4" />}
                onEdit={isAdmin ? () => handleEditPlugin('sophos_api') : undefined}
              />
            </IntegrationCategory>

            {/* CrowdSec Category */}
            <IntegrationCategory
              name="CrowdSec"
              icon={<Shield className="w-4 h-4" />}
              colorClass="text-purple-500"
            >
              {(() => {
                const crowdsecCTI = integrations?.threatProviders.find(p => p.name === 'CrowdSec')
                const ctiStatus = getApiProviderStatus('CrowdSec')
                return (
                  <>
                    {crowdsecCTI && (
                      <IntegrationRow
                        name="CrowdSec CTI"
                        description={crowdsecCTI.description}
                        connected={crowdsecCTI.configured}
                        icon={<Shield className="w-4 h-4" />}
                        onEdit={isAdmin ? () => handleEditPlugin('crowdsec') : undefined}
                        quotaUsed={ctiStatus?.quota_used}
                        quotaMax={ctiStatus?.quota_max}
                        hasError={ctiStatus?.has_error}
                        lastSuccess={ctiStatus?.config.last_success}
                        lastError={ctiStatus?.config.last_error_message}
                      />
                    )}
                    <IntegrationRow
                      name="CrowdSec Blocklist"
                      description={
                        crowdsecBlocklistConfig?.api_key
                          ? crowdsecBlocklistConfig.enabled
                            ? `Syncing to ${crowdsecBlocklistConfig.xgs_group_name}`
                            : 'Configured but disabled'
                          : 'Premium blocklist sync to XGS'
                      }
                      connected={!!crowdsecBlocklistConfig?.api_key}
                      icon={<Globe className="w-4 h-4" />}
                      onEdit={isAdmin ? () => handleEditPlugin('crowdsec_blocklist') : undefined}
                      syncInfo={crowdsecBlocklistConfig ? {
                        lastSync: crowdsecBlocklistConfig.last_sync,
                        totalIPs: crowdsecBlocklistConfig.total_ips
                      } : undefined}
                    />
                  </>
                )
              })()}
            </IntegrationCategory>

            {/* Threat Intelligence Category */}
            <IntegrationCategory
              name="Threat Intelligence"
              icon={<AlertTriangle className="w-4 h-4" />}
              colorClass="text-orange-500"
            >
              {integrations?.threatProviders
                .filter(p => p.name !== 'CrowdSec') // CrowdSec shown in its own category
                .map((provider) => {
                  const pluginId = findPluginByName(provider.name)
                  const apiStatus = getApiProviderStatus(provider.name)
                  return (
                    <IntegrationRow
                      key={provider.name}
                      name={provider.name}
                      description={provider.description}
                      connected={provider.configured}
                      icon={<Shield className="w-4 h-4" />}
                      onEdit={isAdmin && pluginId ? () => handleEditPlugin(pluginId) : undefined}
                      quotaUsed={apiStatus?.quota_used}
                      quotaMax={apiStatus?.quota_max}
                      hasError={apiStatus?.has_error}
                      lastSuccess={apiStatus?.config.last_success}
                      lastError={apiStatus?.config.last_error_message}
                    />
                  )
                })}
            </IntegrationCategory>

            {/* Email & Notifications Category */}
            <IntegrationCategory
              name="Email & Notifications"
              icon={<Mail className="w-4 h-4" />}
              colorClass="text-teal-500"
            >
              <IntegrationRow
                name="SMTP Email"
                description="Email notifications and scheduled reports"
                connected={notifSettings?.smtp_configured || false}
                icon={<Send className="w-4 h-4" />}
                onEdit={isAdmin ? () => handleEditPlugin('smtp') : undefined}
              />
            </IntegrationCategory>

            {/* Premium Features Category */}
            <IntegrationCategory
              name="Premium Features"
              icon={<Sparkles className="w-4 h-4" />}
              colorClass="text-yellow-500"
            >
              <IntegrationRow
                name="VGX Neural-Sync"
                description="Centralized blocklist sync via VigilanceKey"
                connected={false}
                icon={<Brain className="w-4 h-4" />}
                onEdit={isAdmin ? () => handleEditPlugin('neural_sync') : undefined}
              />
            </IntegrationCategory>
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
                  disabled={savingPlugin || disconnecting}
                  className="px-4 py-2 bg-muted rounded-lg hover:bg-muted/80 transition-colors disabled:opacity-50"
                >
                  {saveResult ? 'Close' : 'Cancel'}
                </button>
                {/* Disconnect button - only show when plugin is configured and no success result */}
                {!saveResult?.success && editingPlugin && isPluginConfigured(editingPlugin.id) && (
                  <button
                    type="button"
                    onClick={handleDisconnectPlugin}
                    disabled={savingPlugin || disconnecting}
                    className="px-4 py-2 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30 transition-colors disabled:opacity-50 flex items-center gap-2"
                  >
                    {disconnecting ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Trash2 className="w-4 h-4" />
                    )}
                    {disconnecting ? 'Clearing...' : 'Disconnect'}
                  </button>
                )}
                {!saveResult?.success && (
                  <button
                    onClick={handleSavePlugin}
                    disabled={savingPlugin || disconnecting}
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
        <p>VIGILANCE X v3.55.114</p>
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
  quotaUsed,
  quotaMax,
  hasError,
  lastSuccess,
  lastError,
  syncInfo,
}: {
  name: string
  description: string
  connected: boolean
  icon: React.ReactNode
  onEdit?: () => void
  quotaUsed?: number
  quotaMax?: number // -1 = unlimited
  hasError?: boolean
  lastSuccess?: string
  lastError?: string
  syncInfo?: { lastSync: string; totalIPs: number } // For blocklist-type integrations
}) {
  // Format quota display
  const formatQuota = () => {
    if (quotaMax === undefined || quotaMax === null) return null
    if (quotaMax === -1) return `${quotaUsed || 0} / ∞`
    return `${quotaUsed || 0} / ${quotaMax}`
  }

  // Format sync info display
  const formatSyncInfo = () => {
    if (!syncInfo) return null
    const lastSyncDate = syncInfo.lastSync && syncInfo.lastSync !== '1970-01-01T00:00:00Z'
      ? new Date(syncInfo.lastSync).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })
      : 'Never'
    return { lastSync: lastSyncDate, totalIPs: syncInfo.totalIPs }
  }

  // Format last success date
  const formatLastSuccess = (dateStr: string | undefined) => {
    if (!dateStr || dateStr === '1970-01-01T00:00:00Z') return 'Never'
    try {
      const date = new Date(dateStr)
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    } catch {
      return 'Unknown'
    }
  }

  const quota = formatQuota()
  const syncDisplay = formatSyncInfo()

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
        {/* Sync info for blocklist-type integrations */}
        {syncDisplay && (
          <div className="flex items-center gap-2 px-2 py-1 bg-muted/50 rounded-lg text-xs font-medium">
            <RefreshCw className="w-3 h-3 text-muted-foreground" />
            <span className="text-foreground">{syncDisplay.totalIPs} IPs</span>
            <span className="text-muted-foreground">|</span>
            <Clock className="w-3 h-3 text-muted-foreground" />
            <span className="text-muted-foreground">{syncDisplay.lastSync}</span>
          </div>
        )}

        {/* Quota counter for API-based integrations */}
        {!syncDisplay && quota && (
          <div className="flex items-center gap-1.5 px-2 py-1 bg-muted/50 rounded-lg text-xs font-medium">
            <Hash className="w-3 h-3 text-muted-foreground" />
            <span className={cn(
              quotaMax !== -1 && quotaUsed !== undefined && quotaUsed >= (quotaMax || 0) * 0.9
                ? 'text-orange-500'
                : 'text-foreground'
            )}>
              {quota}
            </span>
            <span className="text-muted-foreground">/day</span>
          </div>
        )}

        {onEdit && (
          <button
            onClick={onEdit}
            className="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors"
            title="Edit configuration"
          >
            <Pencil className="w-4 h-4" />
          </button>
        )}

        {/* Error indicator with last success */}
        {hasError && lastSuccess ? (
          <div
            className="flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium bg-orange-500/10 text-orange-500"
            title={`Last error: ${lastError || 'Unknown'}`}
          >
            <AlertTriangle className="w-4 h-4" />
            <span className="text-xs">Last OK: {formatLastSuccess(lastSuccess)}</span>
          </div>
        ) : (
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
        )}
      </div>
    </div>
  )
}

// Collapsible integration category component
function IntegrationCategory({
  name,
  icon,
  colorClass,
  children,
  defaultOpen = false,
}: {
  name: string
  icon: React.ReactNode
  colorClass: string
  children: React.ReactNode
  defaultOpen?: boolean
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen)

  return (
    <div className="border-b border-border last:border-b-0">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-6 py-4 hover:bg-muted/30 transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className={cn("p-1.5 rounded-lg bg-muted/50", colorClass)}>
            {icon}
          </div>
          <span className="font-semibold">{name}</span>
        </div>
        <ChevronDown className={cn(
          "w-5 h-5 text-muted-foreground transition-transform duration-200",
          isOpen && "rotate-180"
        )} />
      </button>
      {isOpen && (
        <div className="bg-muted/20">
          {children}
        </div>
      )}
    </div>
  )
}
