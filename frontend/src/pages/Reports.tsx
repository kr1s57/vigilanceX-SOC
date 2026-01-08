import { useState, useEffect } from 'react'
import {
  FileText,
  Database,
  Calendar,
  Download,
  Clock,
  Shield,
  Network,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Loader2,
  HardDrive,
  Table2,
} from 'lucide-react'
import { reportsApi } from '@/lib/api'
import { formatNumber } from '@/lib/utils'
import type { DBStats, ReportConfig } from '@/types'

interface ModuleOption {
  id: string
  label: string
  icon: React.ReactNode
  description: string
}

const MODULES: ModuleOption[] = [
  { id: 'waf', label: 'WAF / ModSecurity', icon: <Shield className="w-4 h-4" />, description: 'Web Application Firewall detections' },
  { id: 'vpn', label: 'VPN & Network', icon: <Network className="w-4 h-4" />, description: 'VPN connections and network events' },
  { id: 'threats', label: 'Threat Intelligence', icon: <AlertTriangle className="w-4 h-4" />, description: 'IP reputation and threat scores' },
  { id: 'bans', label: 'Bans & History', icon: <Ban className="w-4 h-4" />, description: 'Active bans and ban history' },
]

export function Reports() {
  const [dbStats, setDbStats] = useState<DBStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [generatingType, setGeneratingType] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Custom report form state
  const [format, setFormat] = useState<'pdf' | 'xml'>('pdf')
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [selectedModules, setSelectedModules] = useState<string[]>(['waf', 'vpn', 'threats', 'bans'])

  useEffect(() => {
    async function fetchStats() {
      try {
        setLoading(true)
        const stats = await reportsApi.getDBStats()
        setDbStats(stats)
      } catch (err) {
        console.error('Failed to load DB stats:', err)
        setError('Failed to load database statistics')
      } finally {
        setLoading(false)
      }
    }
    fetchStats()
  }, [])

  const handleModuleToggle = (moduleId: string) => {
    setSelectedModules(prev =>
      prev.includes(moduleId)
        ? prev.filter(m => m !== moduleId)
        : [...prev, moduleId]
    )
  }

  const generateReport = async (type: 'daily' | 'weekly' | 'monthly' | 'custom') => {
    setGenerating(true)
    setGeneratingType(type)
    setError(null)
    setSuccess(null)

    try {
      const config: ReportConfig = {
        type,
        format,
        modules: selectedModules.length > 0 ? selectedModules : undefined,
      }

      if (type === 'custom') {
        if (!startDate || !endDate) {
          setError('Please select start and end dates for custom reports')
          setGenerating(false)
          setGeneratingType(null)
          return
        }
        config.start_date = startDate
        config.end_date = endDate
      }

      const result = await reportsApi.generate(config)
      setSuccess(`Report downloaded: ${result.filename}`)
    } catch (err) {
      console.error('Failed to generate report:', err)
      setError('Failed to generate report. Please try again.')
    } finally {
      setGenerating(false)
      setGeneratingType(null)
    }
  }

  const formatDateRange = () => {
    if (!dbStats) return 'N/A'
    const start = new Date(dbStats.date_range_start).toLocaleDateString()
    const end = new Date(dbStats.date_range_end).toLocaleDateString()
    return `${start} - ${end}`
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Reports & Export</h1>
          <p className="text-muted-foreground">Generate and download security reports</p>
        </div>
      </div>

      {/* Status Messages */}
      {error && (
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-destructive" />
          <span className="text-destructive">{error}</span>
        </div>
      )}
      {success && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 text-green-500" />
          <span className="text-green-500">{success}</span>
        </div>
      )}

      {/* Quick Reports - Moved to top */}
      <div className="bg-card rounded-xl border p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Clock className="w-5 h-5" />
          Quick Reports
        </h2>
        <p className="text-sm text-muted-foreground mb-4">
          Generate predefined reports for common time periods
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <button
            onClick={() => generateReport('daily')}
            disabled={generating}
            className="flex items-center justify-center gap-3 p-4 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {generatingType === 'daily' ? (
              <Loader2 className="w-5 h-5 animate-spin text-blue-500" />
            ) : (
              <Download className="w-5 h-5 text-blue-500" />
            )}
            <div className="text-left">
              <p className="font-medium">Daily Report</p>
              <p className="text-xs text-muted-foreground">Last 24 hours</p>
            </div>
          </button>

          <button
            onClick={() => generateReport('weekly')}
            disabled={generating}
            className="flex items-center justify-center gap-3 p-4 bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/20 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {generatingType === 'weekly' ? (
              <Loader2 className="w-5 h-5 animate-spin text-purple-500" />
            ) : (
              <Download className="w-5 h-5 text-purple-500" />
            )}
            <div className="text-left">
              <p className="font-medium">Weekly Report</p>
              <p className="text-xs text-muted-foreground">Last 7 days</p>
            </div>
          </button>

          <button
            onClick={() => generateReport('monthly')}
            disabled={generating}
            className="flex items-center justify-center gap-3 p-4 bg-green-500/10 hover:bg-green-500/20 border border-green-500/20 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {generatingType === 'monthly' ? (
              <Loader2 className="w-5 h-5 animate-spin text-green-500" />
            ) : (
              <Download className="w-5 h-5 text-green-500" />
            )}
            <div className="text-left">
              <p className="font-medium">Monthly Report</p>
              <p className="text-xs text-muted-foreground">Last 30 days</p>
            </div>
          </button>
        </div>

        {/* Format Selection */}
        <div className="flex items-center gap-4">
          <span className="text-sm text-muted-foreground">Format:</span>
          <div className="flex items-center gap-2 bg-muted rounded-lg p-1">
            <button
              onClick={() => setFormat('pdf')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
                format === 'pdf'
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              PDF
            </button>
            <button
              onClick={() => setFormat('xml')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
                format === 'xml'
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              XML
            </button>
          </div>
        </div>
      </div>

      {/* Custom Report Builder - Moved to top */}
      <div className="bg-card rounded-xl border p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <FileText className="w-5 h-5" />
          Custom Report
        </h2>
        <p className="text-sm text-muted-foreground mb-6">
          Build a custom report with specific date range and modules
        </p>

        {/* Date Range */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div>
            <label className="block text-sm font-medium mb-2">Start Date</label>
            <input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              className="w-full px-4 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">End Date</label>
            <input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              className="w-full px-4 py-2 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
        </div>

        {/* Module Selection */}
        <div className="mb-6">
          <label className="block text-sm font-medium mb-3">Include Modules</label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {MODULES.map((module) => (
              <label
                key={module.id}
                className={`flex items-center gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${
                  selectedModules.includes(module.id)
                    ? 'bg-primary/10 border-primary/50'
                    : 'bg-muted/30 border-transparent hover:bg-muted/50'
                }`}
              >
                <input
                  type="checkbox"
                  checked={selectedModules.includes(module.id)}
                  onChange={() => handleModuleToggle(module.id)}
                  className="sr-only"
                />
                <div className={`p-2 rounded-lg ${selectedModules.includes(module.id) ? 'bg-primary/20' : 'bg-muted'}`}>
                  {module.icon}
                </div>
                <div className="flex-1">
                  <p className="font-medium">{module.label}</p>
                  <p className="text-xs text-muted-foreground">{module.description}</p>
                </div>
                <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${
                  selectedModules.includes(module.id)
                    ? 'border-primary bg-primary'
                    : 'border-muted-foreground'
                }`}>
                  {selectedModules.includes(module.id) && (
                    <CheckCircle2 className="w-4 h-4 text-primary-foreground" />
                  )}
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Generate Button */}
        <div className="flex items-center justify-end">
          <button
            onClick={() => generateReport('custom')}
            disabled={generating || !startDate || !endDate}
            className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {generating ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <Download className="w-5 h-5" />
                Generate Custom Report
              </>
            )}
          </button>
        </div>
      </div>

      {/* Database Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-card rounded-xl border p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Database Size</p>
              <p className="text-2xl font-bold mt-1">{dbStats?.database_size || 'N/A'}</p>
            </div>
            <div className="p-3 bg-blue-500/10 rounded-lg">
              <Database className="w-6 h-6 text-blue-500" />
            </div>
          </div>
        </div>

        <div className="bg-card rounded-xl border p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Total Events</p>
              <p className="text-2xl font-bold mt-1">{formatNumber(dbStats?.total_events || 0)}</p>
            </div>
            <div className="p-3 bg-purple-500/10 rounded-lg">
              <FileText className="w-6 h-6 text-purple-500" />
            </div>
          </div>
        </div>

        <div className="bg-card rounded-xl border p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Data Range</p>
              <p className="text-lg font-bold mt-1">{formatDateRange()}</p>
            </div>
            <div className="p-3 bg-green-500/10 rounded-lg">
              <Calendar className="w-6 h-6 text-green-500" />
            </div>
          </div>
        </div>

        <div className="bg-card rounded-xl border p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Tables</p>
              <p className="text-2xl font-bold mt-1">{dbStats?.table_stats?.length || 0}</p>
            </div>
            <div className="p-3 bg-orange-500/10 rounded-lg">
              <Table2 className="w-6 h-6 text-orange-500" />
            </div>
          </div>
        </div>
      </div>

      {/* Events by Type */}
      {dbStats?.events_by_type && Object.keys(dbStats.events_by_type).length > 0 && (
        <div className="bg-card rounded-xl border p-6">
          <h2 className="text-lg font-semibold mb-4">Events by Type</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(dbStats.events_by_type).map(([type, count]) => (
              <div key={type} className="bg-muted/50 rounded-lg p-4">
                <p className="text-sm text-muted-foreground">{type}</p>
                <p className="text-xl font-bold">{formatNumber(count)}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Table Statistics */}
      {dbStats?.table_stats && dbStats.table_stats.length > 0 && (
        <div className="bg-card rounded-xl border p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <HardDrive className="w-5 h-5" />
            Table Statistics
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-2 px-4 text-sm font-medium text-muted-foreground">Table</th>
                  <th className="text-right py-2 px-4 text-sm font-medium text-muted-foreground">Rows</th>
                  <th className="text-right py-2 px-4 text-sm font-medium text-muted-foreground">Size</th>
                </tr>
              </thead>
              <tbody>
                {dbStats.table_stats.map((table) => (
                  <tr key={table.table_name} className="border-b last:border-0">
                    <td className="py-2 px-4 font-mono text-sm">{table.table_name}</td>
                    <td className="py-2 px-4 text-right">{formatNumber(table.row_count)}</td>
                    <td className="py-2 px-4 text-right text-muted-foreground">{table.size}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  )
}
