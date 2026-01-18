// v3.57.108: Admin Terminal Console - Docker management and logs viewer
import { useState, useEffect, useRef, useCallback } from 'react'
import {
  X,
  Terminal,
  FileText,
  Send,
  Loader2,
  RefreshCw,
  ChevronDown,
  AlertCircle,
  CheckCircle2,
  Play,
  Square,
  RotateCw
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { consoleApi, type ConsoleCommandResponse } from '@/lib/api'

interface TerminalConsoleProps {
  isOpen: boolean
  onClose: () => void
}

type Tab = 'console' | 'logs'

interface CommandHistory {
  command: string
  response: ConsoleCommandResponse
  timestamp: Date
}

const SERVICES = [
  { name: 'api', label: 'API' },
  { name: 'frontend', label: 'Frontend' },
  { name: 'clickhouse', label: 'ClickHouse' },
  { name: 'redis', label: 'Redis' },
  { name: 'vector', label: 'Vector' },
]

export function TerminalConsole({ isOpen, onClose }: TerminalConsoleProps) {
  const [activeTab, setActiveTab] = useState<Tab>('console')
  const [command, setCommand] = useState('')
  const [history, setHistory] = useState<CommandHistory[]>([])
  const [isExecuting, setIsExecuting] = useState(false)
  const [historyIndex, setHistoryIndex] = useState(-1)

  // Logs viewer state
  const [selectedService, setSelectedService] = useState('api')
  const [logs, setLogs] = useState<string[]>([])
  const [isLoadingLogs, setIsLoadingLogs] = useState(false)
  const [isStreaming, setIsStreaming] = useState(false)
  const [eventSource, setEventSource] = useState<EventSource | null>(null)

  const inputRef = useRef<HTMLInputElement>(null)
  const outputRef = useRef<HTMLDivElement>(null)
  const logsRef = useRef<HTMLDivElement>(null)

  // Focus input when modal opens
  useEffect(() => {
    if (isOpen && activeTab === 'console') {
      setTimeout(() => inputRef.current?.focus(), 100)
    }
  }, [isOpen, activeTab])

  // Scroll to bottom when history changes
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [history])

  // Scroll logs to bottom
  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight
    }
  }, [logs])

  // Cleanup event source on unmount
  useEffect(() => {
    return () => {
      if (eventSource) {
        eventSource.close()
      }
    }
  }, [eventSource])

  const executeCommand = useCallback(async (cmd: string) => {
    if (!cmd.trim()) return

    setHistoryIndex(-1)

    // Parse command and args
    const parts = cmd.trim().split(/\s+/)
    const mainCmd = parts[0].toLowerCase()
    const args = parts.slice(1)

    // Handle local commands (no API call needed)
    if (mainCmd === 'clear' || mainCmd === 'cls') {
      setHistory([])
      setCommand('')
      return
    }

    setIsExecuting(true)

    try {
      const response = await consoleApi.execute(mainCmd, args)
      setHistory(prev => [...prev, {
        command: cmd,
        response,
        timestamp: new Date()
      }])
    } catch (err) {
      setHistory(prev => [...prev, {
        command: cmd,
        response: {
          success: false,
          output: '',
          error: err instanceof Error ? err.message : 'Command failed'
        },
        timestamp: new Date()
      }])
    } finally {
      setIsExecuting(false)
      setCommand('')
    }
  }, [])

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isExecuting) {
      executeCommand(command)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      const commands = history.map(h => h.command)
      if (commands.length > 0) {
        const newIndex = historyIndex < commands.length - 1 ? historyIndex + 1 : historyIndex
        setHistoryIndex(newIndex)
        setCommand(commands[commands.length - 1 - newIndex])
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (historyIndex > 0) {
        const newIndex = historyIndex - 1
        setHistoryIndex(newIndex)
        const commands = history.map(h => h.command)
        setCommand(commands[commands.length - 1 - newIndex])
      } else if (historyIndex === 0) {
        setHistoryIndex(-1)
        setCommand('')
      }
    }
  }

  const loadLogs = async () => {
    setIsLoadingLogs(true)
    try {
      const response = await consoleApi.getLogs(selectedService, 200)
      if (response.error) {
        setLogs([`Error: ${response.error}`])
      } else if (response.lines && response.lines.length > 0) {
        setLogs(response.lines)
      } else if (response.output) {
        setLogs(response.output.split('\n').filter(Boolean))
      } else {
        setLogs(['No logs available for this service'])
      }
    } catch (err: unknown) {
      // Handle axios errors with response data
      const axiosErr = err as { response?: { data?: { error?: string } }; message?: string }
      const errorMsg = axiosErr.response?.data?.error || axiosErr.message || 'Unknown error'
      setLogs([`Error loading logs: ${errorMsg}`])
    } finally {
      setIsLoadingLogs(false)
    }
  }

  const startStreaming = () => {
    if (eventSource) {
      eventSource.close()
    }

    const es = consoleApi.streamLogs(selectedService)

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.line) {
          setLogs(prev => [...prev.slice(-500), data.line])
        }
        if (data.error) {
          setLogs(prev => [...prev, `Error: ${data.error}`])
        }
      } catch {
        // Ignore parse errors
      }
    }

    es.onerror = () => {
      setIsStreaming(false)
      es.close()
    }

    setEventSource(es)
    setIsStreaming(true)
  }

  const stopStreaming = () => {
    if (eventSource) {
      eventSource.close()
      setEventSource(null)
    }
    setIsStreaming(false)
  }

  // Load logs when service changes
  useEffect(() => {
    if (activeTab === 'logs' && isOpen) {
      loadLogs()
    }
  }, [selectedService, activeTab, isOpen])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="admin-console-modal bg-zinc-900 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-4xl max-h-[85vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="admin-console-header flex items-center justify-between px-4 py-3 bg-zinc-800 border-b border-zinc-700">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-green-500" />
              <h2 className="font-semibold text-white">Admin Console</h2>
            </div>
            {/* Tabs */}
            <div className="flex items-center gap-1 ml-4 bg-zinc-900/50 rounded-lg p-1">
              <button
                onClick={() => setActiveTab('console')}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm font-medium transition-colors",
                  activeTab === 'console'
                    ? "bg-zinc-700 text-white"
                    : "text-zinc-400 hover:text-white"
                )}
              >
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-4 h-4" />
                  Console
                </span>
              </button>
              <button
                onClick={() => setActiveTab('logs')}
                className={cn(
                  "px-3 py-1.5 rounded-md text-sm font-medium transition-colors",
                  activeTab === 'logs'
                    ? "bg-zinc-700 text-white"
                    : "text-zinc-400 hover:text-white"
                )}
              >
                <span className="flex items-center gap-1.5">
                  <FileText className="w-4 h-4" />
                  Logs Viewer
                </span>
              </button>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 hover:bg-zinc-700 rounded-lg transition-colors text-zinc-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        {activeTab === 'console' ? (
          <div className="flex-1 flex flex-col min-h-0">
            {/* Output area */}
            <div
              ref={outputRef}
              className="flex-1 overflow-y-auto p-4 font-mono text-sm bg-zinc-950"
            >
              {/* Welcome message */}
              {history.length === 0 && (
                <div className="text-zinc-500 mb-4">
                  <p className="text-green-500 mb-2">VIGILANCE X Admin Console v3.57.107</p>
                  <p>Type 'help' to see available commands.</p>
                  <p className="mt-2 text-xs">Use arrow keys to navigate command history.</p>
                </div>
              )}

              {/* Command history */}
              {history.map((item, index) => (
                <div key={index} className="mb-4">
                  {/* Command */}
                  <div className="flex items-center gap-2 text-zinc-400">
                    <span className="text-green-500">$</span>
                    <span className="text-white">{item.command}</span>
                    <span className="text-zinc-600 text-xs ml-auto">
                      {item.timestamp.toLocaleTimeString()}
                    </span>
                  </div>
                  {/* Response */}
                  <div className={cn(
                    "mt-1 whitespace-pre-wrap",
                    item.response.success ? "text-zinc-300" : "text-red-400"
                  )}>
                    {item.response.error && (
                      <div className="flex items-center gap-2 text-red-400 mb-1">
                        <AlertCircle className="w-4 h-4" />
                        <span>{item.response.error}</span>
                      </div>
                    )}
                    {item.response.output}
                  </div>
                </div>
              ))}

              {/* Executing indicator */}
              {isExecuting && (
                <div className="flex items-center gap-2 text-zinc-400">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Executing...</span>
                </div>
              )}
            </div>

            {/* Input area */}
            <div className="p-3 bg-zinc-900 border-t border-zinc-700">
              <div className="flex items-center gap-2">
                <span className="text-green-500 font-mono">$</span>
                <input
                  ref={inputRef}
                  type="text"
                  value={command}
                  onChange={(e) => setCommand(e.target.value)}
                  onKeyDown={handleKeyDown}
                  disabled={isExecuting}
                  placeholder="Enter command..."
                  className="flex-1 bg-transparent text-white font-mono text-sm focus:outline-none placeholder-zinc-600"
                  autoComplete="off"
                  spellCheck={false}
                />
                <button
                  onClick={() => executeCommand(command)}
                  disabled={isExecuting || !command.trim()}
                  className={cn(
                    "p-2 rounded-lg transition-colors",
                    command.trim() && !isExecuting
                      ? "bg-green-600 hover:bg-green-500 text-white"
                      : "bg-zinc-700 text-zinc-500"
                  )}
                >
                  <Send className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col min-h-0">
            {/* Logs toolbar */}
            <div className="flex items-center gap-4 p-3 bg-zinc-800/50 border-b border-zinc-700">
              {/* Service selector */}
              <div className="relative">
                <select
                  value={selectedService}
                  onChange={(e) => {
                    setSelectedService(e.target.value)
                    if (isStreaming) {
                      stopStreaming()
                    }
                  }}
                  className="appearance-none bg-zinc-700 text-white text-sm px-3 py-1.5 pr-8 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500/50"
                >
                  {SERVICES.map(svc => (
                    <option key={svc.name} value={svc.name}>{svc.label}</option>
                  ))}
                </select>
                <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400 pointer-events-none" />
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2">
                <button
                  onClick={loadLogs}
                  disabled={isLoadingLogs}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-700 hover:bg-zinc-600 text-white text-sm rounded-lg transition-colors disabled:opacity-50"
                >
                  <RefreshCw className={cn("w-4 h-4", isLoadingLogs && "animate-spin")} />
                  Refresh
                </button>

                {isStreaming ? (
                  <button
                    onClick={stopStreaming}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white text-sm rounded-lg transition-colors"
                  >
                    <Square className="w-4 h-4" />
                    Stop
                  </button>
                ) : (
                  <button
                    onClick={startStreaming}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600 hover:bg-green-500 text-white text-sm rounded-lg transition-colors"
                  >
                    <Play className="w-4 h-4" />
                    Stream
                  </button>
                )}

                <button
                  onClick={() => setLogs([])}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-700 hover:bg-zinc-600 text-white text-sm rounded-lg transition-colors"
                >
                  <RotateCw className="w-4 h-4" />
                  Clear
                </button>
              </div>

              {/* Status */}
              <div className="ml-auto flex items-center gap-2 text-sm">
                {isStreaming && (
                  <span className="flex items-center gap-1.5 text-green-500">
                    <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                    Live
                  </span>
                )}
                <span className="text-zinc-500">{logs.length} lines</span>
              </div>
            </div>

            {/* Logs area */}
            <div
              ref={logsRef}
              className="flex-1 overflow-y-auto p-4 font-mono text-xs bg-zinc-950"
            >
              {isLoadingLogs ? (
                <div className="flex items-center justify-center h-full text-zinc-500">
                  <Loader2 className="w-6 h-6 animate-spin" />
                </div>
              ) : logs.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-zinc-500">
                  <FileText className="w-12 h-12 mb-3 opacity-30" />
                  <p>No logs available</p>
                  <p className="text-xs mt-1">Click Refresh or Stream to load logs</p>
                </div>
              ) : (
                logs.map((line, index) => (
                  <div
                    key={index}
                    className={cn(
                      "py-0.5 hover:bg-zinc-800/50",
                      line.toLowerCase().includes('error') && "text-red-400",
                      line.toLowerCase().includes('warn') && "text-yellow-400",
                      line.toLowerCase().includes('info') && "text-blue-400",
                      !line.toLowerCase().includes('error') &&
                      !line.toLowerCase().includes('warn') &&
                      !line.toLowerCase().includes('info') && "text-zinc-300"
                    )}
                  >
                    {line}
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="px-4 py-2 bg-zinc-800 border-t border-zinc-700 flex items-center justify-between text-xs text-zinc-500">
          <span>Admin only - Commands are logged</span>
          <span className="flex items-center gap-2">
            <CheckCircle2 className="w-3 h-3 text-green-500" />
            Connected
          </span>
        </div>
      </div>
    </div>
  )
}
