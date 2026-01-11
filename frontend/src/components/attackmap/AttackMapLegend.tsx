import { Info } from 'lucide-react'
import { getThreatColor, ATTACK_TYPE_CONFIG, type AttackType } from '@/stores/attackMapStore'

export function AttackMapLegend() {
  const levels = [
    { level: 'critical', label: 'Critical' },
    { level: 'high', label: 'High' },
    { level: 'medium', label: 'Medium' },
    { level: 'low', label: 'Low' },
    { level: 'minimal', label: 'Minimal' },
  ] as const

  const attackTypes: AttackType[] = ['waf', 'ips', 'malware', 'threat']

  return (
    <div className="absolute bottom-4 left-4 z-[1000] bg-black/60 backdrop-blur-sm rounded-lg p-3 pointer-events-auto">
      {/* Attack Types */}
      <div className="flex items-center gap-2 text-xs text-gray-400 mb-2">
        <Info className="w-3 h-3" />
        <span>Attack Types</span>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 mb-3">
        {attackTypes.map((type) => {
          const config = ATTACK_TYPE_CONFIG[type]
          return (
            <div key={type} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: config.color }}
              />
              <span className="text-[10px] text-gray-300">{config.label}</span>
            </div>
          )
        })}
      </div>

      {/* Country Intensity */}
      <div className="flex items-center gap-2 text-xs text-gray-400 mb-2 pt-2 border-t border-gray-700">
        <span>Country Intensity</span>
      </div>
      <div className="flex items-center gap-1">
        {levels.map(({ level, label }) => (
          <div
            key={level}
            className="group relative flex flex-col items-center"
          >
            <div
              className="w-6 h-3 rounded-sm"
              style={{ backgroundColor: getThreatColor(level) }}
            />
            <span className="absolute -bottom-5 text-[10px] text-gray-400 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
              {label}
            </span>
          </div>
        ))}
      </div>

      {/* Flow indicator */}
      <div className="flex items-center gap-2 mt-3 pt-3 border-t border-gray-700">
        <div className="relative w-6 h-1">
          <div className="absolute inset-0 bg-gradient-to-r from-orange-500/30 via-orange-500 to-orange-500/30 rounded-full" />
          <div className="absolute w-1.5 h-1.5 bg-white rounded-full -top-0.5 animate-flow-particle" />
        </div>
        <span className="text-[10px] text-gray-400">Attack Flow</span>
      </div>

      {/* Target indicator */}
      <div className="flex items-center gap-2 mt-2">
        <div className="w-3 h-3 rounded-full bg-cyan-500 animate-pulse" />
        <span className="text-[10px] text-gray-400">Target Infrastructure</span>
      </div>

      <style>{`
        @keyframes flow-particle {
          0% {
            left: 0;
            opacity: 0;
          }
          10% {
            opacity: 1;
          }
          90% {
            opacity: 1;
          }
          100% {
            left: calc(100% - 6px);
            opacity: 0;
          }
        }
        .animate-flow-particle {
          animation: flow-particle 1.5s ease-in-out infinite;
        }
      `}</style>
    </div>
  )
}
