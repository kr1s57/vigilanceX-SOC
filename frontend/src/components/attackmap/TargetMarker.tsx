import { Marker, Tooltip } from 'react-leaflet'
import L from 'leaflet'

interface TargetMarkerProps {
  position: [number, number]
  name: string
}

// Create custom pulsing icon
const createPulsingIcon = () => {
  return L.divIcon({
    className: 'target-marker-container',
    html: `
      <div class="target-marker">
        <div class="target-pulse-ring"></div>
        <div class="target-pulse-ring delay-1"></div>
        <div class="target-pulse-ring delay-2"></div>
        <div class="target-core">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s-8-4.5-8-11.8A8 8 0 0 1 12 2a8 8 0 0 1 8 8.2c0 7.3-8 11.8-8 11.8z"/>
            <circle cx="12" cy="10" r="3"/>
          </svg>
        </div>
      </div>
      <style>
        .target-marker-container {
          background: none !important;
          border: none !important;
        }
        .target-marker {
          position: relative;
          width: 60px;
          height: 60px;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .target-pulse-ring {
          position: absolute;
          width: 60px;
          height: 60px;
          border-radius: 50%;
          border: 2px solid rgba(34, 211, 238, 0.6);
          animation: pulse-ring 2s ease-out infinite;
        }
        .target-pulse-ring.delay-1 {
          animation-delay: 0.6s;
        }
        .target-pulse-ring.delay-2 {
          animation-delay: 1.2s;
        }
        @keyframes pulse-ring {
          0% {
            transform: scale(0.5);
            opacity: 1;
          }
          100% {
            transform: scale(1.5);
            opacity: 0;
          }
        }
        .target-core {
          position: relative;
          width: 32px;
          height: 32px;
          background: linear-gradient(135deg, #06b6d4, #3b82f6);
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: 0 0 20px rgba(34, 211, 238, 0.5),
                      0 0 40px rgba(34, 211, 238, 0.3),
                      inset 0 0 10px rgba(255, 255, 255, 0.2);
          animation: glow-pulse 2s ease-in-out infinite;
        }
        @keyframes glow-pulse {
          0%, 100% {
            box-shadow: 0 0 20px rgba(34, 211, 238, 0.5),
                        0 0 40px rgba(34, 211, 238, 0.3),
                        inset 0 0 10px rgba(255, 255, 255, 0.2);
          }
          50% {
            box-shadow: 0 0 30px rgba(34, 211, 238, 0.7),
                        0 0 60px rgba(34, 211, 238, 0.4),
                        inset 0 0 15px rgba(255, 255, 255, 0.3);
          }
        }
        .target-core svg {
          width: 18px;
          height: 18px;
          color: white;
          filter: drop-shadow(0 0 2px rgba(255, 255, 255, 0.5));
        }
      </style>
    `,
    iconSize: [60, 60],
    iconAnchor: [30, 30],
  })
}

export function TargetMarker({ position, name }: TargetMarkerProps) {
  const icon = createPulsingIcon()

  return (
    <Marker position={position} icon={icon}>
      <Tooltip
        direction="top"
        offset={[0, -35]}
        permanent={false}
        className="target-tooltip"
      >
        <div className="font-sans text-center">
          <div className="font-bold text-cyan-400">{name}</div>
          <div className="text-xs text-gray-400">Protected Target</div>
        </div>
        <style>{`
          .target-tooltip {
            background: rgba(0, 0, 0, 0.9) !important;
            backdrop-filter: blur(8px);
            border: 1px solid rgba(34, 211, 238, 0.3) !important;
            border-radius: 8px !important;
            padding: 8px 12px !important;
            color: white !important;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5),
                        0 0 20px rgba(34, 211, 238, 0.2) !important;
          }
          .target-tooltip::before {
            border-top-color: rgba(0, 0, 0, 0.9) !important;
          }
        `}</style>
      </Tooltip>
    </Marker>
  )
}
