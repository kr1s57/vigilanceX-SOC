// v3.57.126: Custom VIGILANCE X logo component
interface LogoProps {
  size?: number
  className?: string
}

export function Logo({ size = 64, className = '' }: LogoProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 32 32"
      width={size}
      height={size}
      className={className}
      fill="none"
    >
      {/* Background - dark hexagon */}
      <path
        d="M16 1L29 8.5v15L16 31 3 23.5v-15L16 1z"
        fill="#0f172a"
        stroke="#14b8a6"
        strokeWidth="0.5"
      />

      {/* Inner shield shape */}
      <path
        d="M16 4L26 9.5v11L16 26 6 20.5v-11L16 4z"
        fill="#0f172a"
        stroke="#14b8a6"
        strokeWidth="1"
      />

      {/* Stylized V with scan lines */}
      <path
        d="M10 10L16 20L22 10"
        stroke="#14b8a6"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />

      {/* Horizontal scan line */}
      <line
        x1="8"
        y1="15"
        x2="24"
        y2="15"
        stroke="#14b8a6"
        strokeWidth="0.75"
        strokeDasharray="2,1"
        opacity="0.6"
      />

      {/* Center dot (eye/focus point) */}
      <circle cx="16" cy="15" r="2" fill="#14b8a6" />

      {/* Corner accents (orange/alert color) */}
      <path d="M16 4L18 5.5" stroke="#f97316" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M16 4L14 5.5" stroke="#f97316" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  )
}

// Large animated version for splash/login screens
export function LogoAnimated({ size = 80, className = '' }: LogoProps) {
  return (
    <div className={`relative ${className}`}>
      <Logo size={size} />
      {/* Pulse ring effect */}
      <div
        className="absolute inset-0 rounded-full animate-ping opacity-20"
        style={{
          background: 'radial-gradient(circle, #14b8a6 0%, transparent 70%)',
          animationDuration: '2s',
        }}
      />
    </div>
  )
}
