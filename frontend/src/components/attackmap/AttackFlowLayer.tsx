import { useEffect, useRef, useCallback } from 'react'
import { useMap } from 'react-leaflet'
import type { AttackFlow } from '@/stores/attackMapStore'

interface AttackFlowLayerProps {
  flows: AttackFlow[]
  isLive: boolean
}

interface Particle {
  flowId: string
  progress: number
  speed: number
  size: number
  opacity: number
  trail: number[] // v3.57.108: Trail positions for comet effect
}

// Bezier curve control point calculation
function getControlPoint(
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  curvature: number = 0.3
): [number, number] {
  const midX = (x1 + x2) / 2
  const midY = (y1 + y2) / 2
  const dx = x2 - x1
  const dy = y2 - y1

  // Perpendicular offset for curve
  const offsetX = -dy * curvature
  const offsetY = dx * curvature

  return [midX + offsetX, midY + offsetY]
}

// Get point on quadratic bezier curve
function getPointOnCurve(
  x1: number, y1: number,
  cx: number, cy: number,
  x2: number, y2: number,
  t: number
): [number, number] {
  const mt = 1 - t
  const x = mt * mt * x1 + 2 * mt * t * cx + t * t * x2
  const y = mt * mt * y1 + 2 * mt * t * cy + t * t * y2
  return [x, y]
}

export function AttackFlowLayer({ flows, isLive }: AttackFlowLayerProps) {
  const map = useMap()
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const animationRef = useRef<number | null>(null)
  const particlesRef = useRef<Particle[]>([])

  // Initialize particles for each flow
  // v3.57.108: Enhanced with more particles and varied properties for immersive effect
  useEffect(() => {
    const particles: Particle[] = []

    flows.forEach(flow => {
      // Create more particles per flow based on intensity for denser effect
      const particleCount = Math.ceil(flow.intensity / 2) + 2
      for (let i = 0; i < particleCount; i++) {
        particles.push({
          flowId: flow.id,
          progress: Math.random(), // Stagger particles along the path
          // v3.57.110: Slower animation for better visibility (reduced by ~50%)
          speed: 0.0015 + Math.random() * 0.001 + (isLive ? 0.001 : 0),
          size: 2.5 + flow.intensity * 0.6 + Math.random() * 1.5,
          opacity: 0.7 + Math.random() * 0.3,
          trail: [], // Will be populated during animation
        })
      }
    })

    particlesRef.current = particles
  }, [flows, isLive])

  // Create canvas overlay
  useEffect(() => {
    const container = map.getContainer()

    // Create canvas if it doesn't exist
    let canvas = container.querySelector('.attack-flow-canvas') as HTMLCanvasElement
    if (!canvas) {
      canvas = document.createElement('canvas')
      canvas.className = 'attack-flow-canvas'
      canvas.style.position = 'absolute'
      canvas.style.top = '0'
      canvas.style.left = '0'
      canvas.style.pointerEvents = 'none'
      canvas.style.zIndex = '450' // Above tiles, below markers
      container.appendChild(canvas)
    }

    canvasRef.current = canvas

    // Resize canvas to match map
    const resize = () => {
      const size = map.getSize()
      canvas.width = size.x
      canvas.height = size.y
    }
    resize()

    map.on('resize', resize)
    map.on('move', () => {}) // Trigger redraw on move

    return () => {
      map.off('resize', resize)
      if (canvas.parentNode) {
        canvas.parentNode.removeChild(canvas)
      }
    }
  }, [map])

  // Animation loop
  const animate = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height)

    // Draw flows and particles
    const flowMap = new Map(flows.map(f => [f.id, f]))

    flows.forEach(flow => {
      // Convert lat/lng to pixel coordinates
      const sourcePoint = map.latLngToContainerPoint([flow.sourceLat, flow.sourceLng])
      const targetPoint = map.latLngToContainerPoint([flow.targetLat, flow.targetLng])

      // Skip if points are too close
      const distance = Math.hypot(targetPoint.x - sourcePoint.x, targetPoint.y - sourcePoint.y)
      if (distance < 20) return

      // Calculate control point for curve
      const [cx, cy] = getControlPoint(
        sourcePoint.x, sourcePoint.y,
        targetPoint.x, targetPoint.y,
        0.25
      )

      // v3.57.108: Enhanced flow path with glow effect
      // Draw outer glow
      ctx.beginPath()
      ctx.moveTo(sourcePoint.x, sourcePoint.y)
      ctx.quadraticCurveTo(cx, cy, targetPoint.x, targetPoint.y)
      ctx.strokeStyle = flow.color.replace(/[\d.]+\)$/, '0.08)')
      ctx.lineWidth = 4 + flow.intensity * 0.8
      ctx.stroke()

      // Draw the flow path (medium opacity)
      ctx.beginPath()
      ctx.moveTo(sourcePoint.x, sourcePoint.y)
      ctx.quadraticCurveTo(cx, cy, targetPoint.x, targetPoint.y)
      ctx.strokeStyle = flow.color.replace(/[\d.]+\)$/, '0.2)')
      ctx.lineWidth = 2 + flow.intensity * 0.4
      ctx.stroke()

      // Draw gradient along path for direction indication
      const gradient = ctx.createLinearGradient(
        sourcePoint.x, sourcePoint.y,
        targetPoint.x, targetPoint.y
      )
      gradient.addColorStop(0, flow.color.replace(/[\d.]+\)$/, '0.05)'))
      gradient.addColorStop(0.5, flow.color.replace(/[\d.]+\)$/, '0.25)'))
      gradient.addColorStop(1, flow.color.replace(/[\d.]+\)$/, '0.5)'))

      ctx.beginPath()
      ctx.moveTo(sourcePoint.x, sourcePoint.y)
      ctx.quadraticCurveTo(cx, cy, targetPoint.x, targetPoint.y)
      ctx.strokeStyle = gradient
      ctx.lineWidth = 2 + flow.intensity * 0.5
      ctx.stroke()
    })

    // Update and draw particles
    particlesRef.current.forEach(particle => {
      const flow = flowMap.get(particle.flowId)
      if (!flow) return

      // Update particle progress
      particle.progress += particle.speed
      if (particle.progress > 1) {
        particle.progress = 0
        // Add flash effect at target on arrival
        if (isLive && Math.random() > 0.7) {
          const targetPoint = map.latLngToContainerPoint([flow.targetLat, flow.targetLng])
          drawImpactFlash(ctx, targetPoint.x, targetPoint.y, flow.color)
        }
      }

      // Get pixel positions
      const sourcePoint = map.latLngToContainerPoint([flow.sourceLat, flow.sourceLng])
      const targetPoint = map.latLngToContainerPoint([flow.targetLat, flow.targetLng])
      const [cx, cy] = getControlPoint(
        sourcePoint.x, sourcePoint.y,
        targetPoint.x, targetPoint.y,
        0.25
      )

      // Get current position on curve
      const [px, py] = getPointOnCurve(
        sourcePoint.x, sourcePoint.y,
        cx, cy,
        targetPoint.x, targetPoint.y,
        particle.progress
      )

      // v3.57.108: Enhanced particle with comet trail and pulsing glow
      // Store previous position for trail
      if (particle.trail.length >= 8) {
        particle.trail.shift()
        particle.trail.shift()
      }
      particle.trail.push(px, py)

      // Draw trail (comet effect)
      if (particle.trail.length >= 4) {
        for (let t = 0; t < particle.trail.length - 2; t += 2) {
          const trailOpacity = (t / particle.trail.length) * 0.4
          const trailSize = particle.size * (0.3 + (t / particle.trail.length) * 0.5)
          ctx.beginPath()
          ctx.arc(particle.trail[t], particle.trail[t + 1], trailSize, 0, Math.PI * 2)
          ctx.fillStyle = flow.color.replace(/[\d.]+\)$/, `${trailOpacity})`)
          ctx.fill()
        }
      }

      // Draw outer glow (larger, more diffuse)
      const outerGlow = ctx.createRadialGradient(px, py, 0, px, py, particle.size * 4)
      outerGlow.addColorStop(0, flow.color.replace(/[\d.]+\)$/, '0.6)'))
      outerGlow.addColorStop(0.3, flow.color.replace(/[\d.]+\)$/, '0.3)'))
      outerGlow.addColorStop(0.6, flow.color.replace(/[\d.]+\)$/, '0.1)'))
      outerGlow.addColorStop(1, 'transparent')

      ctx.beginPath()
      ctx.arc(px, py, particle.size * 4, 0, Math.PI * 2)
      ctx.fillStyle = outerGlow
      ctx.fill()

      // Draw inner glow
      const glow = ctx.createRadialGradient(px, py, 0, px, py, particle.size * 2)
      glow.addColorStop(0, flow.color)
      glow.addColorStop(0.4, flow.color.replace(/[\d.]+\)$/, '0.5)'))
      glow.addColorStop(1, 'transparent')

      ctx.beginPath()
      ctx.arc(px, py, particle.size * 2, 0, Math.PI * 2)
      ctx.fillStyle = glow
      ctx.fill()

      // Core particle (bright white center)
      ctx.beginPath()
      ctx.arc(px, py, particle.size * 0.5, 0, Math.PI * 2)
      ctx.fillStyle = '#fff'
      ctx.globalAlpha = particle.opacity
      ctx.fill()
      ctx.globalAlpha = 1
    })

    animationRef.current = requestAnimationFrame(animate)
  }, [map, flows, isLive])

  // Start animation loop
  useEffect(() => {
    animate()
    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current)
      }
    }
  }, [animate])

  return null
}

// Draw impact flash when particle arrives at target
// v3.57.108: Enhanced with multi-ring ripple effect
function drawImpactFlash(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  color: string
) {
  // Outer ripple
  const outerGradient = ctx.createRadialGradient(x, y, 0, x, y, 50)
  outerGradient.addColorStop(0, 'transparent')
  outerGradient.addColorStop(0.5, color.replace(/[\d.]+\)$/, '0.15)'))
  outerGradient.addColorStop(0.7, color.replace(/[\d.]+\)$/, '0.3)'))
  outerGradient.addColorStop(1, 'transparent')

  ctx.beginPath()
  ctx.arc(x, y, 50, 0, Math.PI * 2)
  ctx.fillStyle = outerGradient
  ctx.fill()

  // Inner flash
  const gradient = ctx.createRadialGradient(x, y, 0, x, y, 25)
  gradient.addColorStop(0, '#fff')
  gradient.addColorStop(0.2, color)
  gradient.addColorStop(0.5, color.replace(/[\d.]+\)$/, '0.5)'))
  gradient.addColorStop(1, 'transparent')

  ctx.beginPath()
  ctx.arc(x, y, 25, 0, Math.PI * 2)
  ctx.fillStyle = gradient
  ctx.fill()
}
