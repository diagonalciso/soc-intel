/**
 * ThreatGlobe — rotating 3D globe showing recent incident locations.
 * Powered by COBE (WebGL canvas globe).
 * Supports mouse drag and touch drag to spin the globe.
 */
import { useEffect, useRef } from 'react'
import createGlobe from 'cobe'

export interface GlobeMarker {
  location: [number, number]  // [lat, lon]
  size: number                // 0.01 – 0.12
  label?: string
  count?: number
}

interface Props {
  markers: GlobeMarker[]
  width?: number
}

export default function ThreatGlobe({ markers, width = 380 }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  // Globe state — kept in refs so onRender always sees the latest values
  const phiRef   = useRef(0.6)      // current longitude rotation
  const thetaRef = useRef(0.15)     // current latitude tilt
  const dragging = useRef(false)
  const lastPos  = useRef({ x: 0, y: 0 })
  const velocity = useRef({ x: 0, y: 0 }) // momentum after drag ends

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const dpr = Math.min(window.devicePixelRatio || 1, 2)

    const globe = createGlobe(canvas, {
      devicePixelRatio: dpr,
      width:  width * dpr,
      height: width * dpr,
      phi:    phiRef.current,
      theta:  thetaRef.current,
      dark: 1,
      diffuse: 1.1,
      mapSamples: 20000,
      mapBrightness: 5,
      baseColor:   [0.15, 0.18, 0.25],
      markerColor: [1.0,  0.2,  0.2],
      glowColor:   [0.18, 0.28, 0.55],
      scale: 1.05,
      offset: [0, 0],
      markers,
      onRender(state) {
        if (dragging.current) {
          // Dampen momentum while actively dragging
          velocity.current.x *= 0.6
          velocity.current.y *= 0.6
        } else {
          // Apply momentum (decays each frame)
          velocity.current.x *= 0.95
          velocity.current.y *= 0.95
          phiRef.current   += velocity.current.x
          thetaRef.current += velocity.current.y
          // Auto-rotate slowly when idle
          phiRef.current += 0.003
        }
        // Clamp theta so the globe doesn't flip upside-down
        thetaRef.current = Math.max(-0.6, Math.min(0.6, thetaRef.current))
        state.phi   = phiRef.current
        state.theta = thetaRef.current
      },
    })

    // ── Pointer helpers (unified mouse + touch) ──────────────────
    function getXY(e: MouseEvent | TouchEvent): { x: number; y: number } {
      if ('touches' in e) {
        return { x: e.touches[0].clientX, y: e.touches[0].clientY }
      }
      return { x: e.clientX, y: e.clientY }
    }

    function onDown(e: MouseEvent | TouchEvent) {
      dragging.current = true
      const { x, y } = getXY(e)
      lastPos.current = { x, y }
      velocity.current = { x: 0, y: 0 }
    }

    function onMove(e: MouseEvent | TouchEvent) {
      if (!dragging.current) return
      const { x, y } = getXY(e)
      const dx = x - lastPos.current.x
      const dy = y - lastPos.current.y
      lastPos.current = { x, y }

      // Scale drag pixels → radians; width gives natural feel at any size
      const scale = 4 / width
      phiRef.current   += dx * scale
      thetaRef.current -= dy * scale

      // Record velocity for momentum on release
      velocity.current.x = dx * scale
      velocity.current.y = -dy * scale
    }

    function onUp() {
      dragging.current = false
    }

    // Mouse events
    canvas.addEventListener('mousedown',  onDown)
    window.addEventListener('mousemove',  onMove)
    window.addEventListener('mouseup',    onUp)

    // Touch events
    canvas.addEventListener('touchstart', onDown, { passive: true })
    window.addEventListener('touchmove',  onMove, { passive: true })
    window.addEventListener('touchend',   onUp)

    return () => {
      globe.destroy()
      canvas.removeEventListener('mousedown',  onDown)
      window.removeEventListener('mousemove',  onMove)
      window.removeEventListener('mouseup',    onUp)
      canvas.removeEventListener('touchstart', onDown)
      window.removeEventListener('touchmove',  onMove)
      window.removeEventListener('touchend',   onUp)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [markers.length, width])

  return (
    <canvas
      ref={canvasRef}
      style={{
        width,
        height: width,
        display: 'block',
        cursor: 'grab',
      }}
      onMouseDown={(e) => { e.currentTarget.style.cursor = 'grabbing' }}
      onMouseUp={(e)   => { e.currentTarget.style.cursor = 'grab' }}
    />
  )
}

// ── Country → [lat, lon] lookup ──────────────────────────────────────────────

export const COUNTRY_COORDS: Record<string, [number, number]> = {
  // North America
  'united states': [37.09, -95.71],
  'usa': [37.09, -95.71],
  'us': [37.09, -95.71],
  'canada': [56.13, -106.34],
  'mexico': [23.63, -102.55],

  // Europe
  'united kingdom': [55.37, -3.43],
  'uk': [55.37, -3.43],
  'england': [52.36, -1.17],
  'germany': [51.16, 10.45],
  'france': [46.22, 2.21],
  'italy': [41.87, 12.56],
  'spain': [40.46, -3.74],
  'netherlands': [52.13, 5.29],
  'belgium': [50.50, 4.46],
  'switzerland': [46.81, 8.22],
  'sweden': [60.12, 18.64],
  'norway': [60.47, 8.46],
  'denmark': [56.26, 9.50],
  'finland': [61.92, 25.74],
  'austria': [47.51, 14.55],
  'poland': [51.92, 19.14],
  'czech republic': [49.81, 15.47],
  'czechia': [49.81, 15.47],
  'portugal': [39.39, -8.22],
  'greece': [39.07, 21.82],
  'romania': [45.94, 24.96],
  'ukraine': [48.37, 31.16],
  'hungary': [47.16, 19.50],
  'ireland': [53.14, -7.69],
  'russia': [61.52, 105.31],
  'turkey': [38.96, 35.24],

  // Asia Pacific
  'china': [35.86, 104.19],
  'japan': [36.20, 138.25],
  'south korea': [35.90, 127.76],
  'korea': [35.90, 127.76],
  'india': [20.59, 78.96],
  'australia': [-25.27, 133.77],
  'singapore': [1.35, 103.81],
  'taiwan': [23.69, 120.96],
  'hong kong': [22.39, 114.10],
  'thailand': [15.87, 100.99],
  'indonesia': [-0.78, 113.92],
  'malaysia': [4.21, 101.97],
  'new zealand': [-40.90, 174.88],
  'philippines': [12.87, 121.77],
  'vietnam': [14.05, 108.27],

  // Middle East / Africa
  'israel': [31.04, 34.85],
  'uae': [23.42, 53.84],
  'united arab emirates': [23.42, 53.84],
  'saudi arabia': [23.88, 45.07],
  'iran': [32.42, 53.68],
  'south africa': [-30.55, 22.93],
  'egypt': [26.82, 30.80],
  'nigeria': [9.08, 8.67],
  'kenya': [-0.02, 37.90],

  // Latin America
  'brazil': [-14.23, -51.92],
  'argentina': [-38.41, -63.61],
  'colombia': [4.57, -74.29],
  'chile': [-35.67, -71.54],
  'peru': [-9.18, -75.01],
}

/** Resolve a country string to [lat, lon], case-insensitive. Returns null if unknown. */
export function resolveCountry(country: string): [number, number] | null {
  const key = country.trim().toLowerCase()
  return COUNTRY_COORDS[key] ?? null
}
