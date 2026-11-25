import { House, Maximize2, Minus, Plus, X } from "lucide-react"
import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react"
import { useNavigate } from "react-router"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import type { LiveEvent } from "@/lib/api"
import { countryName, formatNumber } from "@/lib/format"
import { FAMILY_META, SENSOR_META } from "@/lib/sensors"
import { cn } from "@/lib/utils"
import {
  ACTIVE_MS,
  ageOpacity,
  countWeight,
  motionFrozen,
  type Activity,
  type GeoPoint,
  type Source,
} from "./activity"
import worldSvg from "./data/world.svg?url"
import { DASH_DURATION, DASH_THICKNESS, dashTrack } from "./dash"
import { MAP_WIDTH, project } from "./projection"
import { useOnScreen } from "./use-on-screen"

// --- Viewport -----------------------------------------------------------------

interface View {
  cx: number
  cy: number
  /** Visible width in map units. */
  vw: number
}

interface Box {
  x0: number
  y0: number
  x1: number
  y1: number
}

/** The bounding box, in map units, of a set of [lat, lon] points (a region's outermost land). */
function boxOfPoints(points: readonly (readonly [number, number])[]): Box {
  const pts = points.map(([lat, lon]) => project(lat, lon))
  return {
    x0: Math.min(...pts.map((p) => p[0])),
    x1: Math.max(...pts.map((p) => p[0])),
    y0: Math.min(...pts.map((p) => p[1])),
    y1: Math.max(...pts.map((p) => p[1])),
  }
}

/** Everything that can be shown: the whole width, Greenland's tip to Tierra del Fuego. */
const WORLD: Box = { x0: 0, x1: MAP_WIDTH, y0: project(84.2, 0)[1], y1: project(-56.5, 0)[1] }
/**
 * The "World" preset: the full inhabited band, cropped east and west only where there is no land
 * to show (Alaska to Fiji and Chukotka), north to south from Greenland's tip to Tierra del Fuego.
 * On a wide card that is height-limited, so nothing is cut; on a phone it is width-limited and
 * the card is short to match.
 */
const WORLD_FIT: Box = { x0: 130, x1: 950, y0: WORLD.y0, y1: WORLD.y1 }

/** The regions the switch offers, in order. Each is framed from its latitude/longitude bounds. */
export const MAP_PRESETS = [
  "world",
  "europe",
  "north-america",
  "south-america",
  "africa",
  "asia",
  "oceania",
] as const
export type MapPreset = (typeof MAP_PRESETS)[number]

/**
 * Each region is framed from the outermost land it has: a lat/lon rectangle would take in empty
 * ocean in its corners (Equal Earth pinches the poles), a few extreme points do not.
 */
const REGIONS: Record<Exclude<MapPreset, "world">, Box> = {
  // Iceland to Russia's west, Crete to the North Cape.
  europe: boxOfPoints([
    [36, -9.6],
    [65.5, -24.5],
    [71.2, 26],
    [66, 45],
    [45, 45],
    [35, 24.5],
  ]),
  // The Aleutians' tail to Greenland's tip, Panama to the Arctic islands.
  "north-america": boxOfPoints([
    [65, -168],
    [71.4, -156],
    [83.6, -33],
    [81, -12],
    [47, -52.6],
    [7.2, -78],
    [8, -83],
    [16, -105],
    [23, -110],
    [20, -87],
  ]),
  "south-america": boxOfPoints([
    [12.5, -71.5],
    [10.7, -61],
    [-7, -34.8],
    [-55.9, -68],
    [-5, -81.3],
    [-18, -70.4],
  ]),
  africa: boxOfPoints([
    [37.3, 9.8],
    [14.7, -17.5],
    [-34.8, 20],
    [11.8, 51.3],
    [-12.5, 49.3],
    [-25.6, 45],
    [31, 32],
  ]),
  // Anatolia to Kamchatka and Chukotka, the Taymyr to Timor.
  asia: boxOfPoints([
    [40, 26],
    [77.7, 104],
    [66, 179.9],
    [51, 156],
    [12, 43],
    [-10.5, 124],
    [-8.8, 115],
    [5.5, 95],
    [1.3, 103.8],
    [8, 77.5],
  ]),
  // Australia, New Guinea and New Zealand (Fiji at the date line).
  oceania: boxOfPoints([
    [-22, 113.2],
    [-10.7, 142.5],
    [-2.6, 141],
    [-4.5, 152],
    [-28.6, 153.6],
    [-43.6, 146.8],
    [-46.6, 168],
    [-37.5, 178.5],
    [-17, 178],
  ]),
}

function presetBox(p: MapPreset): Box {
  return p === "world" ? WORLD_FIT : REGIONS[p]
}

/** Breathing space kept around the fitted region, in screen px. */
const FIT_MARGIN = 18

/**
 * Fit `box` entirely inside the map area, centred, with `FIT_MARGIN` px of air on every side. The
 * overlays are not in this area (the toolbar sits above it), so nothing hides what is fitted.
 */
function fit(box: Box, size: { w: number; h: number }): View {
  const availW = Math.max(1, size.w - 2 * FIT_MARGIN)
  const availH = Math.max(1, size.h - 2 * FIT_MARGIN)
  const upp = Math.max((box.x1 - box.x0) / availW, (box.y1 - box.y0) / availH)
  return { cx: (box.x0 + box.x1) / 2, cy: (box.y0 + box.y1) / 2, vw: upp * size.w }
}

const MIN_VW = 70

/** Where the view may go: the world plus some air, so a fitted edge region is never pushed back. */
const PAN_X = { lo: -MAP_WIDTH * 0.06, hi: MAP_WIDTH * 1.06 }
const PAN_Y = {
  lo: WORLD.y0 - (WORLD.y1 - WORLD.y0) * 0.1,
  hi: WORLD.y1 + (WORLD.y1 - WORLD.y0) * 0.1,
}

/** Keeps the centre of a view of `span` units inside [lo, hi]; a wider view may overhang. */
function clampAxis(center: number, span: number, lo: number, hi: number, overhang = 0): number {
  const half = Math.min(span, (hi - lo) * (1 - overhang)) / 2
  return Math.min(hi - half, Math.max(lo + half, center))
}

function clampView(v: View, aspect: number): View {
  // Zoomed all the way out, the whole map fits with its air.
  const maxVw = Math.max(PAN_X.hi - PAN_X.lo, (PAN_Y.hi - PAN_Y.lo) * aspect)
  const vw = Math.min(maxVw, Math.max(MIN_VW, v.vw))
  const vh = vw / aspect
  return {
    // On a wide card a tall region is narrower than the view: it may sit off-centre in it.
    cx: clampAxis(v.cx, vw, PAN_X.lo, PAN_X.hi, 0.5),
    cy: vh >= PAN_Y.hi - PAN_Y.lo ? (PAN_Y.lo + PAN_Y.hi) / 2 : clampAxis(v.cy, vh, PAN_Y.lo, PAN_Y.hi),
    vw,
  }
}

const PRESET_KEY = "suckerpot.map.preset"
/** Tells the other map (the expanded one, the inline one) that the choice changed. */
const PRESET_EVENT = "suckerpot:map-preset"

function storedPreset(): MapPreset {
  try {
    // World is the default; the older two-value choice ("world" or "europe") reads as is.
    const v = localStorage.getItem(PRESET_KEY)
    return MAP_PRESETS.find((p) => p === v) ?? "world"
  } catch {
    return "world"
  }
}

function presetLabel(p: MapPreset): string {
  switch (p) {
    case "world":
      return t("map_preset_world")
    case "europe":
      return t("map_preset_europe")
    case "north-america":
      return t("map_preset_north_america")
    case "south-america":
      return t("map_preset_south_america")
    case "africa":
      return t("map_preset_africa")
    case "asia":
      return t("map_preset_asia")
    case "oceania":
      return t("map_preset_oceania")
  }
}

// --- Geometry -------------------------------------------------------------------

/** Control point of the arc from the source to home, bowing north. Null for the same point. */
function arcControl(from: [number, number], to: [number, number]): [number, number] | null {
  const dx = to[0] - from[0]
  const dy = to[1] - from[1]
  const len = Math.hypot(dx, dy)
  if (len < 0.6) return null
  // Perpendicular, pointing up (towards smaller y).
  let px = -dy / len
  let py = dx / len
  if (py > 0) {
    px = -px
    py = -py
  }
  const bow = Math.min(len * 0.22, 60)
  return [(from[0] + to[0]) / 2 + px * bow, (from[1] + to[1]) / 2 + py * bow]
}

/** A gentle quadratic curve from the source to home, bowing north. Null for the same point. */
function arcPath(from: [number, number], to: [number, number]): string | null {
  const c = arcControl(from, to)
  if (!c) return null
  const f = (n: number) => n.toFixed(2)
  return `M${f(from[0])} ${f(from[1])}Q${f(c[0])} ${f(c[1])} ${f(to[0])} ${f(to[1])}`
}

/** Screen radius (px) of a source dot. */
const dotRadius = (events: number) => 3 + 5 * countWeight(events)

interface Dash {
  key: number
  country: string
  /** performance.now() at launch: a dash redrawn mid-flight (pan, zoom) resumes where it was. */
  born: number
}

const MAX_DASHES = 14
const DASH_MS = 1_700

// --- Component -------------------------------------------------------------------

interface WorldMapProps {
  activity: Activity
  /** Newest first; only used to spot new events for the travelling dash. */
  events: readonly LiveEvent[]
  home: GeoPoint
  homeLabel?: string | undefined
  paused: boolean
  now: number
  /** Country (ISO code) highlighted from outside: its arc stands out, the others step back. */
  focus?: string | null
  /** Hover or keyboard focus on a source dot. */
  onFocusChange?: (country: string | null) => void
  /** Content for the left of the toolbar above the map (the stats strip). */
  topLeft?: React.ReactNode
  /** Shows the "expand" button, which calls this with the button (to give focus back to). */
  onExpand?: (opener: HTMLElement) => void
  /** In the expanded view: shows a close button, which calls this. */
  onClose?: () => void
  /** Another map is shown over this one: stop its pulses and dashes. */
  dormant?: boolean
  className?: string
}

/**
 * The flat attack map (Equal Earth). Recent sources stay on screen as arcs to
 * home, thicker for more events and fading with age; a new event sends one
 * short dash along its arc. Wheel, drag, pinch and the keyboard pan and zoom.
 */
export const WorldMap = memo(function WorldMap({
  activity,
  events,
  home,
  homeLabel,
  paused,
  now,
  focus = null,
  onFocusChange,
  topLeft,
  onExpand,
  onClose,
  dormant = false,
  className,
}: WorldMapProps) {
  const reduced = useReducedMotion()
  const still = reduced || motionFrozen()
  const navigate = useNavigate()
  const hostRef = useRef<HTMLDivElement>(null)
  // Pulses and dashes run only while someone can see them.
  const onScreen = useOnScreen(hostRef)
  const animate = !still && onScreen && !dormant
  const [size, setSize] = useState({ w: 800, h: 450 })
  const aspect = size.w / Math.max(1, size.h)
  const [preset, setPreset] = useState<MapPreset>(storedPreset)
  const [view, setView] = useState<View | null>(null)
  const anim = useRef<number | null>(null)

  // Measure, and fit the preset on first layout and whenever the shape changes.
  useLayoutEffect(() => {
    const el = hostRef.current
    if (!el) return
    const measure = () => {
      const w = el.clientWidth
      const h = el.clientHeight
      if (w > 0 && h > 0) setSize((s) => (s.w === w && s.h === h ? s : { w, h }))
    }
    measure()
    if (typeof ResizeObserver === "undefined") return
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  const [fittedFor, setFittedFor] = useState<string | null>(null)
  const fitKey = `${size.w}x${size.h}`
  if (fittedFor !== fitKey) {
    setFittedFor(fitKey)
    setView(clampView(fit(presetBox(preset), size), aspect))
  }
  const v = view ?? fit(presetBox(preset), size)

  const stopAnim = () => {
    if (anim.current !== null) cancelAnimationFrame(anim.current)
    anim.current = null
  }
  const animateTo = useCallback(
    (target: View) => {
      stopAnim()
      const to = clampView(target, aspect)
      if (still) {
        setView(to)
        return
      }
      const from = view ?? to
      const start = performance.now()
      const step = (now: number) => {
        const k = Math.min(1, (now - start) / 520)
        const e = 1 - (1 - k) ** 3
        setView({
          cx: from.cx + (to.cx - from.cx) * e,
          cy: from.cy + (to.cy - from.cy) * e,
          vw: Math.exp(Math.log(from.vw) + (Math.log(to.vw) - Math.log(from.vw)) * e),
        })
        anim.current = k < 1 ? requestAnimationFrame(step) : null
      }
      anim.current = requestAnimationFrame(step)
    },
    [aspect, still, view],
  )
  useEffect(() => stopAnim, [])

  const choosePreset = (p: MapPreset) => {
    setPreset(p)
    try {
      localStorage.setItem(PRESET_KEY, p)
    } catch {
      // Private mode: the choice just isn't remembered.
    }
    animateTo(fit(presetBox(p), size))
    window.dispatchEvent(new Event(PRESET_EVENT))
  }
  // The other map (inline or expanded) changed region: follow it, without a tween when hidden.
  const followRef = useRef<() => void>(() => {})
  useEffect(() => {
    followRef.current = () => {
      const p = storedPreset()
      if (p === preset) return
      setPreset(p)
      stopAnim()
      setView(clampView(fit(presetBox(p), size), aspect))
    }
  })
  useEffect(() => {
    const onChange = () => followRef.current()
    window.addEventListener(PRESET_EVENT, onChange)
    return () => window.removeEventListener(PRESET_EVENT, onChange)
  }, [])
  const zoomBy = (factor: number, at?: { x: number; y: number }) => {
    stopAnim()
    setView((cur) => {
      const c = cur ?? v
      const upp = c.vw / size.w
      const px = at?.x ?? size.w / 2
      const py = at?.y ?? size.h / 2
      const mx = c.cx + (px - size.w / 2) * upp
      const my = c.cy + (py - size.h / 2) * upp
      const vw = c.vw * factor
      const upp2 = vw / size.w
      return clampView(
        { cx: mx - (px - size.w / 2) * upp2, cy: my - (py - size.h / 2) * upp2, vw },
        aspect,
      )
    })
  }
  const panBy = (dxPx: number, dyPx: number) => {
    stopAnim()
    setView((cur) => {
      const c = cur ?? v
      const upp = c.vw / size.w
      return clampView({ cx: c.cx - dxPx * upp, cy: c.cy - dyPx * upp, vw: c.vw }, aspect)
    })
  }

  // Wheel zoom needs a non-passive listener to keep the page still.
  const zoomRef = useRef(zoomBy)
  useEffect(() => {
    zoomRef.current = zoomBy
  })
  useEffect(() => {
    const el = hostRef.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const r = el.getBoundingClientRect()
      zoomRef.current(Math.exp(e.deltaY * 0.0016), { x: e.clientX - r.left, y: e.clientY - r.top })
    }
    el.addEventListener("wheel", onWheel, { passive: false })
    return () => el.removeEventListener("wheel", onWheel)
  }, [])

  // Drag to pan, two fingers to pinch.
  const pointers = useRef(new Map<number, { x: number; y: number }>())
  const moved = useRef(0)
  const onPointerDown = (e: React.PointerEvent) => {
    if (e.button !== 0) return
    pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY })
    moved.current = 0
  }
  const onPointerMove = (e: React.PointerEvent) => {
    const prev = pointers.current.get(e.pointerId)
    if (!prev) return
    const next = { x: e.clientX, y: e.clientY }
    if (pointers.current.size === 1) {
      const dx = next.x - prev.x
      const dy = next.y - prev.y
      moved.current += Math.abs(dx) + Math.abs(dy)
      if (moved.current > 4) {
        if (!hostRef.current?.hasPointerCapture(e.pointerId))
          hostRef.current?.setPointerCapture(e.pointerId)
        panBy(dx, dy)
      }
    } else if (pointers.current.size === 2) {
      const others = [...pointers.current.entries()].filter(([id]) => id !== e.pointerId)
      const other = others[0]?.[1]
      if (other) {
        const before = Math.hypot(prev.x - other.x, prev.y - other.y)
        const after = Math.hypot(next.x - other.x, next.y - other.y)
        const r = hostRef.current?.getBoundingClientRect()
        if (before > 0 && after > 0 && r) {
          moved.current += 10
          zoomBy(before / after, {
            x: (next.x + other.x) / 2 - r.left,
            y: (next.y + other.y) / 2 - r.top,
          })
        }
      }
    }
    pointers.current.set(e.pointerId, next)
  }
  const onPointerUp = (e: React.PointerEvent) => {
    pointers.current.delete(e.pointerId)
  }
  const onKeyDown = (e: React.KeyboardEvent) => {
    const step = 60
    const keys: Record<string, () => void> = {
      ArrowLeft: () => panBy(step, 0),
      ArrowRight: () => panBy(-step, 0),
      ArrowUp: () => panBy(0, step),
      ArrowDown: () => panBy(0, -step),
      "+": () => zoomBy(0.7),
      "=": () => zoomBy(0.7),
      "-": () => zoomBy(1 / 0.7),
      "0": () => choosePreset("world"),
      e: () => choosePreset("europe"),
    }
    const fn = keys[e.key]
    if (fn && e.target === e.currentTarget) {
      e.preventDefault()
      fn()
    }
  }

  // New events: one dash each along their source's arc (capped, calm).
  const [dashes, setDashes] = useState<Dash[]>([])
  const lastId = useRef<number | null>(null)
  // A dash leaves when its flight is over, even if the map stopped animating in between.
  const dashTimers = useRef(new Set<ReturnType<typeof setTimeout>>())
  useEffect(() => {
    const timers = dashTimers.current
    return () => {
      for (const timer of timers) clearTimeout(timer)
    }
  }, [])
  useEffect(() => {
    const newest = events[0]?.id ?? 0
    if (lastId.current === null) {
      lastId.current = newest
      return
    }
    const since = lastId.current
    lastId.current = Math.max(since, newest)
    if (!animate || paused) return
    const fresh = events
      .filter((e) => e.id > since && e.country)
      .slice(0, 4)
      .flatMap((e) => {
        const src = activity.sources.find((s) => s.country === e.country?.toUpperCase())
        return src ? [{ key: e.id, country: src.country, born: performance.now() }] : []
      })
    if (!fresh.length) return
    setDashes((d) => [...d, ...fresh].slice(-MAX_DASHES))
    const timer = setTimeout(() => {
      dashTimers.current.delete(timer)
      setDashes((d) => d.filter((x) => !fresh.some((f) => f.key === x.key)))
    }, DASH_MS)
    dashTimers.current.add(timer)
  }, [events, animate, paused, activity.sources])

  // Hovered or keyboard-focused dot (local), else the highlight asked for from outside.
  const [hover, setHover] = useState<string | null>(null)
  const enter = (country: string) => {
    setHover(country)
    onFocusChange?.(country)
  }
  const leave = (country: string) => {
    setHover((h) => (h === country ? null : h))
    onFocusChange?.(null)
  }
  const lit = hover ?? focus

  const homeXY = useMemo(() => project(home.lat, home.lon), [home.lat, home.lon])
  const upp = v.vw / size.w
  const vh = v.vw / aspect
  const toScreen = (p: [number, number]) => ({
    x: (p[0] - (v.cx - v.vw / 2)) / upp,
    y: (p[1] - (v.cy - vh / 2)) / upp,
  })

  const drawn = useMemo(() => {
    const all = activity.sources.map((s) => {
      const xy = project(s.point.lat, s.point.lon)
      return { s, xy, d: arcPath(xy, homeXY) }
    })
    // Quietest first, so the busiest arcs and dots sit on top; the highlighted one last of all.
    all.reverse()
    if (lit) {
      const i = all.findIndex((x) => x.s.country === lit)
      const [hit] = i >= 0 ? all.splice(i, 1) : []
      if (hit) all.push(hit)
    }
    return all
  }, [activity.sources, homeXY, lit])
  const tipped = lit ? drawn.find((x) => x.s.country === lit) : undefined
  const dim = (country: string) => (lit && lit !== country ? 0.28 : 1)

  const viewBox = `${v.cx - v.vw / 2} ${v.cy - vh / 2} ${v.vw} ${vh}`
  const homeScreen = toScreen(homeXY)
  const onMap = (p: { x: number; y: number }, margin: number) =>
    p.x >= -margin && p.y >= -margin && p.x <= size.w + margin && p.y <= size.h + margin

  // Dashes in flight, in screen pixels.
  const flights: Flight[] = []
  if (animate) {
    for (const dash of dashes) {
      const hit = drawn.find((x) => x.s.country === dash.country)
      const c = hit ? arcControl(hit.xy, homeXY) : null
      if (!hit || !c) continue
      const p0 = toScreen(hit.xy)
      const p1 = toScreen(c)
      flights.push({
        key: dash.key,
        born: dash.born,
        color: FAMILY_META[hit.s.family].cssVar,
        x0: p0.x,
        y0: p0.y,
        x1: p1.x,
        y1: p1.y,
        x2: homeScreen.x,
        y2: homeScreen.y,
      })
    }
  }

  // Active sources (an event in the last minute) pulse; only those in view get a ring.
  const pulses: Pulse[] = []
  if (animate) {
    for (const s of activity.sources) {
      if (now - s.last >= ACTIVE_MS) continue
      const p = toScreen(project(s.point.lat, s.point.lon))
      const r = dotRadius(s.events)
      if (!onMap(p, r * PULSE_SCALE)) continue
      pulses.push({
        key: s.country,
        x: p.x,
        y: p.y,
        r,
        color: FAMILY_META[s.family].cssVar,
        opacity: dim(s.country),
      })
    }
  }

  const open = (s: Source) => void navigate(`/attacks?country=${s.country}`)
  const homeName = homeLabel ?? t("map_home")
  const homeLabelW = 26 + homeName.length * 6.6

  return (
    <div className={cn("flex size-full min-h-0 flex-col", className)}>
      {/* The bar is above the map, not over it: no land ever hides under a control. */}
      <div className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1.5 px-2.5 pt-2.5 pb-1 sm:px-3">
        <div className="min-w-0">{topLeft}</div>
        <div className="ml-auto flex max-w-full min-w-0 items-center gap-1">
          <RegionSwitch preset={preset} onChoose={choosePreset} />
          <div className="flex shrink-0 rounded-md border bg-surface-raised p-0.5 shadow-sm">
            <button
              type="button"
              aria-label={t("map_zoom_in")}
              onClick={() => zoomBy(0.7)}
              className="flex size-6 items-center justify-center rounded-sm text-fg-muted hover:text-fg"
            >
              <Plus aria-hidden className="size-3.5" />
            </button>
            <button
              type="button"
              aria-label={t("map_zoom_out")}
              onClick={() => zoomBy(1 / 0.7)}
              className="flex size-6 items-center justify-center rounded-sm text-fg-muted hover:text-fg"
            >
              <Minus aria-hidden className="size-3.5" />
            </button>
          </div>
          {onExpand || onClose ? (
            <div className="flex shrink-0 rounded-md border bg-surface-raised p-0.5 shadow-sm">
              <button
                type="button"
                aria-label={onClose ? t("common_close") : t("map_expand")}
                onClick={(e) => (onClose ? onClose() : onExpand?.(e.currentTarget))}
                className="flex size-6 items-center justify-center rounded-sm text-fg-muted hover:text-fg"
              >
                {onClose ? (
                  <X aria-hidden className="size-3.5" />
                ) : (
                  <Maximize2 aria-hidden className="size-3.5" />
                )}
              </button>
            </div>
          ) : null}
        </div>
      </div>
      <div
        ref={hostRef}
        className="relative min-h-0 flex-1 touch-pan-y overflow-hidden outline-none select-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
        tabIndex={0}
        role="group"
        aria-roledescription="map"
        aria-label={t("map_aria", { home: homeLabel ?? t("map_home_sensors") })}
        onKeyDown={onKeyDown}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
      >
        <BaseLayer viewBox={viewBox} />
        <ArcLayer viewBox={viewBox} drawn={drawn} lit={lit} now={now} />
        {animate ? <DashLayer flights={flights} /> : null}
        {animate ? <PulseLayer pulses={pulses} home={homeScreen} /> : null}
        <DotLayer viewBox={viewBox} drawn={drawn} lit={lit} now={now} upp={upp} home={homeXY} />

        {/* Hit targets for the sources: real buttons, so they are focusable and clickable. */}
        {drawn.map(({ s, xy }) => {
          const p = toScreen(xy)
          if (!onMap(p, 10)) return null
          const name = countryName(s.country) ?? s.country
          return (
            <button
              key={`hit-${s.country}`}
              type="button"
              className="absolute size-7 -translate-x-1/2 -translate-y-1/2 rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring"
              style={{ left: p.x, top: p.y }}
              aria-label={t("map_source_aria", { name, events: s.events, ips: s.ips })}
              onPointerEnter={() => enter(s.country)}
              onPointerLeave={() => leave(s.country)}
              onFocus={() => enter(s.country)}
              onBlur={() => leave(s.country)}
              onClick={() => {
                if (moved.current <= 4) open(s)
              }}
            />
          )
        })}

        {/*
          Labels: home first, then the busiest visible sources. Each label tries the right of its
          dot, then the left, above, below and the diagonals; it is skipped only when all collide (around
          home at World scale), so the busiest neighbours keep theirs.
        */}
        {(() => {
          const placed: Box[] = [
            {
              x0: homeScreen.x - 10,
              y0: homeScreen.y - 10,
              x1: homeScreen.x + 12 + homeLabelW,
              y1: homeScreen.y + 10,
            },
          ]
          return activity.sources.slice(0, 12).flatMap((s) => {
            const xy = project(s.point.lat, s.point.lon)
            const p = toScreen(xy)
            const text = `${s.country} ${formatNumber(s.events)}`
            const w = 10 + text.length * 6.6
            const r = dotRadius(s.events)
            // Busiest first: a label may cover a quieter dot (still clickable under it), never a
            // busier one, so the leading sources get their labels first.
            placed.push({ x0: p.x - r - 1, y0: p.y - r - 1, x1: p.x + r + 1, y1: p.y + r + 1 })
            const candidates: Box[] = [
              { x0: p.x + r + 4, y0: p.y - 9, x1: p.x + r + 4 + w, y1: p.y + 9 },
              { x0: p.x - r - 4 - w, y0: p.y - 9, x1: p.x - r - 4, y1: p.y + 9 },
              { x0: p.x - w / 2, y0: p.y - r - 22, x1: p.x + w / 2, y1: p.y - r - 4 },
              { x0: p.x - w / 2, y0: p.y + r + 4, x1: p.x + w / 2, y1: p.y + r + 22 },
              // Diagonals, for the tight cluster around home at World scale.
              { x0: p.x + r, y0: p.y - r - 20, x1: p.x + r + w, y1: p.y - r - 2 },
              { x0: p.x - r - w, y0: p.y - r - 20, x1: p.x - r, y1: p.y - r - 2 },
              { x0: p.x + r, y0: p.y + r + 2, x1: p.x + r + w, y1: p.y + r + 20 },
              { x0: p.x - r - w, y0: p.y + r + 2, x1: p.x - r, y1: p.y + r + 20 },
            ]
            const box = candidates.find(
              (c) =>
                c.x0 >= 0 &&
                c.y0 >= 0 &&
                c.x1 <= size.w - 4 &&
                c.y1 <= size.h - 4 &&
                !placed.some((b) => b.x0 < c.x1 && c.x0 < b.x1 && b.y0 < c.y1 && c.y0 < b.y1),
            )
            if (!box) return []
            placed.push(box)
            return [
              <span
                key={`label-${s.country}`}
                aria-hidden
                className={cn(
                  "pointer-events-none absolute flex h-[18px] items-center rounded-xs bg-surface/85 px-1 font-mono text-2xs text-fg-muted transition-opacity duration-200",
                  lit && lit !== s.country && "opacity-30",
                )}
                style={{ left: box.x0, top: box.y0 }}
              >
                <span className="font-medium text-fg">{s.country}</span>&nbsp;
                {formatNumber(s.events)}
              </span>,
            ]
          })
        })()}

        <span
          className="pointer-events-none absolute flex h-5 items-center gap-1 rounded-sm border border-border-strong bg-surface-raised/90 px-1.5 text-2xs font-medium text-fg shadow-sm"
          style={{ left: homeScreen.x + 12, top: homeScreen.y - 10 }}
        >
          <House aria-hidden className="size-3 text-fg-muted" strokeWidth={2} />
          {homeName}
        </span>

        {tipped ? (
          <SourceTooltip
            source={tipped.s}
            at={toScreen(tipped.xy)}
            homeX={homeScreen.x}
            size={size}
          />
        ) : null}

      </div>
    </div>
  )
})

/** The region switch: one pressed button, scrollable sideways when the bar is narrow. */
function RegionSwitch({
  preset,
  onChoose,
}: {
  preset: MapPreset
  onChoose: (p: MapPreset) => void
}) {
  const ref = useRef<HTMLDivElement>(null)
  // Keep the pressed region in view when the row scrolls (a phone, a narrow card).
  useEffect(() => {
    const row = ref.current
    const on = row?.querySelector<HTMLElement>("[aria-pressed=true]")
    if (!row || !on) return
    const left = on.offsetLeft - (row.clientWidth - on.offsetWidth) / 2
    row.scrollTo?.({ left, behavior: "auto" })
  }, [preset])
  return (
    <div
      ref={ref}
      role="group"
      aria-label={t("map_regions_aria")}
      className="relative flex min-w-0 overflow-x-auto rounded-md border bg-surface-raised p-0.5 shadow-sm [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
    >
      {MAP_PRESETS.map((p) => (
        <button
          key={p}
          type="button"
          aria-pressed={preset === p}
          onClick={() => onChoose(p)}
          className={cn(
            "h-6 shrink-0 rounded-sm px-2 text-xs font-medium whitespace-nowrap transition-colors",
            preset === p ? "bg-surface-hover text-fg" : "text-fg-muted hover:text-fg",
          )}
        >
          {presetLabel(p)}
        </button>
      ))}
    </div>
  )
}

function SourceTooltip({
  source,
  at,
  homeX,
  size,
}: {
  source: Source
  at: { x: number; y: number }
  homeX: number
  size: { w: number; h: number }
}) {
  const name = countryName(source.country) ?? source.country
  const W = 232
  // On the side away from home, so the lit arc stays in view.
  const roomRight = at.x + 16 + W < size.w
  const roomLeft = at.x - 16 - W > 0
  const left = (at.x < homeX && roomLeft) || !roomRight ? Math.max(8, at.x - 16 - W) : at.x + 16
  const top = Math.min(Math.max(0, at.y - 16), Math.max(0, size.h - 132))
  return (
    <div
      role="tooltip"
      className="pointer-events-none absolute z-10 w-58 animate-fade-in rounded-md border bg-surface-raised p-3 text-xs shadow-md"
      style={{ left, top }}
    >
      <p className="font-medium text-fg">
        {name}
        <span className="font-normal text-fg-subtle"> · {t("map_tooltip_window")}</span>
      </p>
      <p className="mt-1 text-fg-muted">
        {tNodes(
          "map_tooltip_counts",
          { events: source.events, ips: source.ips },
          {
            eventsN: (
              <span className="font-medium text-fg tabular-nums">{formatNumber(source.events)}</span>
            ),
            ipsN: (
              <span className="font-medium text-fg tabular-nums">{formatNumber(source.ips)}</span>
            ),
          },
        )}
      </p>
      <p className="mt-1.5 flex flex-wrap gap-x-2 gap-y-1 text-fg-muted">
        {source.sensors.map((s) => {
          const m = SENSOR_META[s]
          return (
            <span key={s} className="inline-flex items-center gap-1">
              <m.icon aria-hidden className={cn("size-3", m.text)} />
              {m.label}
            </span>
          )
        })}
      </p>
      <p className="mt-1.5 text-fg-subtle">{t("map_tooltip_open")}</p>
    </div>
  )
}

// --- Layers ---------------------------------------------------------------------
//
// The map is a stack of layers, each on its own compositing layer (will-change), so what moves
// repaints only itself: the land and borders are drawn once per view, the arcs and dots when the
// data changes, the dashes while one flies, and the pulses never (HTML rings animated with
// transform and opacity only, which the compositor runs off the main thread).

const LAYER = "absolute inset-0 size-full will-change-transform"

interface Drawn {
  s: Source
  xy: [number, number]
  d: string | null
}

/** Land and borders, from the static `world.svg` asset (kept out of the JS bundle). */
const BaseLayer = memo(function BaseLayer({ viewBox }: { viewBox: string }) {
  return (
    <svg className={LAYER} viewBox={viewBox} preserveAspectRatio="xMidYMid meet" aria-hidden>
      <use href={`${worldSvg}#land`} fill="var(--map-land)" />
      <use href={`${worldSvg}#borders`} stroke="var(--map-border)" />
    </svg>
  )
})

const ArcLayer = memo(function ArcLayer({
  viewBox,
  drawn,
  lit,
  now,
}: {
  viewBox: string
  drawn: readonly Drawn[]
  lit: string | null
  now: number
}) {
  return (
    <svg className={LAYER} viewBox={viewBox} preserveAspectRatio="xMidYMid meet" aria-hidden>
      {drawn.map(({ s, d }) =>
        d ? (
          <path
            key={`arc-${s.country}`}
            d={d}
            fill="none"
            stroke={FAMILY_META[s.family].cssVar}
            strokeOpacity={
              lit === s.country
                ? 1
                : 0.8 * ageOpacity(s.last, now) * (lit && lit !== s.country ? 0.28 : 1)
            }
            strokeWidth={1.2 + 2.6 * countWeight(s.events) + (lit === s.country ? 1 : 0)}
            strokeLinecap="round"
            vectorEffect="non-scaling-stroke"
            className="transition-[stroke-opacity] duration-200"
          />
        ) : null,
      )}
    </svg>
  )
})

interface Flight {
  key: number
  born: number
  color: string
  /** Source, control point and home, screen px. */
  x0: number
  y0: number
  x1: number
  y1: number
  x2: number
  y2: number
}

function DashLayer({ flights }: { flights: readonly Flight[] }) {
  return (
    <div className="pointer-events-none absolute inset-0" aria-hidden data-map-dashes>
      {flights.map(({ key, ...f }) => (
        <DashFlight key={key} {...f} />
      ))}
    </div>
  )
}

/** One dash: transform and opacity keyframes only (see `dash.ts`), run by the compositor. */
const DashFlight = memo(function DashFlight({
  born,
  color,
  x0,
  y0,
  x1,
  y1,
  x2,
  y2,
}: Omit<Flight, "key">) {
  const ref = useRef<HTMLSpanElement>(null)
  const track = useMemo(() => dashTrack([x0, y0], [x1, y1], [x2, y2]), [x0, y0, x1, y1, x2, y2])
  useLayoutEffect(() => {
    const el = ref.current
    if (!el || typeof el.animate !== "function") return
    const flight = el.animate(track.keyframes, { duration: DASH_DURATION, fill: "both" })
    flight.currentTime = Math.min(DASH_DURATION, Math.max(0, performance.now() - born))
    return () => flight.cancel()
  }, [track, born])
  return (
    <span
      ref={ref}
      className="absolute top-0 left-0 rounded-full opacity-0"
      style={{
        width: track.width,
        height: DASH_THICKNESS,
        marginTop: -DASH_THICKNESS / 2,
        transformOrigin: `0 ${DASH_THICKNESS / 2}px`,
        background: color,
      }}
    />
  )
})

/** How far a pulse ring grows, in dot radii (the `map-pulse` keyframes start at 1 / this). */
const PULSE_SCALE = 2.8

interface Pulse {
  key: string
  /** Screen position and dot radius, px. */
  x: number
  y: number
  r: number
  color: string
  opacity: number
}

/**
 * Rings around active sources and home. Each ring is drawn at its largest size with a 1 px
 * border and shrunk to the dot by the animation, so the line never gets thicker than 1 px.
 */
function PulseLayer({
  pulses,
  home,
}: {
  pulses: readonly Pulse[]
  home: { x: number; y: number }
}) {
  const ring = (key: string, x: number, y: number, r: number, color: string, opacity = 1) => {
    const size = 2 * r * PULSE_SCALE + 1
    return (
      <span
        key={key}
        className="absolute transition-opacity duration-200"
        style={{ left: x, top: y, opacity }}
      >
        <span
          className="absolute block animate-map-pulse rounded-full border"
          style={{
            width: size,
            height: size,
            left: -size / 2,
            top: -size / 2,
            borderColor: color,
          }}
        />
      </span>
    )
  }
  return (
    <div className="pointer-events-none absolute inset-0" aria-hidden data-map-pulses>
      {pulses.map((p) => ring(p.key, p.x, p.y, p.r, p.color, p.opacity))}
      {ring("home", home.x, home.y, 5, "var(--fg)")}
    </div>
  )
}

const DotLayer = memo(function DotLayer({
  viewBox,
  drawn,
  lit,
  now,
  upp,
  home,
}: {
  viewBox: string
  drawn: readonly Drawn[]
  lit: string | null
  now: number
  /** Map units per screen pixel: dots keep their screen size at every zoom. */
  upp: number
  home: [number, number]
}) {
  return (
    <svg className={LAYER} viewBox={viewBox} preserveAspectRatio="xMidYMid meet" aria-hidden>
      {drawn.map(({ s, xy }) => (
        <circle
          key={`src-${s.country}`}
          cx={xy[0]}
          cy={xy[1]}
          r={dotRadius(s.events) * upp}
          fill={FAMILY_META[s.family].cssVar}
          fillOpacity={0.4 + 0.6 * ageOpacity(s.last, now)}
          stroke={lit === s.country ? "var(--fg)" : "var(--surface)"}
          strokeWidth={lit === s.country ? 1.5 : 1}
          vectorEffect="non-scaling-stroke"
          opacity={lit && lit !== s.country ? 0.28 : 1}
          className="transition-opacity duration-200"
        />
      ))}
      {/* Home: a ring and a solid dot (its pulse is in the pulse layer), always on top. */}
      <circle
        cx={home[0]}
        cy={home[1]}
        r={8 * upp}
        fill="none"
        stroke="var(--fg)"
        strokeOpacity={0.5}
        strokeWidth={1}
        vectorEffect="non-scaling-stroke"
      />
      <circle
        cx={home[0]}
        cy={home[1]}
        r={4 * upp}
        fill="var(--fg)"
        stroke="var(--surface)"
        strokeWidth={1.5}
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
})
