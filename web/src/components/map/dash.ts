/**
 * The travelling dash: a short capsule flying once along a source's arc to home. It is an HTML
 * element animated with transform and opacity keyframes computed here, so the compositor runs
 * it without repainting the map (an SVG stroke-dashoffset animation repaints every frame).
 * Pure geometry, in screen pixels.
 */

export type Pt = readonly [number, number]

export const DASH_DURATION = 1_600
/** Length of the dash, as a share of the arc. */
const DASH_SHARE = 0.14
/** Stroke width, px (the caps are half of it at each end). */
export const DASH_THICKNESS = 2.8
/** Opacity holds until this share of the flight, then fades out. */
const FADE_FROM = 0.85

/** CSS `cubic-bezier(x1, y1, x2, y2)` as a function of progress. */
export function cubicBezier(x1: number, y1: number, x2: number, y2: number) {
  const at = (a: number, b: number, t: number) =>
    3 * a * t * (1 - t) ** 2 + 3 * b * t ** 2 * (1 - t) + t ** 3
  return (x: number) => {
    if (x <= 0) return 0
    if (x >= 1) return 1
    let lo = 0
    let hi = 1
    for (let i = 0; i < 40; i++) {
      const mid = (lo + hi) / 2
      if (at(x1, x2, mid) < x) lo = mid
      else hi = mid
    }
    return at(y1, y2, (lo + hi) / 2)
  }
}

/** The flight's easing: quick out of the source, settling into home. */
export const dashEase = cubicBezier(0.22, 1, 0.36, 1)

/** Samples of a quadratic Bézier with their cumulative length, to walk it by arc length. */
function walker(p0: Pt, p1: Pt, p2: Pt, n = 64) {
  const pts: Pt[] = []
  const cum: number[] = []
  let len = 0
  for (let i = 0; i <= n; i++) {
    const t = i / n
    const u = 1 - t
    const p: Pt = [
      u * u * p0[0] + 2 * u * t * p1[0] + t * t * p2[0],
      u * u * p0[1] + 2 * u * t * p1[1] + t * t * p2[1],
    ]
    const prev = pts[i - 1]
    if (prev) len += Math.hypot(p[0] - prev[0], p[1] - prev[1])
    pts.push(p)
    cum.push(len)
  }
  /** The point at `s` (0 to 1) of the length. */
  const at = (s: number): Pt => {
    const target = Math.min(1, Math.max(0, s)) * len
    let i = 1
    while (i < n && (cum[i] ?? 0) < target) i++
    const a = pts[i - 1] ?? p0
    const b = pts[i] ?? p2
    const ca = cum[i - 1] ?? 0
    const cb = cum[i] ?? len
    const k = cb > ca ? (target - ca) / (cb - ca) : 0
    return [a[0] + (b[0] - a[0]) * k, a[1] + (b[1] - a[1]) * k]
  }
  return { len, at }
}

export interface DashTrack {
  /** Width of the element, px: the full dash with its caps. */
  width: number
  keyframes: Keyframe[]
}

/**
 * Keyframes for one flight from `p0` to `p2` (control point `p1`): the same motion as a
 * 14 % dash slid along the path with `stroke-dashoffset` from 0.14 to -1 (it grows out of the
 * source, travels, slides into home), eased, fading over the last 15 %. The element is a
 * capsule `width` wide, its origin at its left middle, placed by the transform.
 */
export function dashTrack(p0: Pt, p1: Pt, p2: Pt, samples = 48): DashTrack {
  const path = walker(p0, p1, p2)
  const cap = DASH_THICKNESS / 2
  const width = DASH_SHARE * path.len + DASH_THICKNESS
  const keyframes: Keyframe[] = []
  let lastAngle: number | null = null
  for (let i = 0; i <= samples; i++) {
    const t = i / samples
    const e = dashEase(t)
    // The dash covers [head - 0.14, head] of the path; only the part on the path shows.
    const head = (1 + DASH_SHARE) * e
    const a = Math.min(1, Math.max(0, head - DASH_SHARE))
    const b = Math.min(1, Math.max(0, head))
    const from = path.at(a)
    const visible = (b - a) * path.len
    // Direction: along the visible piece, or the path's tangent where nothing shows.
    const ahead = visible > 0.01 ? path.at(b) : path.at(Math.min(1, a + 0.01))
    const behind = visible > 0.01 ? from : path.at(Math.max(0, a - 0.01))
    let angle = Math.atan2(ahead[1] - behind[1], ahead[0] - behind[0])
    // Keep the angle continuous, so the rotation never spins between two keyframes.
    if (lastAngle !== null) {
      while (angle - lastAngle > Math.PI) angle -= 2 * Math.PI
      while (angle - lastAngle < -Math.PI) angle += 2 * Math.PI
    }
    lastAngle = angle
    const scale = visible > 0.01 ? (visible + DASH_THICKNESS) / width : 0
    const opacity = t <= FADE_FROM ? 1 : 1 - dashEase((t - FADE_FROM) / (1 - FADE_FROM))
    keyframes.push({
      offset: t,
      transform: `translate(${from[0].toFixed(2)}px, ${from[1].toFixed(2)}px) rotate(${angle.toFixed(4)}rad) translateX(${-cap}px) scaleX(${scale.toFixed(4)})`,
      opacity: +opacity.toFixed(3),
    })
  }
  return { width, keyframes }
}
