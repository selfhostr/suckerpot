import { describe, expect, it } from "vitest"
import { DASH_THICKNESS, cubicBezier, dashEase, dashTrack } from "./dash"

/** translate(x, y), rotate(rad) and scaleX out of a keyframe's transform. */
function parse(frame: Keyframe) {
  const t = String(frame.transform)
  const n = (re: RegExp) => Number(re.exec(t)?.[1])
  const xy = /translate\(([-\d.]+)px, ([-\d.]+)px\)/.exec(t)
  return {
    x: Number(xy?.[1]),
    y: Number(xy?.[2]),
    angle: n(/rotate\(([-\d.]+)rad\)/),
    scale: n(/scaleX\(([-\d.]+)\)/),
    opacity: Number(frame.opacity),
  }
}

describe("cubicBezier", () => {
  it("matches the ends and the linear curve", () => {
    const linear = cubicBezier(0.25, 0.25, 0.75, 0.75)
    expect(linear(0)).toBe(0)
    expect(linear(1)).toBe(1)
    expect(linear(0.3)).toBeCloseTo(0.3, 4)
  })

  it("eases out: most of the way is covered early", () => {
    expect(dashEase(0.25)).toBeGreaterThan(0.6)
    expect(dashEase(0.5)).toBeGreaterThan(dashEase(0.25))
  })
})

describe("dashTrack", () => {
  // A straight flight 200 px to the right (the control point on the line).
  const track = dashTrack([0, 0], [100, 0], [200, 0], 40)
  const frames = track.keyframes.map(parse)

  it("is a 14 % dash with its round caps", () => {
    expect(track.width).toBeCloseTo(0.14 * 200 + DASH_THICKNESS, 1)
    expect(track.keyframes[0]?.offset).toBe(0)
    expect(track.keyframes.at(-1)?.offset).toBe(1)
  })

  it("grows out of the source, travels and slides into home", () => {
    const first = frames[0]
    const last = frames.at(-1)
    // Nothing shows at either end of the flight.
    expect(first?.scale).toBe(0)
    expect(last?.scale).toBe(0)
    expect(first?.x).toBeCloseTo(0, 1)
    expect(last?.x).toBeCloseTo(200, 1)
    // In between it moves forward only, pointing along the path, never longer than the dash.
    for (let i = 1; i < frames.length; i++) {
      const f = frames[i]
      const prev = frames[i - 1]
      if (!f || !prev) continue
      expect(f.x).toBeGreaterThanOrEqual(prev.x - 1e-6)
      expect(f.scale).toBeLessThanOrEqual(1 + 1e-6)
      expect(Math.abs(f.angle)).toBeLessThan(1e-3)
    }
    expect(frames.some((f) => f.scale > 0.99)).toBe(true)
  })

  it("holds full opacity, then fades out over the last 15 %", () => {
    for (const f of track.keyframes) {
      const o = Number(f.opacity)
      if (Number(f.offset) <= 0.85) expect(o).toBe(1)
    }
    expect(frames.at(-1)?.opacity).toBe(0)
  })

  it("keeps the rotation continuous on a curve", () => {
    const curved = dashTrack([0, 100], [100, -50], [200, 100]).keyframes.map(parse)
    for (let i = 1; i < curved.length; i++) {
      const a = curved[i - 1]?.angle ?? 0
      const b = curved[i]?.angle ?? 0
      expect(Math.abs(b - a)).toBeLessThan(Math.PI / 2)
    }
    // Climbing at first (negative y is up), coming down at the end.
    expect(curved[2]?.angle).toBeLessThan(0)
    expect(curved.at(-2)?.angle).toBeGreaterThan(0)
  })
})
