// @vitest-environment node
/// <reference types="node" />
import { readFileSync } from "node:fs"
import { blend, contrastRatio, parseHex, readTokenBlock } from "@/lib/contrast"
import { FAMILY_META, SENSOR_FAMILIES, SENSORS } from "@/lib/sensors"

const css = readFileSync("src/styles/tokens.css", "utf8")

const themes = {
  dark: readTokenBlock(css, ':root,\n[data-theme="dark"]'),
  light: readTokenBlock(css, '[data-theme="light"] {'),
}

const SURFACES = ["bg", "surface", "surface-hover"] as const
const BODY_TEXT = ["fg", "fg-muted", "fg-subtle"] as const
const HUES = [
  "family-shell",
  "family-web",
  "family-data",
  "family-windows",
  "sev-info",
  "sev-notice",
  "sev-warning",
  "sev-severe",
] as const

function hex(tokens: Record<string, string>, name: string) {
  const v = tokens[name]
  if (!v) throw new Error(`missing token --${name}`)
  return parseHex(v)
}

describe.each(Object.entries(themes))("%s theme", (_name, t) => {
  const tint = Number.parseFloat(t.tint ?? "0") / 100

  it("defines the same token names as the other theme", () => {
    expect(Object.keys(t).sort()).toEqual(Object.keys(themes.dark).sort())
  })

  it.each(BODY_TEXT.flatMap((fg) => SURFACES.map((bg) => [fg, bg] as const)))(
    "--%s on --%s is AA for body text (>= 4.5)",
    (fg, bg) => {
      expect(contrastRatio(hex(t, fg), hex(t, bg))).toBeGreaterThanOrEqual(4.5)
    },
  )

  it.each(HUES.flatMap((fg) => ["bg", "surface"].map((bg) => [fg, bg] as const)))(
    "--%s text on --%s is AA (>= 4.5)",
    (fg, bg) => {
      expect(contrastRatio(hex(t, fg), hex(t, bg))).toBeGreaterThanOrEqual(4.5)
    },
  )

  it.each(HUES.map((h) => [h] as const))("--%s text on its own tinted badge is AA", (h) => {
    const badgeBg = blend(hex(t, h), hex(t, "surface"), tint)
    expect(contrastRatio(hex(t, h), badgeBg)).toBeGreaterThanOrEqual(4.5)
  })

  it("primary button text is AA", () => {
    expect(contrastRatio(hex(t, "fg-on-primary"), hex(t, "primary"))).toBeGreaterThanOrEqual(4.5)
  })

  // selfhostr guidelines 3.6: the focus outline is the ink colour, 2 px, offset 2 px.
  it("draws focus in the text colour", () => {
    expect(t.ring).toBe(t.fg)
  })

  it.each([["ring"], ["border-strong"], ["status-ok"]] as const)(
    "--%s is visible as a UI element on --bg (>= 3)",
    (name) => {
      const min = name === "border-strong" ? 1.4 : 3
      expect(contrastRatio(hex(t, name), hex(t, "bg"))).toBeGreaterThanOrEqual(min)
    },
  )

  // Per-sensor shades are chart fills only (never text): non-text contrast, WCAG 1.4.11.
  it.each(SENSORS.map((s) => [s] as const))(
    "--sensor-%s fill is visible on --surface and --bg (>= 3)",
    (s) => {
      for (const bg of ["surface", "bg"]) {
        expect(contrastRatio(hex(t, `sensor-${s}`), hex(t, bg))).toBeGreaterThanOrEqual(3)
      }
    },
  )

  it.each(SENSOR_FAMILIES.map((f) => [f] as const))(
    "the %s family's shades are distinct from each other (>= 1.3)",
    (f) => {
      const shades = FAMILY_META[f].sensors.map((s) => hex(t, `sensor-${s}`))
      for (let i = 0; i < shades.length; i++)
        for (let j = i + 1; j < shades.length; j++) {
          const a = shades[i]
          const b = shades[j]
          if (a && b) expect(contrastRatio(a, b)).toBeGreaterThanOrEqual(1.3)
        }
    },
  )
})
