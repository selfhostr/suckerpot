// @vitest-environment node
/// <reference types="node" />
import { readFileSync, readdirSync, statSync } from "node:fs"
import { join } from "node:path"

/*
 * One type scale and one set of component sizes (DESIGN.md, "Type roles" and "Sizes"). These
 * checks keep pages from drifting back to one-off sizes.
 */

const tokens = readFileSync("src/styles/tokens.css", "utf8")
const index = readFileSync("src/styles/index.css", "utf8")

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sources(path)
    return path.endsWith(".tsx") && !path.endsWith(".test.tsx") ? [path] : []
  })
}

const files = sources("src").map((path) => ({ path, text: readFileSync(path, "utf8") }))
/** Pages and feature components: the shadcn primitives are checked separately. */
const app = files.filter((f) => !f.path.includes("components/ui/"))

function rootVar(name: string, css = tokens) {
  return new RegExp(`--${name}:\\s*([^;]+);`).exec(css)?.[1]?.trim()
}

describe("component sizes", () => {
  it("has three control heights and one chip height (selfhostr button 40, plate 22)", () => {
    expect(rootVar("control-sm")).toBe("2rem")
    expect(rootVar("control-md")).toBe("2.25rem")
    expect(rootVar("control-lg")).toBe("2.5rem")
    expect(rootVar("chip")).toBe("1.375rem")
  })

  it("raises every control to a 40 px target on touch screens", () => {
    const coarse = tokens.slice(tokens.indexOf("@media (pointer: coarse)"))
    expect(coarse).not.toBe("")
    expect(rootVar("control-sm", coarse)).toBe("2.5rem")
    expect(rootVar("control-md", coarse)).toBe("2.5rem")
  })

  it("sizes the control primitives from the tokens, not fixed heights", () => {
    for (const name of ["button", "input", "select", "toggle", "tabs"]) {
      const text = readFileSync(`src/components/ui/${name}.tsx`, "utf8")
      expect(text, name).toMatch(/--control-(sm|md|lg)/)
      expect(text, name).not.toMatch(/(?<![\w-])(h|size)-(7|8|9|10)(?![\w.-])/)
    }
  })

  it("has no extra-small button size", () => {
    const button = readFileSync("src/components/ui/button.tsx", "utf8")
    expect(button).not.toMatch(/\bxs:|"icon-xs"/)
    for (const f of app) expect(f.text, f.path).not.toMatch(/size="(xs|icon-xs)"/)
  })
})

describe("type roles", () => {
  const defined = new Set([...index.matchAll(/@utility (type-[a-z-]+)/g)].map((m) => m[1]))

  it("defines the roles DESIGN.md lists", () => {
    for (const role of [
      "type-page-title",
      "type-section-title",
      "type-card-title",
      "type-subtitle",
      "type-eyebrow",
      "type-column",
      "type-lede",
      "type-kpi",
      "type-figure",
    ]) {
      expect(defined.has(role), role).toBe(true)
    }
  })

  it("uses only roles that exist", () => {
    for (const f of files) {
      for (const m of f.text.matchAll(/\b(type-[a-z]+(?:-[a-z]+)*)\b/g)) {
        const role = m[1] ?? ""
        // `type-` also starts plain words in code ("type-check"); only class-like uses count.
        if (!/^type-(page|section|card|subtitle|eyebrow|column|lede|kpi|figure)/.test(role))
          continue
        expect(defined.has(role), `${f.path}: ${role}`).toBe(true)
      }
    }
  })

  it("gives every page title the page-title role", () => {
    for (const f of app) {
      for (const m of f.text.matchAll(/<h1\b[^>]*className="([^"]*)"/g)) {
        expect(m[1], f.path).toContain("type-page-title")
      }
    }
  })

  it("keeps running text at a line height of 1.5 or more", () => {
    const size = (n: string) => Number.parseFloat(rootVar(`text-${n}`, index) ?? "0")
    const lead = (n: string) => Number.parseFloat(rootVar(`text-${n}--line-height`, index) ?? "0")
    for (const n of ["xs", "sm", "base", "md"]) {
      expect(lead(n) / size(n), n).toBeGreaterThanOrEqual(1.5)
    }
  })

  it("has no one-off font sizes", () => {
    for (const f of app) {
      const hits = [...f.text.matchAll(/\btext-\[\d+(\.\d+)?(px|rem)\]/g)].map((m) => m[0])
      // The flag fallback draws a two-letter code inside an 18 x 12 px box.
      const allowed = f.path.endsWith("country-flag.tsx") ? ["text-[8px]"] : []
      expect(
        hits.filter((h) => !allowed.includes(h)),
        f.path,
      ).toEqual([])
    }
  })
})
