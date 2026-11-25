import { IntlMessageFormat } from "intl-messageformat"
import { LOCALES, matchTag, pickFromNavigator } from "./locales"
import { currentLocale, intlLocale, setLocale, t } from "./index"
import { tNodes } from "./rich"

const bundles = import.meta.glob<Record<string, string>>("./locales/*.json", {
  eager: true,
  import: "default",
})
const sources = import.meta.glob<string>(["../**/*.ts", "../**/*.tsx"], {
  eager: true,
  import: "default",
  query: "?raw",
})

function locale(code: string): Record<string, string> {
  const bundle = bundles[`./locales/${code}.json`]
  if (!bundle) throw new Error(`missing locale file ${code}.json`)
  return bundle
}

const en = locale("en")

/** The argument names a message uses, from its parsed ICU tree. */
interface AstNode {
  type: number
  value?: string
  options?: Record<string, { value: AstNode[] }>
  children?: AstNode[]
}
function argumentsOf(message: string): string[] {
  const names = new Set<string>()
  const walk = (nodes: AstNode[]) => {
    for (const n of nodes) {
      // 1 argument, 2 number, 3 date, 4 time, 5 select, 6 plural
      if (n.type >= 1 && n.type <= 6 && n.value) names.add(n.value)
      for (const o of Object.values(n.options ?? {})) walk(o.value)
      if (n.children) walk(n.children)
    }
  }
  walk(new IntlMessageFormat(message, "en").getAst())
  return [...names].sort()
}

/** Keys written as t("key"), tk("key") or tNodes("key") in the source, outside tests. */
function usedKeys(): Map<string, string> {
  const found = new Map<string, string>()
  const re = /(?<![\w.])(?:t|tk|tNodes)\(\s*["`]([A-Za-z0-9_]+)["`]/g
  for (const [path, text] of Object.entries(sources)) {
    if (
      path.includes(".test.") ||
      path.startsWith("./") ||
      path.startsWith("../i18n/") ||
      path.startsWith("../mocks/")
    ) {
      continue
    }
    for (const m of text.matchAll(re)) if (m[1]) found.set(m[1], path)
  }
  return found
}

describe("string files", () => {
  it("has one file per locale and no other", () => {
    expect(Object.keys(bundles).sort()).toEqual(
      LOCALES.map((l) => `./locales/${l.code}.json`).sort(),
    )
  })

  it("uses only keys that exist in en.json", () => {
    const missing = [...usedKeys()]
      .filter(([key]) => !(key in en))
      .map(([key, file]) => `${key} (${file})`)
    expect(missing).toEqual([])
  })

  it.each(LOCALES.filter((l) => l.code !== "en").map((l) => l.code))(
    "%s has no key that is absent from en.json",
    (code) => {
      expect(Object.keys(locale(code)).filter((k) => !(k in en))).toEqual([])
    },
  )

  it.each(LOCALES.map((l) => l.code))(
    "%s messages parse and keep the placeholders of en",
    (code) => {
      const problems: string[] = []
      for (const [key, message] of Object.entries(locale(code))) {
        const source = en[key]
        if (source === undefined) continue
        try {
          if (argumentsOf(message).join() !== argumentsOf(source).join())
            problems.push(`${key}: placeholders`)
        } catch {
          problems.push(`${key}: does not parse`)
        }
        if (message.includes("—")) problems.push(`${key}: em dash`)
      }
      expect(problems).toEqual([])
    },
  )
})

describe("locale choice", () => {
  it("maps browser tags to the nine locales", () => {
    expect(matchTag("fr-CH")).toBe("fr")
    expect(matchTag("pt-BR")).toBe("pt-BR")
    expect(matchTag("pt-PT")).toBe("pt")
    expect(matchTag("pt")).toBe("pt")
    expect(matchTag("zh-CN")).toBe("zh-Hans")
    expect(matchTag("zh-Hans-SG")).toBe("zh-Hans")
    expect(matchTag("zh-TW")).toBeNull()
    expect(matchTag("ja")).toBeNull()
  })

  it("takes the first language that matches, English when none does", () => {
    expect(pickFromNavigator(["ja", "de-AT", "fr"])).toBe("de")
    expect(pickFromNavigator(["ja", "ko"])).toBe("en")
    expect(pickFromNavigator([])).toBe("en")
  })
})

describe("translate", () => {
  afterEach(async () => {
    await setLocale("en")
  })

  it("answers in English by default and falls back to it", () => {
    expect(currentLocale()).toBe("en")
    expect(t("common_cancel")).toBe("Cancel")
    expect(t("format_duration_m_s", { m: 1, s: 40 })).toBe("1 min 40 s")
  })

  it("switches language, sets <html lang> and formats for Intl", async () => {
    await setLocale("pt")
    expect(currentLocale()).toBe("pt")
    expect(intlLocale()).toBe("pt-PT")
    expect(document.documentElement.lang).toBe("pt")
    await setLocale("zh-Hans")
    expect(document.documentElement.lang).toBe("zh-Hans")
  })

  it("puts React nodes where the placeholders are", () => {
    const out = tNodes("account_menu_label", {}, { name: "x" })
    expect(Array.isArray(out)).toBe(true)
    expect(out).toHaveLength(2)
  })
})
