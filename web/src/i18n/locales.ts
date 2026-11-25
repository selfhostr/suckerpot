/** The nine locales of the UI. `en` is the source and the fallback of every other one. */
export const LOCALES = [
  { code: "en", name: "English", intl: "en" },
  { code: "fr", name: "Français", intl: "fr" },
  { code: "de", name: "Deutsch", intl: "de" },
  { code: "es", name: "Español", intl: "es" },
  { code: "it", name: "Italiano", intl: "it" },
  // `pt` is European Portuguese: Intl needs pt-PT, a bare "pt" formats as Brazilian.
  { code: "pt", name: "Português", intl: "pt-PT" },
  { code: "pt-BR", name: "Português (Brasil)", intl: "pt-BR" },
  { code: "ru", name: "Русский", intl: "ru" },
  { code: "zh-Hans", name: "简体中文", intl: "zh-Hans" },
] as const

export type LocaleCode = (typeof LOCALES)[number]["code"]

export const DEFAULT_LOCALE: LocaleCode = "en"

/** localStorage key of an explicit language choice. */
export const LOCALE_STORAGE_KEY = "suckerpot.locale"

export function isLocaleCode(value: unknown): value is LocaleCode {
  return typeof value === "string" && LOCALES.some((l) => l.code === value)
}

/** Map one BCP 47 tag from `navigator.languages` to a supported locale, or null. */
export function matchTag(tag: string): LocaleCode | null {
  const parts = tag.toLowerCase().replaceAll("_", "-").split("-")
  const base = parts[0]
  const rest = parts.slice(1)
  switch (base) {
    case "pt":
      return rest.includes("br") ? "pt-BR" : "pt"
    case "zh":
      // Simplified only: Traditional (Hant, TW, HK, MO) has no translation.
      if (rest.includes("hant") || rest.some((p) => p === "tw" || p === "hk" || p === "mo")) {
        return null
      }
      return "zh-Hans"
    case "en":
    case "fr":
    case "de":
    case "es":
    case "it":
    case "ru":
      return base
    default:
      return null
  }
}

/** First `navigator.languages` entry that matches a locale; English when none does. */
export function pickFromNavigator(languages: readonly string[]): LocaleCode {
  for (const tag of languages) {
    const m = matchTag(tag)
    if (m) return m
  }
  return DEFAULT_LOCALE
}

export function readStoredLocale(): LocaleCode | null {
  try {
    const v = localStorage.getItem(LOCALE_STORAGE_KEY)
    return isLocaleCode(v) ? v : null
  } catch {
    return null
  }
}

export function writeStoredLocale(code: LocaleCode): void {
  try {
    localStorage.setItem(LOCALE_STORAGE_KEY, code)
  } catch {
    // Storage blocked: the choice just will not persist.
  }
}

/** Stored choice, else the browser's list, else English. */
export function detectLocale(): LocaleCode {
  const stored = readStoredLocale()
  if (stored) return stored
  const langs =
    typeof navigator === "undefined"
      ? []
      : navigator.languages.length
        ? navigator.languages
        : [navigator.language]
  return pickFromNavigator(langs.filter(Boolean))
}
