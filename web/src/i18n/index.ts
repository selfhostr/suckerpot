import i18next from "i18next"
import ICU from "i18next-icu"
import { initReactI18next } from "react-i18next"
import en from "./locales/en.json"
import {
  DEFAULT_LOCALE,
  LOCALES,
  detectLocale,
  isLocaleCode,
  writeStoredLocale,
  type LocaleCode,
} from "./locales"

export { LOCALES, DEFAULT_LOCALE, detectLocale, isLocaleCode, type LocaleCode } from "./locales"

/** Lazy loaders: one chunk per language, only the active one is downloaded. English is bundled. */
const loaders: Record<
  Exclude<LocaleCode, "en">,
  () => Promise<{ default: Record<string, string> }>
> = {
  fr: () => import("./locales/fr.json"),
  de: () => import("./locales/de.json"),
  es: () => import("./locales/es.json"),
  it: () => import("./locales/it.json"),
  pt: () => import("./locales/pt.json"),
  "pt-BR": () => import("./locales/pt-BR.json"),
  ru: () => import("./locales/ru.json"),
  "zh-Hans": () => import("./locales/zh-Hans.json"),
}

export type MessageValues = Record<string, string | number | boolean | Date | null | undefined>

/**
 * Initialise i18next (English only, synchronous). Safe to call twice. Tests rely on this
 * running at import time, so a component can call `t()` without any setup.
 */
void i18next
  .use(ICU)
  .use(initReactI18next)
  .init({
    lng: DEFAULT_LOCALE,
    fallbackLng: DEFAULT_LOCALE,
    supportedLngs: LOCALES.map((l) => l.code),
    resources: { en: { translation: en } },
    // Keys are flat snake_case sentences' names: no namespaces, no dotted paths.
    keySeparator: false,
    nsSeparator: false,
    interpolation: { escapeValue: false },
    initAsync: false,
    // A missing key shows the English text, then the key itself, never an empty string.
    saveMissing: false,
  })

/** Translate a key. The key is a string literal at every call site (a test checks it exists). */
export function t(key: string, values?: MessageValues): string {
  return i18next.t(key, values as never) as unknown as string
}

/**
 * Mark a key that is stored in data (a nav table, a column list) and translated later with
 * `t()`. It returns the key unchanged; the test that lists the used keys looks for `tk("...")`.
 */
export function tk<K extends string>(key: K): K {
  return key
}

/** The active locale code (`en`, `pt-BR`, `zh-Hans`). */
export function currentLocale(): LocaleCode {
  const l = i18next.language
  return isLocaleCode(l) ? l : DEFAULT_LOCALE
}

/** The BCP 47 tag to give to `Intl` for the active locale (pt is pt-PT, not Brazilian). */
export function intlLocale(): string {
  const code = currentLocale()
  return LOCALES.find((l) => l.code === code)?.intl ?? "en"
}

type Listener = (code: LocaleCode) => void
const listeners = new Set<Listener>()

/** Subscribe to language changes (used by the root to remount the tree). */
export function onLocaleChange(fn: Listener): () => void {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

function applyDocument(code: LocaleCode): void {
  if (typeof document === "undefined") return
  document.documentElement.lang = code
  document.documentElement.dir = "ltr"
}

/** Load a language and make it the active one. `persist` stores an explicit user choice. */
export async function setLocale(code: LocaleCode, persist = false): Promise<void> {
  if (code !== "en" && !i18next.hasResourceBundle(code, "translation")) {
    const mod = await loaders[code]()
    i18next.addResourceBundle(code, "translation", mod.default, true, true)
  }
  await i18next.changeLanguage(code)
  applyDocument(code)
  if (persist) writeStoredLocale(code)
  for (const fn of listeners) fn(code)
}

/** Called once before the first render: stored choice, else navigator.languages, else English. */
export async function initLocale(): Promise<LocaleCode> {
  const code = detectLocale()
  if (code === "en") applyDocument(code)
  else await setLocale(code)
  return code
}
