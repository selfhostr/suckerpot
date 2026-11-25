/**
 * Formatting helpers. Numbers and dates follow the active UI language (see `@/i18n`); times are
 * shown in the browser's time zone. Formatters are cached per locale.
 */
import { intlLocale, t } from "@/i18n"

const cache = new Map<string, unknown>()

/** One `Intl` formatter per (kind, locale, options), built on first use. */
function cached<T>(kind: string, build: (locale: string) => T): T {
  const locale = intlLocale()
  const key = `${kind}|${locale}`
  let f = cache.get(key) as T | undefined
  if (!f) {
    f = build(locale)
    cache.set(key, f)
  }
  return f
}

const integer = () => cached("int", (l) => new Intl.NumberFormat(l, { maximumFractionDigits: 0 }))
const compact = () =>
  cached(
    "compact",
    (l) => new Intl.NumberFormat(l, { notation: "compact", maximumFractionDigits: 1 }),
  )
const percent = () =>
  cached("pct", (l) => new Intl.NumberFormat(l, { style: "percent", maximumFractionDigits: 0 }))

export function formatNumber(n: number): string {
  return integer().format(n)
}

export function formatCompact(n: number): string {
  return n < 10_000 ? integer().format(n) : compact().format(n)
}

export function formatPercent(ratio: number): string {
  return percent().format(ratio)
}

/**
 * English-only "3 passwords" / "1 password". Do not use in new code: write the sentence as one
 * message with an ICU plural (`{count, plural, one {# password} other {# passwords}}`).
 */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${formatNumber(n)} ${n === 1 ? one : many}`
}

const absolute = () =>
  cached(
    "abs",
    (l) =>
      new Intl.DateTimeFormat(l, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hourCycle: "h23",
        timeZoneName: "short",
      }),
  )

const clock = () =>
  cached(
    "clock",
    (l) =>
      new Intl.DateTimeFormat(l, {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hourCycle: "h23",
      }),
  )

export function formatAbsolute(iso: string | Date): string {
  return absolute().format(typeof iso === "string" ? new Date(iso) : iso)
}

const windowFmt = () =>
  cached(
    "window",
    (l) =>
      new Intl.DateTimeFormat(l, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hourCycle: "h23",
      }),
  )

/** A time window to the minute, compact: "Oct 31, 13:53 – 17:53" (browser time zone). */
export function formatWindow(start: string | Date, end: string | Date): string {
  const a = typeof start === "string" ? new Date(start) : start
  const b = typeof end === "string" ? new Date(end) : end
  return a <= b ? windowFmt().formatRange(a, b) : windowFmt().format(a)
}

export function formatClock(iso: string | Date): string {
  return clock().format(typeof iso === "string" ? new Date(iso) : iso)
}

export function browserTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone
}

const rtf = () =>
  cached("rtf", (l) => new Intl.RelativeTimeFormat(l, { numeric: "auto", style: "short" }))
const shortDate = () =>
  cached("shortDate", (l) => new Intl.DateTimeFormat(l, { month: "short", day: "numeric" }))

/** "just now", "42 sec. ago", "5 min. ago", "3 hr. ago", "yesterday", then a date. */
export function formatRelative(iso: string | Date, now: number = Date.now()): string {
  const tm = (typeof iso === "string" ? new Date(iso) : iso).getTime()
  const diff = Math.round((tm - now) / 1000)
  const abs = Math.abs(diff)
  // Events never come from the future: a few seconds or minutes "ahead" is clock skew
  // (server vs browser, or the shared 30 s clock between ticks), not "in 11 sec.".
  if (abs < 10 || (diff > 0 && diff < 120)) return t("format_just_now")
  if (abs < 60) return rtf().format(diff, "second")
  if (abs < 3600) return rtf().format(Math.round(diff / 60), "minute")
  if (abs < 86_400) return rtf().format(Math.round(diff / 3600), "hour")
  if (abs < 7 * 86_400) return rtf().format(Math.round(diff / 86_400), "day")
  return shortDate().format(tm)
}

/** "8 s", "1 min 40 s", "2 h 05 min". */
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return t("format_duration_s", { s })
  if (s < 3600) {
    const m = Math.floor(s / 60)
    const r = s % 60
    return r ? t("format_duration_m_s", { m, s: r }) : t("format_duration_m", { m })
  }
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return t("format_duration_h_m", { h, m: String(m).padStart(2, "0") })
}

/** ISO 3166-1 alpha-2 code -> country name in the UI language. Unknown codes return null. */
export function countryName(code: string | null | undefined): string | null {
  if (!code || !/^[A-Za-z]{2}$/.test(code)) return null
  try {
    const names = cached("region", (l) => new Intl.DisplayNames([l], { type: "region" }))
    const name = names.of(code.toUpperCase())
    return name && name !== code.toUpperCase() && name !== "Unknown Region" ? name : null
  } catch {
    return null
  }
}

/** Mask an address for sharing: 203.0.113.42 -> 203.0.x.x, 2001:db8:1::5 -> 2001:db8:x::x. */
export function maskIp(ip: string): string {
  if (ip.includes(":")) {
    const parts = ip.split(":").filter(Boolean)
    return `${parts.slice(0, 2).join(":")}:x::x`
  }
  const parts = ip.split(".")
  return parts.length === 4 ? `${parts.slice(0, 2).join(".")}.x.x` : ip
}

const IPV4_IN_TEXT = /\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b/g

/** Mask every IPv4 address inside free text (URLs, commands, summaries). */
export function maskIpsInText(text: string): string {
  return text.replace(IPV4_IN_TEXT, "$1.x.x")
}

/** Mask addresses in text that may carry defanged ones ("203[.]0[.]113[.]66"). */
export function maskDefangedText(text: string): string {
  return maskIpsInText(text.replaceAll("[.]", "."))
}

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"] as const

/** Decimal units, one decimal above KB: "3.2 GB", "512 MB", "820 B". */
export function formatBytes(bytes: number): string {
  let v = Math.max(0, bytes)
  let i = 0
  while (v >= 1000 && i < BYTE_UNITS.length - 1) {
    v /= 1000
    i++
  }
  const unit = BYTE_UNITS[i] ?? "B"
  if (i === 0) return `${formatNumber(Math.round(v))} ${unit}`
  const digits = v >= 100 ? 0 : 1
  const num = cached(
    `bytes${digits}`,
    (l) => new Intl.NumberFormat(l, { minimumFractionDigits: 0, maximumFractionDigits: digits }),
  )
  return `${num.format(digits ? Math.round(v * 10) / 10 : Math.round(v))} ${unit}`
}
