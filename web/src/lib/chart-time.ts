import { intlLocale } from "@/i18n"

export interface DayPoint {
  day: string
  events: number
}

const hourFormats = new Map<string, Intl.DateTimeFormat>()

/** "14:00" in the browser time zone, in the active language. */
export const formatHour = (iso: string) => {
  const locale = intlLocale()
  let f = hourFormats.get(locale)
  if (!f) {
    f = new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit", hourCycle: "h23" })
    hourFormats.set(locale, f)
  }
  return f.format(new Date(iso))
}

/** Fill the gaps so a quiet day shows as an empty slot, not a missing one. */
export function fillDays(points: readonly DayPoint[], days = 30, now = Date.now()): DayPoint[] {
  const byDay = new Map(points.map((p) => [p.day, p.events]))
  const today = new Date(now)
  today.setUTCHours(0, 0, 0, 0)
  return Array.from({ length: days }, (_, i) => {
    const d = new Date(today.getTime() - (days - 1 - i) * 86_400_000)
    const day = d.toISOString().slice(0, 10)
    return { day, events: byDay.get(day) ?? 0 }
  })
}
