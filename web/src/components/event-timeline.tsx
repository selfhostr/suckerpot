import { ChevronsUpDown } from "lucide-react"
import { useState } from "react"
import { EventRow } from "@/components/event-row"
import type { SensorEvent } from "@/lib/api"
import { t } from "@/i18n"
import { formatDuration } from "@/lib/format"
import { NOUN, NOUN_FALLBACK, foldEvents } from "@/lib/fold-events"

export function EventTimeline({ events }: { events: readonly SensorEvent[] }) {
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set())
  const items = foldEvents(events)

  return (
    <ol aria-label={t("events_timeline_label")} className="divide-y">
      {items.flatMap((item) => {
        if (item.kind === "event") {
          return [
            <li key={item.event.id}>
              <EventRow event={item.event} />
            </li>,
          ]
        }
        if (open.has(item.id)) {
          return item.events.map((e) => (
            <li key={e.id}>
              <EventRow event={e} isNew />
            </li>
          ))
        }
        const first = item.events[0]
        const last = item.events.at(-1)
        const span =
          first && last ? formatDuration((Date.parse(last.ts) - Date.parse(first.ts)) / 1000) : ""
        return [
          <li key={item.id}>
            <button
              type="button"
              onClick={() => setOpen((s) => new Set(s).add(item.id))}
              className="flex min-h-11 w-full items-center gap-3 px-4 py-2 text-left text-sm text-fg-muted transition-colors duration-150 hover:bg-surface-hover/50 hover:text-fg sm:px-5"
            >
              <span className="w-16 shrink-0" aria-hidden />
              <span className="flex size-7 shrink-0 items-center justify-center rounded-md border border-dashed">
                <ChevronsUpDown aria-hidden className="size-3.5" />
              </span>
              <span>
                {t(NOUN[item.type] ?? NOUN_FALLBACK, { count: item.events.length })}
                {span ? <span className="whitespace-nowrap text-fg-subtle"> · {span}</span> : null}
              </span>
            </button>
          </li>,
        ]
      })}
    </ol>
  )
}
