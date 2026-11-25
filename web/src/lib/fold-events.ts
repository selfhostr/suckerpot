import { tk } from "@/i18n"
import type { SensorEvent } from "./api"

export type TimelineItem =
  | { kind: "event"; event: SensorEvent }
  | { kind: "fold"; id: string; type: string; events: SensorEvent[] }

/** Runs longer than this are folded (first HEAD and last TAIL stay visible). */
const FOLD_OVER = 6
const HEAD = 3
const TAIL = 1

/**
 * Only repetitive noise folds; commands and downloads are the story and stay visible. The value
 * is the message key of the "Show N more ..." button for that event type.
 */
export const NOUN: Record<string, string> = {
  login_attempt: tk("event_fold_show_login_attempt"),
  http_request: tk("event_fold_show_http_request"),
  scan: tk("event_fold_show_scan"),
}

/** Key of the fold button for an event type that has no entry in NOUN. */
export const NOUN_FALLBACK = tk("event_fold_show_event")

/** Fold long runs of identical event types, so a brute force is one line, not ninety. */
export function foldEvents(events: readonly SensorEvent[]): TimelineItem[] {
  const out: TimelineItem[] = []
  let i = 0
  while (i < events.length) {
    const first = events[i]
    if (!first) break
    let j = i
    while (j < events.length && events[j]?.type === first.type) j++
    const run = events.slice(i, j)
    if (run.length > FOLD_OVER && first.type in NOUN) {
      run.slice(0, HEAD).forEach((event) => out.push({ kind: "event", event }))
      out.push({
        kind: "fold",
        id: `${first.type}-${first.id}`,
        type: first.type,
        events: run.slice(HEAD, run.length - TAIL),
      })
      run.slice(run.length - TAIL).forEach((event) => out.push({ kind: "event", event }))
    } else {
      run.forEach((event) => out.push({ kind: "event", event }))
    }
    i = j
  }
  return out
}
