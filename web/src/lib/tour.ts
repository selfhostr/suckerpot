/**
 * The guided tour (M24, docs/dev/design/m24.md section 2): its seven steps, and the per-account
 * "already seen" flag. The flag is one harmless key per username in localStorage; nothing else
 * about the person is stored.
 */

import { tk } from "@/i18n"
import { withText } from "@/lib/utils"

export interface TourStep {
  id: "what" | "daily" | "group" | "payloads" | "egress" | "abuse" | "alerts"
  /** One plain sentence. */
  title: string
  /** Two or three short sentences. */
  body: string
}

export const TOUR_STEPS: readonly TourStep[] = [
  withText(
    { title: tk("tour_what_title"), body: tk("tour_what_body") },
    { id: "what" as const },
  ),
  withText(
    { title: tk("tour_daily_title"), body: tk("tour_daily_body") },
    { id: "daily" as const },
  ),
  withText(
    { title: tk("tour_group_title"), body: tk("tour_group_body") },
    { id: "group" as const },
  ),
  withText(
    { title: tk("tour_payloads_title"), body: tk("tour_payloads_body") },
    { id: "payloads" as const },
  ),
  withText(
    { title: tk("tour_egress_title"), body: tk("tour_egress_body") },
    { id: "egress" as const },
  ),
  withText(
    { title: tk("tour_abuse_title"), body: tk("tour_abuse_body") },
    { id: "abuse" as const },
  ),
  withText(
    { title: tk("tour_alerts_title"), body: tk("tour_alerts_body") },
    { id: "alerts" as const },
  ),
]

export const TOUR_KEY_PREFIX = "suckerpot.tour.seen."

export function tourKey(username: string): string {
  return `${TOUR_KEY_PREFIX}${username}`
}

/** Storage can be missing or full (private mode): then the tour simply does not open by itself. */
export function hasSeenTour(
  username: string,
  storage: Storage | undefined = safeStorage(),
): boolean {
  if (!storage) return true
  try {
    return storage.getItem(tourKey(username)) !== null
  } catch {
    return true
  }
}

export function markTourSeen(username: string, storage: Storage | undefined = safeStorage()) {
  try {
    storage?.setItem(tourKey(username), "1")
  } catch {
    // Nothing to do: the tour may open again next time.
  }
}

function safeStorage(): Storage | undefined {
  try {
    return typeof window === "undefined" ? undefined : window.localStorage
  } catch {
    return undefined
  }
}
