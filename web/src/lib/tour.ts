/**
 * The guided tour (M24, docs/dev/design/m24.md section 2): its seven steps, and the per-account
 * "already seen" flag. The flag is one harmless key per username in localStorage; nothing else
 * about the person is stored.
 */

export interface TourStep {
  id: "what" | "daily" | "group" | "payloads" | "egress" | "abuse" | "alerts"
  /** One plain sentence. */
  title: string
  /** Two or three short sentences. */
  body: string
}

export const TOUR_STEPS: readonly TourStep[] = [
  {
    id: "what",
    title: "SuckerPot is a trap: fake servers that attackers find on the internet.",
    body: "Twelve sensors pretend to be SSH, a web app, a database and more, with nothing real behind them. Every attempt is recorded, and the events of one connection are grouped into a session you can read as a story.",
  },
  {
    id: "daily",
    title: "Read it daily: start with Today, then open Attacks.",
    body: "Today shows what is happening right now on a live map, the last 24 hours in a few numbers, and what needs you. Attacks lists every visit as one line; open a session to read its timeline and, for shell sessions, replay the commands at real speed.",
  },
  {
    id: "group",
    title: "Related sessions are grouped for you.",
    body: "Campaigns join sessions that share a script, a payload host or an exploit. Under Understand, Payloads shows the tools behind them (scripts, files, hosts and URLs), and Patterns shows what attackers try most and what is new.",
  },
  {
    id: "payloads",
    title: "Payloads are never run, and fetching them is optional.",
    body: "Sensors only record the download URL. When payload fetching is on, the collector fetches it through the VPN into a quarantine, and the analyzer, which has no network, reads the file for its type, hashes, rule matches, hidden scripts and possible command servers.",
  },
  {
    id: "egress",
    title: "Only one service can reach out to the internet: the VPN.",
    body: "Every lookup, download and alert the stack makes leaves through the vpn service, so none of them comes from your home address (the sensors still answer attackers on it). The gate pauses all outbound work when the tunnel or its exit looks wrong, and a kill switch blocks traffic if the tunnel drops.",
  },
  {
    id: "abuse",
    title: "Abuse reports are drafts for you to send.",
    body: "When abuse reports are on, contacts are found over RDAP through the VPN, and one draft is built per abuse contact. You review it and send it from your own mailbox: by default SuckerPot never sends a report, and it does so only if you set up SMTP and choose a sending mode. An identity check masks or blocks anything that matches your own addresses or the terms you listed.",
  },
  {
    id: "alerts",
    title: "Alerts tell you when something matters.",
    body: "Rules watch for things like a new campaign or a malware drop, and send a message to Discord, Teams or email, and a weekly report is built every Monday. Everything is off until you switch it on, and messages leave through the VPN.",
  },
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
