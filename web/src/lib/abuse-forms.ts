/**
 * The form-only desks queue (M38, docs/dev/design/m38.md section 6): shapes of `/abuse/forms`,
 * `/abuse/reports/{id}/kit` and `/abuse/reports/{id}/submitted`, the sentences of the queue and the
 * suggestion text for the shared directory. Nothing here submits a form: the owner opens the form,
 * pastes each field and records the submission.
 */
import { getJson, sendJson } from "./api"
import type { GuardResult, Recipient, ReportKind } from "./abuse"
import { plural } from "./format"

/** Shown at the top of every kit, always: a browser does not go through the node's VPN. */
export const BROWSER_WARNING =
  "The provider sees the address of the browser that submits the form. Open it through your VPN or the Tor Browser."

/** Where suggestions for the shared directory go: a public issue template (D12). */
export const SUGGEST_URL =
  "https://github.com/selfhostr/suckerpot/issues/new?template=abuse-form.yml"

export interface FormLink {
  url: string
  /** The host, shown in text next to the link. */
  host: string
  origin: "directory" | "reply"
  /** The server allows a link only for https on an allowed host with no query string. */
  clickable: boolean
  /** Directory links: the maintainers' last check (YYYY-MM-DD). */
  checked_on?: string | null
  /** Last checked over a year ago. */
  stale?: boolean
}

export interface FormQueueItem {
  public_id: string
  revision: number
  status: string
  recipient: Recipient
  /** The Monday (UTC) of the report's ISO week. */
  week: string | null
  subject_count: number
  stale_count: number
  window_start: string
  window_end: string
  updated_at: string
  guard: GuardResult
  form_host?: string | null
  form_origin?: "directory" | "reply" | null
}

export interface FormQueue {
  items: FormQueueItem[]
  missing: string[]
}

export interface KitSource {
  kind: ReportKind
  subject_type: "ip" | "url" | "domain"
  value: string
  abuse_type: string
  first_seen: string
  last_seen: string
  description: string
  log_excerpt: string
  /** Older than 7 days. */
  stale: boolean
}

export interface Kit {
  public_id: string
  revision: number
  status: string
  provider: string
  mailbox: string | null
  week: string | null
  warning: string
  links: FormLink[]
  /** The directory and a reply point at different forms. */
  links_differ: boolean
  email: string
  name: string
  abuse_type: string
  addresses: string
  first_seen: string
  last_seen: string
  description: string
  log_excerpt: string
  evidence: { name: string; media_type: string; content: string }
  sources: KitSource[]
  one_ip_per_submission: boolean
  max_chars: number
  /** The form's own label of a kit field, from the shared directory. */
  labels: Record<string, string>
  guard: GuardResult
}

export interface SubjectRef {
  kind: ReportKind
  subject_type: "ip" | "url" | "domain"
  value: string
}

export interface Submitted {
  public_id: string
  submitted: number
  left: number
  sent_at: string
}

export const formKeys = {
  queue: ["abuse", "forms"] as const,
  kit: (id: string, revision: number) => ["abuse", "kit", id, revision] as const,
}

export const formsApi = {
  queue: () => getJson<FormQueue>("/abuse/forms"),
  kit: (id: string) => getJson<Kit>(`/abuse/reports/${id}/kit`),
  submitted: (id: string, revision: number, subjects?: SubjectRef[]) =>
    sendJson<Submitted>("POST", `/abuse/reports/${id}/submitted`, {
      revision,
      ...(subjects ? { subjects } : {}),
    }),
  /** The owner sends a desk to the form queue by hand (true) or back to mail (false). */
  setFormOnly: (recipientId: number, on: boolean) =>
    sendJson("PATCH", `/abuse/recipients/${recipientId}`, { form_only: on }),
}

/**
 * The href of a form link, or null when it must be shown as text only. The server already decided
 * (`clickable`); this checks again that it is a plain https URL whose host is the one shown, so a
 * link never says one host and opens another.
 */
export function formLinkHref(link: FormLink): string | null {
  if (!link.clickable || !link.url.startsWith("https://")) return null
  try {
    const u = new URL(link.url)
    if (u.protocol !== "https:" || u.username || u.password || u.port) return null
    return u.host.toLowerCase() === link.host.toLowerCase() ? link.url : null
  } catch {
    return null
  }
}

/** The Monday (UTC) of the ISO week of a time, as YYYY-MM-DD, or null. */
export function mondayOf(iso: string): string | null {
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return null
  const d = new Date(t)
  d.setUTCHours(0, 0, 0, 0)
  d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7))
  return d.toISOString().slice(0, 10)
}

/**
 * The weeks the sources of a form report span: "Week of 16 Nov 2026", or "Weeks of 9 Nov 2026 to
 * 16 Nov 2026" when an unsubmitted report carried older sources into the new week.
 */
export function weekSpanLabel(windowStart: string, windowEnd: string): string {
  const first = mondayOf(windowStart)
  const last = mondayOf(windowEnd)
  if (!first || !last) return weekLabel(last ?? first)
  if (first === last) return weekLabel(first)
  return `Weeks of ${weekLabel(first).slice("Week of ".length)} to ${weekLabel(last).slice("Week of ".length)}`
}

/** "Week of 16 Nov 2026" from the Monday of an ISO week. */
export function weekLabel(week: string | null | undefined): string {
  if (!week || !/^\d{4}-\d{2}-\d{2}$/.test(week)) return "This week"
  const d = new Date(`${week}T00:00:00Z`)
  const day = d.toLocaleDateString("en-GB", {
    day: "numeric",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  })
  return `Week of ${day}`
}

/** The sentence over the queue. */
export function describeFormQueue(n: number): string {
  if (n === 0) return "Nothing to submit by form."
  return `${plural(n, "provider week", "provider weeks")} to submit through the provider's web form.`
}

/** The sentence on a queue card. */
export function describeFormItem(item: FormQueueItem): string {
  const parts = [plural(item.subject_count, "address", "addresses")]
  if (item.stale_count > 0) parts.push(`${item.stale_count} older than 7 days`)
  return parts.join(", ")
}

/** The label of a link: the directory is reviewed, a reply is a hint. */
export function linkLabel(link: FormLink): string {
  if (link.origin === "directory") {
    const checked = link.checked_on ? `, checked ${link.checked_on}` : ""
    return link.stale
      ? `From the shared directory${checked} (last checked over a year ago)`
      : `From the shared directory${checked}`
  }
  return "From a reply: check the address before you open it"
}

/** The source references of the ticked addresses. */
export function refsOf(sources: KitSource[], ticked: ReadonlySet<string>): SubjectRef[] {
  return sources
    .filter((s) => ticked.has(keyOf(s)))
    .map((s) => ({ kind: s.kind, subject_type: s.subject_type, value: s.value }))
}

export const keyOf = (s: Pick<KitSource, "kind" | "subject_type" | "value">): string =>
  `${s.kind}|${s.subject_type}|${s.value}`

/**
 * The text to post as an issue for the shared directory (D12). Only what a maintainer needs to
 * check the form on the provider's own site: never an address we reported, a ticket number, the
 * reply text or anything about this node.
 */
export function suggestionText(input: {
  provider: string
  mailbox: string | null
  asns: number[]
  formUrl: string
  /** The link was cut to its scheme, host and path (see `reducedFormUrl`). */
  shortened?: boolean
}): string {
  const domain = input.mailbox?.includes("@") ? input.mailbox.split("@").pop() : null
  const lines = [
    `Provider: ${input.provider}`,
    `Abuse mailbox domain: ${domain ?? "unknown"}`,
    `ASN: ${input.asns.length > 0 ? input.asns.map((a) => `AS${a}`).join(", ") : "unknown"}`,
    input.shortened
      ? `Form link (shortened to its address and path): ${input.formUrl}`
      : `Form link: ${input.formUrl}`,
    "Learned from a verified reply.",
  ]
  return lines.join("\n")
}

/**
 * A reply's form link cut to its scheme, host and path: no user info, port, query or fragment, any
 * of which could carry a ticket id or the reply contact. Null when it is not an https URL.
 */
export function reducedFormUrl(url: string | null | undefined): string | null {
  if (!url?.startsWith("https://")) return null
  try {
    const u = new URL(url)
    if (u.protocol !== "https:") return null
    return `https://${u.hostname}${u.pathname}`
  } catch {
    return null
  }
}

/** Save a text file the browser holds (the kit's evidence file). */
export function saveText(name: string, mediaType: string, content: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: mediaType }))
  const a = document.createElement("a")
  a.href = url
  a.download = name
  a.rel = "noopener"
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
