/**
 * MSW handlers for the form-only desks queue (M38): one provider with two sources, its copy
 * kit, and "Submitted". Stateful for the page load. Every value is a placeholder (documentation
 * addresses, example.* names).
 */
import { delay, http, HttpResponse, type RequestHandler } from "msw"
import type { FormQueueItem, Kit } from "@/lib/abuse-forms"
import { BROWSER_WARNING } from "@/lib/abuse-forms"

const LATENCY_MS = 140
const ID = "5f0f0f0f-0000-4000-8000-0000000000f1"
const now = Date.now()
const iso = (msAgo: number) => new Date(now - msAgo).toISOString()
const DAY = 86_400_000
const monday = (() => {
  const d = new Date(now)
  d.setUTCHours(0, 0, 0, 0)
  d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7))
  return d.toISOString().slice(0, 10)
})()

let submitted = false

/** Whether the one form report of the mock still waits (read by the Today mock). */
export const formReportWaiting = () => !submitted

const item: FormQueueItem = {
  public_id: ID,
  revision: 3,
  status: "draft",
  recipient: {
    id: 41,
    name: "Example Hosting",
    mailbox: "abuse@example-hosting.example",
    source: "rdap",
    muted: false,
    form_only: true,
    form_source: "directory",
  },
  week: monday,
  subject_count: 2,
  stale_count: 0,
  window_start: iso(3 * DAY),
  window_end: iso(2 * 3_600_000),
  updated_at: iso(2 * 3_600_000),
  guard: { ok: true, codes: [] },
  form_host: "www.example-hosting.example",
  form_origin: "directory",
  provider: "Example Hosting",
  reports: [{ public_id: ID, revision: 3 }],
}

const kit: Kit = {
  public_id: ID,
  revision: 3,
  status: "draft",
  provider: "Example Hosting",
  mailbox: "abuse@example-hosting.example",
  week: monday,
  warning: BROWSER_WARNING,
  links: [
    {
      url: "https://www.example-hosting.example/abuse/report",
      host: "www.example-hosting.example",
      origin: "directory",
      clickable: true,
      checked_on: "2026-11-01",
      stale: false,
    },
  ],
  links_differ: false,
  email: "reports@example.net",
  name: "",
  abuse_type: "Login attack",
  addresses: "198.51.100.61\n198.51.100.62",
  first_seen: "2026-11-19T08:12Z",
  last_seen: "2026-11-21T22:40Z",
  description:
    "198.51.100.61 (AS64501, EXAMPLE-HOSTING)\n  2026-11-20T10:02Z to 2026-11-21T22:40Z, TCP/22 (ssh)\n  - Login attempts: 1840 (users: root, admin)\n198.51.100.62 (AS64501, EXAMPLE-HOSTING)\n  2026-11-19T08:12Z to 2026-11-20T01:05Z, TCP/80 (http)\n  - 2026-11-19T08:12Z Exploit attempts:\n      GET /cgi-bin/luci/;stok=/locale\nref 4c1d9e0a7b23",
  log_excerpt:
    "2026-11-20T10:02Z 198.51.100.61:51544 TCP/22 (ssh) Login attempts: 1840; users: root,admin\n\n2026-11-19T08:12Z 198.51.100.62:40112 TCP/80 (http) Exploit attempts; GET /cgi-bin/luci/;stok=/locale",
  evidence: {
    name: "evidence.csv",
    media_type: "text/csv",
    content:
      "source,asn,network,country,time,protocol,src_port,port,count,details,sha256\r\n198.51.100.61,64501,EXAMPLE-HOSTING,NL,2026-11-20T10:02Z,tcp,51544,22,1840,Login attempts,\r\n",
  },
  sources: [
    {
      kind: "attack_source",
      subject_type: "ip",
      value: "198.51.100.61",
      abuse_type: "Login attack",
      first_seen: "2026-11-20T10:02Z",
      last_seen: "2026-11-21T22:40Z",
      description: "198.51.100.61 (AS64501, EXAMPLE-HOSTING)\nref 4c1d9e0a7b23",
      log_excerpt: "2026-11-20T10:02Z 198.51.100.61:51544 TCP/22 (ssh) Login attempts: 1840",
      stale: false,
    },
    {
      kind: "attack_source",
      subject_type: "ip",
      value: "198.51.100.62",
      abuse_type: "Exploit attempt",
      first_seen: "2026-11-19T08:12Z",
      last_seen: "2026-11-20T01:05Z",
      description: "198.51.100.62 (AS64501, EXAMPLE-HOSTING)\nref 4c1d9e0a7b23",
      log_excerpt: "2026-11-19T08:12Z 198.51.100.62:40112 TCP/80 (http) Exploit attempts",
      stale: false,
    },
  ],
  one_ip_per_submission: false,
  max_chars: 2000,
  labels: { abuse_type: "Type of abuse", description: "Comments" },
  type_key: "login_attack",
  reports: [{ public_id: ID, revision: 3 }],
  guard: { ok: true, codes: [] },
}
// The browser helper's data, as the server builds it from the kit (forms.fill_data).
kit.fill = JSON.stringify({
  format: "formfill/1",
  labels: { abuse_type: "Type of abuse", description: "Comments" },
  type: "login_attack",
  values: {
    abuse_type: kit.abuse_type,
    addresses: kit.addresses,
    description: kit.description,
    email: kit.email,
    first_seen: kit.first_seen,
    last_seen: kit.last_seen,
    log_excerpt: kit.log_excerpt,
  },
})

export const abuseFormHandlers: RequestHandler[] = [
  http.get("/api/v1/abuse/forms", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json({ items: submitted ? [] : [item], missing: [] })
  }),
  http.get("/api/v1/abuse/reports/:id/kit", async ({ params }) => {
    await delay(LATENCY_MS)
    if (String(params.id) !== ID)
      return HttpResponse.json(
        { detail: "This report is not in the form queue.", code: "not_a_form_report" },
        { status: 409 },
      )
    return HttpResponse.json(kit)
  }),
  http.post("/api/v1/abuse/reports/:id/submitted", async ({ params }) => {
    await delay(LATENCY_MS)
    if (String(params.id) !== ID || submitted)
      return HttpResponse.json(
        { detail: "That step is not possible.", code: "invalid_transition" },
        { status: 409 },
      )
    submitted = true
    return HttpResponse.json({
      public_id: ID,
      submitted: 2,
      left: 0,
      sent_at: new Date().toISOString(),
    })
  }),
]
