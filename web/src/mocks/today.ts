/**
 * MSW handlers for GET /today and GET /stats/benign. The numbers come from the same fixtures as
 * the sessions API, so "what happened" agrees with the Attacks page; the other cards are fixed,
 * fictional examples (documentation addresses, example domains).
 */
import { delay, http, HttpResponse } from "msw"
import { SENSOR_META, isSensor } from "@/lib/sensors"
import type { BenignCount, TodayCardData, TodayResponse } from "@/lib/today"
import { formReportWaiting } from "./abuse-forms"
import { buildBenignFixtures } from "./benign"
import { buildFixtures } from "./fixtures"

const LATENCY_MS = 180
const DAY = 86_400_000

const fixtures = buildFixtures()
const benign = buildBenignFixtures()

const num = (n: number) => n.toLocaleString("en-US")
const noun = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`

function top(counts: Map<string, number>): [string, number] | null {
  let best: [string, number] | null = null
  for (const [k, v] of counts) if (!best || v > best[1]) best = [k, v]
  return best
}

function happened(includeBenign: boolean): TodayCardData {
  const now = Date.now()
  const pool = [...fixtures, ...(includeBenign ? benign : [])].map((f) => f.session)
  const cur = pool.filter((s) => Date.parse(s.started_at) >= now - DAY)
  const prev = pool.filter(
    (s) => Date.parse(s.started_at) >= now - 2 * DAY && Date.parse(s.started_at) < now - DAY,
  )
  const ips = new Set(cur.map((s) => s.src_ip)).size
  const withCommands = cur.filter((s) => s.commands > 0).length
  const change =
    prev.length >= 10 ? Math.round(((cur.length - prev.length) / prev.length) * 100) : 0
  // Past a doubling, "15 times as many" reads faster than "1,415% more".
  const ratio = prev.length >= 10 ? cur.length / prev.length : 0
  const trend =
    ratio >= 2
      ? `, ${Math.round(ratio)} times as many as the day before`
      : change >= 25
        ? `, ${change}% more than the day before`
        : change <= -25
          ? `, ${-change}% fewer than the day before`
          : ""
  const tally = (pick: (s: (typeof cur)[number]) => string | string[] | null) => {
    const m = new Map<string, number>()
    for (const s of cur) {
      const v = pick(s)
      for (const k of Array.isArray(v) ? v : v ? [v] : []) m.set(k, (m.get(k) ?? 0) + 1)
    }
    return top(m)
  }
  const sensor = tally((s) => s.sensor)
  const country = tally((s) => s.country)
  const tag = tally((s) => s.tags.filter((t) => t !== "scanner"))
  const items: TodayCardData["items"] = []
  if (sensor && isSensor(sensor[0])) {
    items.push({
      kind: "sensor",
      value: sensor[0],
      label: `Most targeted: ${SENSOR_META[sensor[0]].label}`,
      detail: null,
      count: sensor[1],
      to: `/attacks?sensor=${sensor[0]}`,
    })
  }
  if (country) {
    items.push({
      kind: "country",
      value: country[0],
      label: `Most active country: ${country[0]}`,
      detail: null,
      count: country[1],
      to: `/attackers?country=${country[0]}`,
    })
  }
  if (tag) {
    items.push({
      kind: "tag",
      value: tag[0],
      label: `Most common behaviour: ${tag[0]}`,
      detail: null,
      count: tag[1],
      to: `/attacks?tag=${tag[0]}`,
    })
  }
  return {
    id: "happened",
    sentence: `${noun(cur.length, "attack")} came from ${noun(ips, "address", "addresses")} in the last 24 hours${trend}. ${noun(withCommands, "session")} ran commands on a fake shell.`,
    items,
    action: { label: "See all attacks", to: "/attacks" },
    empty: cur.length === 0,
  }
}

const CAMPAIGNS: TodayCardData = {
  id: "campaigns",
  sentence:
    "2 new campaigns formed in the last 24 hours: several addresses reusing the same tools or servers.",
  items: [
    {
      kind: "campaign",
      value: "3",
      label: "Mirai-style loader over Telnet #3",
      detail: "37 sessions from 9 sources",
      count: 37,
      to: "/campaigns/3",
    },
    {
      kind: "campaign",
      value: "2",
      label: "Xmrig miner drop over SSH #2",
      detail: "12 sessions from 4 sources",
      count: 12,
      to: "/campaigns/2",
    },
  ],
  action: { label: "See all campaigns", to: "/campaigns" },
  empty: false,
}

const ACT: TodayCardData = {
  id: "act",
  sentence:
    "2 servers tried to hand malware to your sensors today. Block them on your firewall or web proxy.",
  items: [
    {
      kind: "host",
      value: "7",
      label: "files[.]update-cdn[.]example",
      detail: "Serves malware downloads",
      count: 14,
      to: "/infrastructure?indicator=7",
    },
    {
      kind: "host",
      value: "8",
      label: "198[.]51[.]100[.]23",
      detail: "Serves malware downloads",
      count: 6,
      to: "/infrastructure?indicator=8",
    },
  ],
  action: { label: "Open the blocklists", to: "/defend/blocklists" },
  empty: false,
}

const NEW_WEEK: TodayCardData = {
  id: "new_week",
  sentence: "9 things showed up for the first time this week: 1 network, 4 URLs and 4 commands.",
  items: [
    {
      kind: "new",
      value: "asn:64530",
      label: "AS64530",
      detail: "New network",
      count: 41,
      to: "/trends?field=asn&days=7",
    },
    {
      kind: "new",
      value: "url:/cgi-bin/luci/;stok=/locale",
      label: "/cgi-bin/luci/;stok=/locale",
      detail: "New URL",
      count: 23,
      to: "/trends?field=url&days=7",
    },
    {
      kind: "new",
      value: "command:uname -s -m | tee /tmp/.a",
      label: "uname -s -m | tee /tmp/.a",
      detail: "New command",
      count: 11,
      to: "/trends?field=command&days=7",
    },
  ],
  action: { label: "See what is new", to: "/trends?field=url&days=7" },
  empty: false,
}

const EXPOSURE: TodayCardData = {
  id: "exposure",
  sentence: "Attackers went after 2 of the 3 services you listed today, 214 attacks in all.",
  items: [
    {
      kind: "service",
      value: "ssh",
      label: "Jump host",
      detail: "OpenSSH 9.6",
      count: 160,
      to: "/attacks?sensor=ssh",
    },
    {
      kind: "service",
      value: "web",
      label: "Customer portal",
      detail: "Apache 2.4.58",
      count: 54,
      to: "/attacks?sensor=web",
    },
  ],
  action: { label: "Open your exposure", to: "/defend/exposure" },
  empty: false,
}

const FORMS: TodayCardData = {
  id: "forms",
  sentence:
    "1 report to submit by web form, for 1 provider. These desks take no mail: the report waits until you paste it into their form.",
  items: [],
  action: { label: "Open the form queue", to: "/abuse?status=forms" },
  empty: false,
}

function benignCount(): BenignCount {
  const recent = benign.filter((f) => Date.parse(f.session.started_at) >= Date.now() - DAY)
  return {
    window_hours: 24,
    sessions: recent.length,
    sources: new Set(recent.map((f) => f.session.src_ip)).size,
  }
}

export const todayHandlers = [
  http.get("/api/v1/today", async ({ request }) => {
    await delay(LATENCY_MS)
    const include = new URL(request.url).searchParams.get("include_benign") === "1"
    const body: TodayResponse = {
      generated_at: new Date().toISOString(),
      window_hours: 24,
      hidden_benign: include ? 0 : benignCount().sessions,
      cards: [
        happened(include),
        ...(formReportWaiting() ? [FORMS] : []),
        CAMPAIGNS,
        ACT,
        NEW_WEEK,
        EXPOSURE,
      ],
      form_queue: formReportWaiting() ? { reports: 1, providers: 1 } : null,
    }
    return HttpResponse.json(body)
  }),
  http.get("/api/v1/stats/benign", async () => {
    await delay(LATENCY_MS)
    return HttpResponse.json(benignCount())
  }),
]
