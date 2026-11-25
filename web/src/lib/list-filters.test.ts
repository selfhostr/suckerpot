import { describe, expect, it } from "vitest"
import type { AsnItem } from "./api"
import {
  activeFilterCount,
  clearParams,
  dayAfter,
  dayStart,
  filterNetworks,
  parseAsn,
  parseAttackerFilters,
  parseCountry,
  parseNetworkView,
  parseSessionFilters,
  parseTag,
  patchParams,
  presetSince,
  SESSION_PARAMS,
  toDateInput,
} from "./list-filters"

const qs = (s: string) => new URLSearchParams(s)

describe("parseSessionFilters", () => {
  it("reads every filter from the query string", () => {
    const f = parseSessionFilters(
      qs(
        "sensor=ssh,telnet&src_ip=203.0.113.9&username=root&command=uname%20-a&tag=mirai&country=nl&asn=AS64500&stage=commands&kind=burst&since=2026-11-01T00:00:00Z",
      ),
    )
    expect(f).toMatchObject({
      sensor: ["ssh", "telnet"],
      src_ip: "203.0.113.9",
      username: "root",
      command: "uname -a",
      tag: "mirai",
      country: "NL",
      stage: "commands",
      kind: "burst",
      since: "2026-11-01T00:00:00.000Z",
    })
    // A pasted "AS64500" is sent as the number the API takes.
    expect(f.asn).toBe("64500")
  })

  it("drops values the API would refuse", () => {
    const f = parseSessionFilters(
      qs("tag=Bad%20Tag&country=xyz&asn=abc&stage=nope&src_ip=not%20an%20ip&since=yesterday"),
    )
    expect(f.tag).toBeUndefined()
    expect(f.country).toBeUndefined()
    expect(f.asn).toBeUndefined()
    expect(f.stage).toBeUndefined()
    expect(f.src_ip).toBeUndefined()
    expect(f.since).toBeUndefined()
  })

  it("is empty for a bare URL", () => {
    const f = parseSessionFilters(qs(""))
    expect(Object.values(f).filter((v) => v !== undefined)).toEqual([])
  })
})

describe("parseAttackerFilters", () => {
  it("defaults to last seen, newest first", () => {
    expect(parseAttackerFilters(qs(""))).toMatchObject({ sort: "last_seen", order: "desc" })
  })
  it("reads sort, direction and filters", () => {
    const v = parseAttackerFilters(qs("sort=sessions&order=asc&q=203.0.113&country=FR&asn=64500"))
    expect(v.sort).toBe("sessions")
    expect(v.order).toBe("asc")
    expect(v.filters).toMatchObject({ q: "203.0.113", country: "FR", asn: "64500", order: "asc" })
  })
  it("ignores an unknown sort and a bad prefix", () => {
    const v = parseAttackerFilters(qs("sort=drop&order=sideways&q=<script>"))
    expect(v).toMatchObject({ sort: "last_seen", order: "desc" })
    expect(v.filters.q).toBeUndefined()
  })
})

describe("value parsers", () => {
  it("accepts an AS number with or without the prefix", () => {
    expect(parseAsn("AS64500")).toBe("64500")
    expect(parseAsn("as 64500")).toBe("64500")
    expect(parseAsn("64500")).toBe("64500")
    expect(parseAsn("AS")).toBeUndefined()
  })
  it("accepts a country as a code or a name", () => {
    expect(parseCountry("de")).toBe("DE")
    expect(parseCountry("Germany")).toBe("DE")
    expect(parseCountry("Atlantis")).toBeUndefined()
  })
  it("turns a typed tag into a slug", () => {
    expect(parseTag(" Crypto Miner ")).toBe("crypto-miner")
    expect(parseTag("a/b")).toBeUndefined()
  })
})

describe("networks", () => {
  const items: AsnItem[] = [
    {
      asn: 64500,
      org: "Polder Cloud BV",
      country: "NL",
      ips: 3,
      sessions: 9,
      events: 40,
      last_seen: "",
    },
    {
      asn: 64501,
      org: "Nordlys Hosting",
      country: "NO",
      ips: 1,
      sessions: 2,
      events: 5,
      last_seen: "",
    },
    { asn: 12, org: null, country: null, ips: 1, sessions: 1, events: 1, last_seen: "" },
  ]
  it("defaults to sessions with no filter", () => {
    expect(parseNetworkView(qs(""))).toEqual({
      sort: "sessions",
      q: "",
      country: undefined,
      since: undefined,
    })
    expect(parseNetworkView(qs("sort=ips")).sort).toBe("ips")
    expect(parseNetworkView(qs("sort=bad")).sort).toBe("sessions")
  })
  it("matches an AS number, a name or a country name", () => {
    const find = (q: string) => filterNetworks(items, { q, country: undefined }).map((n) => n.asn)
    expect(find("AS6450")).toEqual([64500, 64501])
    expect(find("nordlys")).toEqual([64501])
    expect(find("netherlands")).toEqual([64500])
    expect(find("")).toHaveLength(3)
  })
  it("combines the text with the country", () => {
    expect(filterNetworks(items, { q: "6450", country: "NO" }).map((n) => n.asn)).toEqual([64501])
  })
})

describe("periods", () => {
  it("counts a preset back from now", () => {
    expect(presetSince("24h", Date.parse("2026-11-12T12:00:00Z"))).toBe("2026-11-11T12:00:00.000Z")
    expect(presetSince("nope")).toBeUndefined()
  })
  it("turns date inputs into instants and back, the last day included", () => {
    const from = dayStart("2026-11-10")
    const to = dayAfter("2026-11-12")
    expect(from).toBeDefined()
    expect(Date.parse(to ?? "") - Date.parse(dayStart("2026-11-12") ?? "")).toBeGreaterThanOrEqual(
      23 * 3_600_000,
    )
    expect(toDateInput(from)).toBe("2026-11-10")
    expect(toDateInput(to, true)).toBe("2026-11-12")
    expect(dayStart("12/11/2026")).toBeUndefined()
    expect(toDateInput(undefined)).toBe("")
  })
})

describe("writing the URL", () => {
  it("sets, replaces and removes params, keeping the others", () => {
    const next = patchParams(qs("sensor=ssh&tag=mirai"), { tag: null, country: "NL", sensor: "" })
    expect(next.toString()).toBe("country=NL")
  })
  it("clears the filters but keeps the sort", () => {
    const next = clearParams(qs("sort=sessions&country=NL&tag=mirai&since=x&until=y"), [
      ...SESSION_PARAMS,
    ])
    expect(next.toString()).toBe("sort=sessions")
  })
  it("counts a period once", () => {
    expect(activeFilterCount(qs("since=a&until=b&tag=x"), SESSION_PARAMS)).toBe(2)
    expect(activeFilterCount(qs("until=b"), SESSION_PARAMS)).toBe(1)
    expect(activeFilterCount(qs(""), SESSION_PARAMS)).toBe(0)
  })
})
