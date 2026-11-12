import { describe, expect, it } from "vitest"
import {
  describeChain,
  describeCollector,
  describeEgress,
  describeKind,
  describeSample,
  describeSamples,
  egressReason,
  familyLabel,
  fetchStatusLabel,
  isPlainWeb,
  orderChain,
  webKindLabel,
  type Egress,
  type SampleDetail,
  type SampleChain,
  type SampleItem,
} from "./samples"

const NOW = Date.parse("2026-10-31T12:00:00Z")
const DAY = 86_400_000

function sample(over: Partial<SampleItem>): SampleItem {
  return {
    sha256: "a".repeat(64),
    kind: "ELF",
    arch: "ARM",
    bits: 32,
    family: "Mirai",
    severity: "severe",
    size: 1000,
    sources: 1,
    sessions: 1,
    first_seen: new Date(NOW - DAY).toISOString(),
    last_seen: new Date(NOW - DAY).toISOString(),
    yara: [],
    stored: true,
    analysis_status: "done",
    origin: "local",
    ...over,
  }
}

describe("describeSamples", () => {
  it("handles an empty list", () => {
    expect(describeSamples([], false, NOW)).toBe("No samples collected yet.")
  })
  it("names the top family and its architectures", () => {
    const rows = [
      sample({ arch: "ARM" }),
      sample({ arch: "MIPS" }),
      sample({ family: "Gafgyt", arch: "x86" }),
    ]
    expect(describeSamples(rows, false, NOW)).toBe(
      "3 new files this week, 2 of them Mirai builds for ARM and MIPS.",
    )
  })
  it("says at least when more pages exist", () => {
    expect(describeSamples([sample({})], true, NOW)).toMatch(/^At least 1 new file this week/)
  })
  it("says so when nothing is new", () => {
    const old = new Date(NOW - 30 * DAY).toISOString()
    expect(describeSamples([sample({ first_seen: old })], false, NOW)).toBe(
      "1 sample collected, none of them new this week.",
    )
  })
})

describe("labels", () => {
  it("describes a kind", () => {
    expect(describeKind({ kind: "ELF", arch: "ARM", bits: 32 })).toBe("ELF ARM 32-bit")
    expect(describeKind({ kind: null, arch: null, bits: null })).toBe("Unknown file")
  })
  it("names the kinds of ordinary web content in plain English", () => {
    const labels = Object.fromEntries(
      ["html", "svg", "xml", "css", "json", "javascript"].map((k) => [
        k,
        describeKind({ kind: k, arch: null, bits: null }),
      ]),
    )
    expect(labels).toEqual({
      html: "Web page",
      svg: "Image (SVG)",
      xml: "Data (XML)",
      css: "Stylesheet",
      json: "Data (JSON)",
      javascript: "Script (web)",
    })
    expect(describeKind({ kind: "HTML", arch: "ARM", bits: 32 })).toBe("Web page")
  })
  it("leaves every other kind alone", () => {
    expect(webKindLabel("script")).toBeNull()
    expect(webKindLabel("elf")).toBeNull()
    expect(webKindLabel("constructor")).toBeNull()
    expect(webKindLabel(null)).toBeNull()
    expect(describeKind({ kind: "script", arch: null, bits: null })).toBe("script")
  })
  it("names a plain web page by its kind instead of Unknown", () => {
    expect(familyLabel(null, "html")).toBe("Web page")
    expect(familyLabel(null, "elf")).toBe("Unknown")
    expect(familyLabel(null)).toBe("Unknown")
    expect(familyLabel("Mirai", "html")).toBe("Mirai")
    expect(isPlainWeb({ kind: "css", family: null })).toBe(true)
    expect(isPlainWeb({ kind: "css", family: "Shell dropper" })).toBe(false)
    expect(isPlainWeb({ kind: "script", family: null })).toBe(false)
  })
  it("tells TFTP apart", () => {
    expect(fetchStatusLabel("unsupported", "tftp://192.0.2.9/x")).toBe("Not fetched (TFTP)")
    expect(fetchStatusLabel("fetched")).toBe("Fetched")
  })
})

describe("web content in the sentences", () => {
  const page = sample({ kind: "html", arch: null, bits: null, family: null, severity: "info" })
  it("does not count plain web pages as new files", () => {
    expect(describeSamples([page, page], false, NOW)).toBe(
      "2 samples collected, all ordinary web content (pages, images, style sheets), nothing to flag.",
    )
    const mixed = [page, sample({})]
    expect(describeSamples(mixed, false, NOW)).toBe(
      "1 new file this week, 1 of them Mirai builds for ARM.",
    )
  })
  it("says a page is ordinary web content", () => {
    const detail = { item: page } as SampleDetail
    expect(describeSample(detail)).toBe(
      "Ordinary web content, 1 KB. Served from 1 address in 1 session. It is kept for reference and its links are not followed.",
    )
  })
})

describe("chain", () => {
  const chain: SampleChain = {
    nodes: [
      { id: "c", kind: "c2", label: "203.0.113.77:23" },
      { id: "f", kind: "sample", label: "abc" },
      { id: "u", kind: "url", label: "http://files.example.net/x" },
      { id: "s", kind: "session", label: "S1" },
    ],
    edges: [
      { from: "s", to: "u" },
      { from: "u", to: "f" },
      { from: "f", to: "c" },
    ],
  }
  it("orders steps from the session to the command server", () => {
    expect(orderChain(chain).map((n) => n.id)).toEqual(["s", "u", "f", "c"])
  })
  it("survives a cycle", () => {
    const loop: SampleChain = {
      nodes: [
        { id: "a", kind: "url", label: "a" },
        { id: "b", kind: "url", label: "b" },
      ],
      edges: [
        { from: "a", to: "b" },
        { from: "b", to: "a" },
      ],
    }
    expect(orderChain(loop)).toHaveLength(2)
  })
  it("summarises the chain", () => {
    expect(describeChain(chain)).toBe(
      "The chain links 1 session, 1 URL, 1 file and 1 command server.",
    )
  })
})

describe("egress", () => {
  const gate = { state: "open" as const, reason: null, checked_at: null }
  const base: Egress = {
    ingest: gate,
    collector: gate,
    exit_ip_allowed: true,
    exit_ip: null,
    collector_quota: { used: 1, limit: 2 },
    quarantine: { used_bytes: 1, max_bytes: 2 },
  }
  it("says the VPN is used when open", () => {
    expect(describeEgress(base)).toBe("Outbound traffic leaves through the VPN.")
  })
  it("says the tunnel is down when closed for that reason", () => {
    const e = { ...base, ingest: { ...gate, state: "closed" as const, reason: "tunnel_down" } }
    expect(describeEgress(e)).toBe("Outbound traffic is paused: the VPN tunnel is down.")
  })
  it("names real gate codes in plain words", () => {
    expect(egressReason("ip_not_allowed")).toBe("the exit address is not on the allow-list")
    expect(egressReason("no_vpn")).toBe("the VPN is not reachable")
  })
  it("explains why only URLs are recorded", () => {
    expect(describeCollector(undefined).finding).toBe(
      "The sample collector is off, so only URLs are recorded.",
    )
    const never = { ...base, collector: { ...gate, state: "closed" as const, reason: "no_status" } }
    expect(describeCollector(never).detail).toContain("COLLECTOR_ENABLED")
    const down = {
      ...base,
      collector: { ...gate, state: "closed" as const, reason: "tunnel_down" },
    }
    expect(describeCollector(down).finding).toBe(
      "The sample collector is paused (the VPN tunnel is down), so only URLs are recorded.",
    )
    expect(describeCollector(base).finding).toBe(
      "No file has been collected yet, so only URLs are recorded.",
    )
    expect(describeCollector(base, ["unsupported", "unsupported"]).finding).toContain("TFTP")
    expect(describeCollector(base, ["pending", null]).detail).toContain("working through")
  })
  it("falls back to readable text for unknown codes", () => {
    expect(egressReason("some_new_code")).toBe("some new code")
  })
})
