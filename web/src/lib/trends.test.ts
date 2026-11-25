import { describe, expect, it } from "vitest"
import {
  defangUrl,
  describeNew,
  describeTags,
  describeTop,
  tagTotals,
  type TagPoint,
} from "./trends"

describe("defangUrl", () => {
  it("defangs scheme and host dots, leaves the path alone", () => {
    expect(defangUrl("http://files.example.net/bins/x86.sh")).toBe(
      "hxxp://files[.]example[.]net/bins/x86.sh",
    )
    expect(defangUrl("https://198.51.100.23:8080/a.b")).toBe("hxxps://198[.]51[.]100[.]23:8080/a.b")
    expect(defangUrl("ftp://cdn.example.org/f")).toBe("fxp://cdn[.]example[.]org/f")
  })
  it("handles URLs without a scheme", () => {
    expect(defangUrl("cdn.example.org/x.sh")).toBe("cdn[.]example[.]org/x.sh")
  })
  it("never leaves a live scheme behind", () => {
    expect(defangUrl("HTTP://Example.NET/x")).not.toMatch(/^https?:/i)
  })
})

describe("findings", () => {
  const points: TagPoint[] = [
    { ts: "2026-10-18T00:00:00Z", tags: { recon: 50, php2shell: 10, other: 5 } },
    { ts: "2026-10-19T00:00:00Z", tags: { recon: 50, php2shell: 10, other: 5 } },
    { ts: "2026-10-20T00:00:00Z", tags: { recon: 40, php2shell: 60, other: 5 } },
    { ts: "2026-10-21T00:00:00Z", tags: { recon: 40, php2shell: 60, other: 5 } },
  ]
  it("totals tags and describes the leader", () => {
    expect(tagTotals(points)[0]).toEqual(["recon", 180])
    const f = describeTags(points, 7)
    expect(f.finding).toContain('"recon" is the most common tag')
    expect(describeTags([], 7).finding).toMatch(/No tagged activity/)
  })
  it("describes top lists", () => {
    const top = {
      field: "username" as const,
      total: 100,
      items: [
        { value: "root", count: 42, share: 0.42 },
        { value: "admin", count: 20, share: 0.2 },
      ],
    }
    expect(describeTop("username", top, 7).finding).toBe(
      '"root" was the most seen username in the last 7 days, in 42% of login attempts, ahead of "admin" (20%).',
    )
    expect(describeTop("url", undefined, 30).finding).toBe("No URLs recorded in the last 30 days.")
  })
  it("describes new values", () => {
    const items = [
      { value: "a", count: 3, first_seen: "2026-10-20T00:00:00Z" },
      { value: "b", count: 9, first_seen: "2026-10-21T00:00:00Z" },
    ]
    expect(describeNew("password", items, 7).finding).toBe(
      '2 passwords were never seen before this week; the most used is "b" (9 times).',
    )
    expect(describeNew("asn", [], 30).finding).toMatch(/No new networks/)
  })
})
