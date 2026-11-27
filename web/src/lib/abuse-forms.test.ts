import { describe, expect, it } from "vitest"
import {
  describeFormQueue,
  formLinkHref,
  reducedFormUrl,
  weekSpanLabel,
  keyOf,
  linkLabel,
  refsOf,
  suggestionText,
  weekLabel,
  type FormLink,
  type KitSource,
} from "./abuse-forms"

const link = (over: Partial<FormLink> = {}): FormLink => ({
  url: "https://www.example.net/abuse",
  host: "www.example.net",
  origin: "directory",
  clickable: true,
  ...over,
})

describe("formLinkHref", () => {
  it("allows a plain https link whose host is the one shown", () => {
    expect(formLinkHref(link())).toBe("https://www.example.net/abuse")
  })

  it.each([
    ["not allowed by the server", link({ clickable: false })],
    ["http", link({ url: "http://www.example.net/abuse" })],
    ["another host", link({ url: "https://evil.example.org/abuse" })],
    ["user info", link({ url: "https://user@www.example.net/abuse" })],
    ["a port", link({ url: "https://www.example.net:8443/abuse", host: "www.example.net:8443" })],
    ["javascript", link({ url: "javascript:alert(1)" })],
    ["garbage", link({ url: "https://" })],
  ])("refuses %s", (_name, l) => {
    expect(formLinkHref(l)).toBeNull()
  })
})

describe("labels and sentences", () => {
  it("names the week by its Monday", () => {
    expect(weekLabel("2026-11-16")).toBe("Week of 16 Nov 2026")
    expect(weekLabel(null)).toBe("This week")
  })

  it("says where a link comes from", () => {
    expect(linkLabel(link({ checked_on: "2026-11-01" }))).toBe(
      "From the shared directory, checked 2026-11-01",
    )
    expect(linkLabel(link({ checked_on: "2024-01-01", stale: true }))).toMatch(/over a year ago/)
    expect(linkLabel(link({ origin: "reply" }))).toBe(
      "From a reply: check the address before you open it",
    )
  })

  it("counts the queue", () => {
    expect(describeFormQueue(0)).toBe("Nothing to submit by form.")
    expect(describeFormQueue(2)).toMatch(/^2 providers/)
  })
})

describe("suggestionText", () => {
  it("holds only what a maintainer needs", () => {
    const text = suggestionText({
      provider: "Example Hosting",
      mailbox: "abuse@example.net",
      asns: [64500, 64501],
      formUrl: "https://www.example.net/abuse",
    })
    expect(text).toBe(
      [
        "Provider: Example Hosting",
        "Abuse mailbox domain: example.net",
        "ASN: AS64500, AS64501",
        "Form link: https://www.example.net/abuse",
        "Learned from a verified reply.",
      ].join("\n"),
    )
  })
})

describe("refsOf", () => {
  it("keeps the ticked sources only", () => {
    const s = (value: string): KitSource => ({
      kind: "attack_source",
      subject_type: "ip",
      value,
      abuse_type: "Login attack",
      first_seen: "",
      last_seen: "",
      description: "",
      log_excerpt: "",
      stale: false,
    })
    const sources = [s("198.51.100.1"), s("198.51.100.2")]
    expect(
      refsOf(
        sources,
        new Set([keyOf({ kind: "attack_source", subject_type: "ip", value: "198.51.100.2" })]),
      ),
    ).toEqual([{ kind: "attack_source", subject_type: "ip", value: "198.51.100.2" }])
  })
})

describe("reducedFormUrl", () => {
  it("keeps the provider's site only", () => {
    expect(
      reducedFormUrl("https://user@support.example.net:8443/abuse?ticket=1&email=me@example.org#x"),
    ).toBe("https://support.example.net/")
    expect(reducedFormUrl("https://support.example.net/ticket/123456")).toBe(
      "https://support.example.net/",
    )
    expect(reducedFormUrl("https://support.example.net/r/a8F3kQ9zX2")).toBe(
      "https://support.example.net/",
    )
    expect(reducedFormUrl("http://support.example.net/abuse")).toBeNull()
    expect(reducedFormUrl(null)).toBeNull()
  })

  it("says it was shortened in the suggestion", () => {
    expect(
      suggestionText({
        provider: "P",
        mailbox: null,
        asns: [],
        formUrl: "https://support.example.net/",
        shortened: true,
      }),
    ).toContain(
      "Provider site (the form link was left out, find the form page there): https://support.example.net/",
    )
  })
})

describe("weekSpanLabel", () => {
  it("names one week, or the first and last weeks the sources span", () => {
    expect(weekSpanLabel("2026-11-16T10:00:00Z", "2026-11-20T10:00:00Z")).toBe(
      "Week of 16 Nov 2026",
    )
    expect(weekSpanLabel("2026-11-12T10:00:00Z", "2026-11-20T10:00:00Z")).toBe(
      "Weeks of 9 Nov 2026 to 16 Nov 2026",
    )
  })
})
