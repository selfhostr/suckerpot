import type { Session, SessionCredentials, StatsSummary } from "./api"
import {
  connectionsOf,
  credentialsFinding,
  floodHeadline,
  floodHour,
  floodKindFor,
  floodParamFor,
  floodShareClause,
  floodSentence,
  floodSpan,
  floodViewFromParam,
  isFlood,
  parseAt,
  sessionHref,
  totalConnections,
} from "./floods"

const summary = (o: Partial<StatsSummary> = {}): StatsSummary => ({
  window_hours: 24,
  events: 90_000,
  sessions: 5_000,
  unique_ips: 310,
  sessions_with_commands: 40,
  download_attempts: 9,
  by_sensor: {},
  flood_sessions: 4_800,
  flood_sources: 20,
  ...o,
})

const row = (o: Partial<Session> = {}): Pick<Session, "kind" | "connections"> => ({
  kind: "session",
  connections: 1,
  ...o,
})

describe("flood rows", () => {
  it("tells a group from a session, and counts connections", () => {
    expect(isFlood(row({ kind: "burst", connections: 812 }))).toBe(true)
    expect(isFlood(row())).toBe(false)
    // An older API sends neither field: a session of one connection.
    expect(isFlood({})).toBe(false)
    expect(connectionsOf({})).toBe(1)
    expect(connectionsOf(row({ kind: "burst", connections: 812 }))).toBe(812)
    expect(totalConnections([row({ kind: "burst", connections: 812 }), row(), row(), {}])).toBe(815)
  })
})

describe("the Floods control and the URL", () => {
  it("maps All, Hide and Only to ?kind=", () => {
    expect(floodViewFromParam(null)).toBe("all")
    expect(floodViewFromParam("session")).toBe("hide")
    expect(floodViewFromParam("burst")).toBe("only")
    // Anything else is ignored instead of failing with a 422.
    expect(floodViewFromParam("bogus")).toBe("all")
    expect(floodParamFor("all")).toBeNull()
    expect(floodParamFor("hide")).toBe("session")
    expect(floodParamFor("only")).toBe("burst")
    expect(floodKindFor("all")).toBeUndefined()
    expect(floodKindFor("hide")).toBe("session")
    expect(floodKindFor("only")).toBe("burst")
  })
})

describe("flood sentences", () => {
  it("writes the share of floods for the Attacks headline", () => {
    expect(floodShareClause(summary())).toBe("96% of them in floods from 20 addresses")
    expect(floodShareClause(summary({ flood_sources: 1 }))).toBe(
      "96% of them in floods from 1 address",
    )
    expect(floodShareClause(summary({ flood_sessions: 0 }))).toBeNull()
    // An older API has no flood fields.
    expect(floodShareClause({ sessions: 5_000 })).toBeNull()
  })

  it("never rounds a small or a nearly total share to 0% or 100%", () => {
    expect(floodShareClause(summary({ flood_sessions: 12 }))).toBe(
      "Less than 1% of them in floods from 20 addresses",
    )
    expect(floodShareClause(summary({ sessions: 5_000, flood_sessions: 4_999 }))).toBe(
      "More than 99% of them in floods from 20 addresses",
    )
  })

  it("has a headline per view", () => {
    expect(floodHeadline("all", summary())).toBe(
      "5,000 sessions from 310 addresses in the last 24 hours, 96% of them in floods from 20 addresses.",
    )
    expect(floodHeadline("all", summary({ flood_sessions: 0 }))).toBeNull()
    expect(floodHeadline("only", summary())).toBe(
      "4,800 connections came in floods from 20 addresses in the last 24 hours, one row per address and hour.",
    )
    expect(floodHeadline("only", summary({ flood_sessions: 0 }))).toBe(
      "No address flooded the sensors in the last 24 hours.",
    )
    expect(floodHeadline("hide", summary())).toBe(
      "200 sessions in the last 24 hours, without the 4,800 connections that came in floods.",
    )
    expect(floodHeadline("hide", summary({ flood_sessions: 0 }))).toBe(
      "5,000 sessions in the last 24 hours, none of them in a flood.",
    )
  })

  it("says how much of an attacker came in floods", () => {
    expect(floodSentence(1456)).toBe("of which 1,456 in floods")
    expect(floodSentence(9000, true)).toBe("of which at least 9,000 in floods")
  })
})

describe("credentials finding", () => {
  const creds = (o: Partial<SessionCredentials> = {}): SessionCredentials => ({
    attempts: 812,
    distinct_usernames: 1,
    distinct_passwords: 812,
    distinct_pairs: 812,
    truncated: false,
    usernames: [{ value: "Administrator", count: 812 }],
    passwords: [{ value: "Spring2026!", count: 1 }],
    pairs: [],
    ...o,
  })

  it("says when nothing was repeated", () => {
    expect(credentialsFinding(creds())).toBe(
      "812 attempts, 1 username and 812 passwords: no pair was tried twice.",
    )
  })

  it("says when the same few pairs came back", () => {
    expect(
      credentialsFinding(creds({ attempts: 1204, distinct_passwords: 24, distinct_pairs: 31 })),
    ).toBe("1,204 attempts, 1 username and 24 passwords: 31 pairs tried over and over.")
  })

  it("keeps a plain sentence in between, and handles no login at all", () => {
    expect(
      credentialsFinding(creds({ attempts: 100, distinct_passwords: 60, distinct_pairs: 80 })),
    ).toBe("100 attempts, 1 username and 60 passwords.")
    expect(credentialsFinding(creds({ attempts: 0 }))).toBe("No login was tried.")
  })

  it("does not invent a password when the client only sent a hash", () => {
    expect(
      credentialsFinding(creds({ distinct_passwords: 1, passwords: [{ value: "", count: 812 }] })),
    ).toBe("812 attempts with 1 username, and no password was captured.")
  })
})

describe("time and links", () => {
  it("names the UTC hour of a group", () => {
    expect(floodHour("2026-11-12T14:02:11Z")).toEqual({
      since: "2026-11-12T14:00:00.000Z",
      until: "2026-11-12T15:00:00.000Z",
    })
  })

  it("shows the span of a group as clock times", () => {
    // Same minute: one time. Otherwise first to last, in the browser's time zone.
    const same = floodSpan({
      started_at: "2026-11-12T14:02:11Z",
      last_event_at: "2026-11-12T14:02:40Z",
    })
    expect(same).not.toContain("–")
    const span = floodSpan({
      started_at: "2026-11-12T14:02:11Z",
      last_event_at: "2026-11-12T14:58:00Z",
    })
    expect(span).toMatch(/^\d{2}:\d{2}–\d{2}:\d{2}$/)
  })

  it("adds the event time to a session link so a folded connection finds its group", () => {
    expect(sessionHref("abc 1")).toBe("/attacks/abc%201")
    expect(sessionHref("k3J9x2_a7Qe", "2026-11-12T14:02:11+00:00")).toBe(
      "/attacks/k3J9x2_a7Qe?at=2026-11-12T14%3A02%3A11%2B00%3A00",
    )
  })

  it("accepts only an ISO instant with a time zone as ?at=", () => {
    expect(parseAt("2026-11-12T14:02:11Z")).toBe("2026-11-12T14:02:11Z")
    expect(parseAt("2026-11-12T14:02:11.250+01:00")).toBe("2026-11-12T14:02:11.250+01:00")
    expect(parseAt("2026-11-12T14:02:11")).toBeUndefined()
    expect(parseAt("yesterday")).toBeUndefined()
    expect(parseAt(null)).toBeUndefined()
  })
})
