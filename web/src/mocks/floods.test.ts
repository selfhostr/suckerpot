import { connectionsOf, isFlood } from "@/lib/floods"
import { buildFloodFixtures } from "./floods"

describe("flood group mocks", () => {
  const now = Date.parse("2026-11-12T16:20:00Z")
  const groups = buildFloodFixtures(now)

  it("builds groups shaped like the API, each with its own id", () => {
    expect(groups.length).toBeGreaterThan(3)
    const ids = groups.map((g) => g.session.session_id)
    expect(new Set(ids).size).toBe(ids.length)
    for (const { session } of groups) {
      expect(session.session_id).toMatch(/^burst-[0-9a-f]{24}$/)
      expect(isFlood(session)).toBe(true)
      expect(connectionsOf(session)).toBeGreaterThan(20)
      expect(session.src_port).toBe(0)
      expect(session.login_success).toBe(false)
      expect(session.commands + session.downloads + session.http_requests).toBe(0)
    }
  })

  it("keeps every group inside the last day, newest first, and never in the future", () => {
    const starts = groups.map((g) => Date.parse(g.session.started_at))
    expect(starts).toEqual([...starts].sort((a, b) => b - a))
    for (const { session } of groups) {
      expect(Date.parse(session.last_event_at)).toBeLessThanOrEqual(now)
      expect(Date.parse(session.started_at)).toBeGreaterThan(now - 24 * 3_600_000)
      expect(Date.parse(session.started_at)).toBeLessThanOrEqual(Date.parse(session.last_event_at))
    }
  })

  it("uses documentation addresses only", () => {
    for (const { session, events } of groups) {
      expect(session.src_ip).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$/)
      expect(events.every((e) => e.src_ip === session.src_ip)).toBe(true)
    }
  })

  it("stores the first events of the group, each connection under its own id", () => {
    const biggest = groups.find((g) => connectionsOf(g.session) === 812)
    if (!biggest) throw new Error("no 812-connection group")
    expect(biggest.events.length).toBeGreaterThan(100)
    expect(biggest.events.length).toBeLessThanOrEqual(biggest.session.event_count)
    const connect = biggest.events.filter((e) => e.type === "connect")
    expect(new Set(connect.map((e) => e.session_id)).size).toBe(connect.length)
    expect(biggest.credentials.attempts).toBe(biggest.session.login_attempts)
  })
})
