import { formatBytes } from "./format"
import {
  enrichmentFinding,
  keyInFlight,
  retentionFinding,
  secretErrorMessage,
  sensorsFinding,
  sourceLabel,
  storageFinding,
  testMessage,
  type EnrichmentSettings,
  type KeyInfo,
  type SensorStatus,
  type SystemSettings,
} from "./settings"

const NOW = Date.parse("2026-10-24T18:00:00Z")
const NO_KEY: KeyInfo = {
  configured: false,
  source: null,
  last4: null,
  updated_at: null,
  secret_error: null,
  pending_apply: false,
  test: null,
  test_pending: false,
  test_requested_at: null,
}
const s = (sensor: string, status: SensorStatus["status"], last: string | null): SensorStatus => ({
  sensor,
  status,
  last_event_at: last,
  events_last_hour: 10,
})

describe("settings findings", () => {
  it("sensors", () => {
    const all = ["ssh", "telnet", "web", "rdp"].map((x) => s(x, "active", "2026-10-24T17:58:00Z"))
    expect(sensorsFinding(all, NOW)).toBe("All four sensors reported in the last 15 minutes.")
    const mixed = [
      s("ssh", "active", "2026-10-24T17:58:00Z"),
      s("telnet", "quiet", "2026-10-24T15:00:00Z"),
      s("web", "active", "2026-10-24T17:59:00Z"),
      s("rdp", "silent", null),
    ]
    expect(sensorsFinding(mixed, NOW)).toBe(
      "SSH and Web reported in the last 15 minutes; Telnet last reported 3 hr. ago; RDP has not reported in over 24 hours.",
    )
    expect(
      sensorsFinding(
        mixed.map((m) => ({ ...m, status: "silent" as const })),
        NOW,
      ),
    ).toBe("No sensor has reported in the last 24 hours.")
  })

  const enrich: EnrichmentSettings = {
    geoip: {
      provider: "dbip",
      available: true,
      files: {
        city: { file: "c.mmdb", bytes: 1, updated_at: "2026-10-01T00:00:00Z", age_days: 23.6 },
      },
      last_error: null,
      refresh_days: 30,
      attribution: "IP geolocation by DB-IP.com",
    },
    abuseipdb: {
      ...NO_KEY,
      configured: true,
      source: "env",
      daily_quota: 1000,
      used_today: 312,
      disabled: null,
      paused: false,
      last_error: null,
    },
    greynoise: {
      ...NO_KEY,
      daily_quota: null,
      used_today: 0,
      disabled: null,
      paused: false,
      last_error: null,
    },
    abusech: {
      ...NO_KEY,
      daily_quota: null,
      used_today: 0,
      disabled: null,
      paused: false,
      last_error: null,
    },
    virustotal: {
      ...NO_KEY,
      daily_quota: null,
      used_today: 0,
      disabled: null,
      paused: false,
      last_error: null,
    },
    maxmind: NO_KEY,
    nvd: NO_KEY,
    github: NO_KEY,
    key_editing: { enabled: true, reason: null },
    reported_at: null,
  }

  it("enrichment", () => {
    expect(enrichmentFinding(enrich)).toBe(
      "GeoIP is on (DB-IP Lite, 24 days old); AbuseIPDB used 312 of 1,000 checks today.",
    )
    expect(
      enrichmentFinding({
        ...enrich,
        geoip: { ...enrich.geoip, provider: "off", available: false },
      }),
    ).toMatch(/^GeoIP is off/)
    expect(enrichmentFinding({ ...enrich, geoip: { ...enrich.geoip, provider: "unknown" } })).toBe(
      "Ingest has not reported its enrichment status yet.",
    )
  })

  const GUARD = {
    state: "ok",
    active: true,
    size_bytes: 3.2e9,
    max_bytes: 20e9,
    percent: 16,
  } as const
  const sys: SystemSettings = {
    sensors: [],
    retention: {
      raw_days: 90,
      compression_after_days: 7,
      oldest_event_at: null,
      aggregates: ["events_hourly"],
    },
    disk_guard: GUARD,
    ingest_disk: null,
    database: { size_bytes: 3.2e9, max_bytes: 20e9 },
  }

  it("retention and storage", () => {
    expect(retentionFinding(sys.retention)).toBe(
      "Raw events are kept for 90 days; aggregates are kept forever.",
    )
    expect(storageFinding(sys)).toBe("The database uses 3.2 GB of its 20 GB ceiling (16%).")
    expect(
      storageFinding({ ...sys, disk_guard: { ...GUARD, state: "critical", percent: 97 } }),
    ).toMatch(/97%/)
    expect(storageFinding({ ...sys, database: { size_bytes: null, max_bytes: null } })).toBe(
      "The database size is not available.",
    )
  })

  describe("retentionFinding", () => {
    const at = (days: number) => new Date(NOW - days * 86_400_000).toISOString()
    const withOldest = (days: number | null) => ({
      ...sys.retention,
      oldest_event_at: days === null ? null : at(days),
    })
    const full = { ...GUARD, max_bytes: 10e9 }

    it("keeps the plain sentence when the window is filled", () => {
      const plain = "Raw events are kept for 90 days; aggregates are kept forever."
      expect(retentionFinding(withOldest(89), null, NOW)).toBe(plain)
      expect(retentionFinding(withOldest(90), full, NOW)).toBe(plain)
      expect(retentionFinding(withOldest(null), full, NOW)).toBe(plain)
    })

    it("says plainly that a young store has not filled the window", () => {
      expect(retentionFinding(withOldest(5), GUARD, NOW)).toBe(
        "Raw events are set to be kept for 90 days; the oldest stored event is 5 days old, so the store has not filled that window yet.",
      )
      expect(retentionFinding(withOldest(5), null, NOW)).toMatch(/has not filled/)
    })

    it("blames the size limit when the guard dropped data", () => {
      const trimmed = { ...full, state: "trimmed" as const, last_trim_at: at(1) }
      expect(retentionFinding(withOldest(12), trimmed, NOW)).toBe(
        "Raw events are set to be kept for 90 days, but the oldest stored event is 12 days old: the 10 GB size limit removes older data first.",
      )
    })

    it("blames the size limit when the database is near it", () => {
      expect(retentionFinding(withOldest(12), { ...full, percent: 85 }, NOW)).toMatch(
        /10 GB size limit/,
      )
    })

    it("handles retention without a time window", () => {
      expect(retentionFinding({ ...sys.retention, raw_days: null }, null, NOW)).toMatch(
        /until the disk guard trims/,
      )
    })
  })

  it("formats bytes", () => {
    expect(formatBytes(820)).toBe("820 B")
    expect(formatBytes(3_200_000_000)).toBe("3.2 GB")
    expect(formatBytes(512_000_000)).toBe("512 MB")
  })
})

describe("provider key status", () => {
  it("names the source", () => {
    expect(sourceLabel("env")).toBe("From .env")
    expect(sourceLabel("settings")).toBe("Set in Settings")
    expect(sourceLabel(null)).toBe("No key")
  })

  it("reports a pending test, then its outcome", () => {
    const requested = new Date(NOW - 5_000).toISOString()
    const pending = {
      ...NO_KEY,
      configured: true,
      test_pending: true,
      test_requested_at: requested,
    }
    expect(testMessage(pending, NOW)).toEqual({ tone: "pending", text: "Testing the key…" })
    expect(keyInFlight(pending, NOW)).toBe(true)

    const stale = { ...pending, test_requested_at: new Date(NOW - 120_000).toISOString() }
    expect(testMessage(stale, NOW)?.tone).toBe("warning")
    expect(keyInFlight(stale, NOW)).toBe(false)

    const checked_at = new Date(NOW).toISOString()
    const ok = { ...NO_KEY, test: { ok: true, error: null, checked_at } }
    expect(testMessage(ok, NOW)).toEqual({ tone: "ok", text: "The provider accepted the key." })
    const bad = { ...NO_KEY, test: { ok: false, error: "auth", checked_at } }
    expect(testMessage(bad, NOW)?.text).toMatch(/rejected the key/)
    expect(testMessage(NO_KEY, NOW)).toBeNull()
  })

  it("tracks a saved key that ingest has not applied yet", () => {
    expect(keyInFlight({ ...NO_KEY, pending_apply: true }, NOW)).toBe(true)
    expect(keyInFlight(NO_KEY, NOW)).toBe(false)
  })

  it("explains a saved key that cannot be used", () => {
    expect(secretErrorMessage("cannot_decrypt")).toMatch(/SETTINGS_ENCRYPTION_KEY changed/)
    expect(secretErrorMessage("no_encryption_key")).toMatch(/not set/)
    expect(secretErrorMessage(null)).toBeNull()
  })
})
