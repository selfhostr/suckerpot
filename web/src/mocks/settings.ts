import { delay, http, HttpResponse } from "msw"
import type {
  EnrichmentSettings,
  KeyInfo,
  KeySource,
  KeyTest,
  ProviderId,
  SystemSettings,
} from "@/lib/settings"

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString()
const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000).toISOString()

/** `GET /api/v1/settings/system`: most sensors busy, RDP quiet for a couple of hours, SIP silent. */
export function systemSettings(): SystemSettings {
  return {
    sensors: [
      { sensor: "ssh", last_event_at: minutesAgo(0.2), events_last_hour: 2_418, status: "active" },
      { sensor: "telnet", last_event_at: minutesAgo(1), events_last_hour: 1_096, status: "active" },
      { sensor: "adb", last_event_at: minutesAgo(6), events_last_hour: 214, status: "active" },
      { sensor: "web", last_event_at: minutesAgo(3), events_last_hour: 1_731, status: "active" },
      { sensor: "docker", last_event_at: minutesAgo(4), events_last_hour: 388, status: "active" },
      { sensor: "redis", last_event_at: minutesAgo(0.5), events_last_hour: 902, status: "active" },
      { sensor: "mysql", last_event_at: minutesAgo(2), events_last_hour: 655, status: "active" },
      { sensor: "mssql", last_event_at: minutesAgo(8), events_last_hour: 471, status: "active" },
      { sensor: "rdp", last_event_at: minutesAgo(134), events_last_hour: 0, status: "quiet" },
      { sensor: "smb", last_event_at: minutesAgo(1), events_last_hour: 1_204, status: "active" },
      { sensor: "sip", last_event_at: daysAgo(2), events_last_hour: 0, status: "silent" },
      { sensor: "synology", last_event_at: minutesAgo(7), events_last_hour: 63, status: "active" },
    ],
    retention: {
      raw_days: 90,
      compression_after_days: 7,
      oldest_event_at: daysAgo(21),
      aggregates: ["events_hourly", "events_daily_tags", "events_daily_country", "events_daily_ip"],
    },
    disk_guard: {
      state: "ok",
      active: true,
      size_bytes: 3_412_000_000,
      max_bytes: 20_000_000_000,
      percent: 17.1,
      last_trim_at: null,
      last_trim_chunks: null,
    },
    ingest_disk: {
      degraded: false,
      degraded_writes: 0,
      size_bytes: 41_000_000,
      max_bytes: 1_000_000_000,
      percent: 4.1,
    },
    database: { size_bytes: 3_412_000_000, max_bytes: 20_000_000_000 },
  }
}

interface MockKey {
  source: KeySource | null
  last4: string | null
  updatedAt: string | null
  test: KeyTest | null
  testRequestedAt: string | null
  /** When a pending test resolves (mock "ingest" answers after a couple of seconds). */
  testDoneAt: number | null
}

/** In-memory keys so the demo and the screenshots can really set, test and remove a key. */
const keys: Record<ProviderId, MockKey> = {
  abuseipdb: {
    source: "env",
    last4: null,
    updatedAt: null,
    test: null,
    testRequestedAt: null,
    testDoneAt: null,
  },
  greynoise: {
    source: "settings",
    last4: "7c2f",
    updatedAt: minutesAgo(125),
    test: { ok: true, error: null, checked_at: minutesAgo(20) },
    testRequestedAt: minutesAgo(20.5),
    testDoneAt: null,
  },
  nvd: {
    source: null,
    last4: null,
    updatedAt: null,
    test: null,
    testRequestedAt: null,
    testDoneAt: null,
  },
  github: {
    source: null,
    last4: null,
    updatedAt: null,
    test: null,
    testRequestedAt: null,
    testDoneAt: null,
  },
  maxmind: {
    source: null,
    last4: null,
    updatedAt: null,
    test: null,
    testRequestedAt: null,
    testDoneAt: null,
  },
  abusech: {
    source: "settings",
    last4: "9d41",
    updatedAt: minutesAgo(60 * 30),
    test: { ok: true, error: null, checked_at: minutesAgo(60 * 29) },
    testRequestedAt: minutesAgo(60 * 29 + 1),
    testDoneAt: null,
  },
  virustotal: {
    source: null,
    last4: null,
    updatedAt: null,
    test: null,
    testRequestedAt: null,
    testDoneAt: null,
  },
}

const PASSWORD_REFUSED = "wrong"

function keyInfo(id: ProviderId): KeyInfo {
  const k = keys[id]
  // The mock ingest answers a test about 2.5 s after the request.
  if (k.testDoneAt !== null && Date.now() >= k.testDoneAt) {
    k.test = { ok: true, error: null, checked_at: new Date().toISOString() }
    k.testDoneAt = null
  }
  return {
    configured: k.source !== null,
    source: k.source,
    last4: k.last4,
    updated_at: k.updatedAt,
    secret_error: null,
    pending_apply: false,
    test: k.test,
    test_pending: k.testDoneAt !== null,
    test_requested_at: k.testRequestedAt,
  }
}

/** `GET /api/v1/settings/enrichment`: DB-IP Lite, AbuseIPDB from .env, GreyNoise set in Settings. */
export function enrichmentSettings(): EnrichmentSettings {
  const editingOff =
    new URLSearchParams(typeof window === "undefined" ? "" : window.location.search).get("keys") ===
    "off"
  return {
    geoip: {
      provider: "dbip",
      available: true,
      files: {
        city: {
          file: "dbip-city-lite.mmdb",
          bytes: 131_072_000,
          updated_at: daysAgo(23.6),
          age_days: 23.6,
        },
        asn: {
          file: "dbip-asn-lite.mmdb",
          bytes: 9_437_184,
          updated_at: daysAgo(23.6),
          age_days: 23.6,
        },
      },
      last_error: null,
      refresh_days: 30,
      attribution: "IP geolocation by DB-IP.com (https://db-ip.com), CC BY 4.0",
    },
    abuseipdb: {
      ...keyInfo("abuseipdb"),
      daily_quota: 1_000,
      used_today: 312,
      disabled: null,
      paused: false,
      last_error: null,
    },
    greynoise: {
      ...keyInfo("greynoise"),
      daily_quota: 50,
      used_today: 18,
      disabled: null,
      paused: false,
      last_error: null,
    },
    abusech: {
      ...keyInfo("abusech"),
      daily_quota: 1_000,
      used_today: 164,
      disabled: null,
      paused: false,
      last_error: null,
    },
    virustotal: {
      ...keyInfo("virustotal"),
      daily_quota: 400,
      used_today: 0,
      disabled: null,
      paused: false,
      last_error: null,
    },
    maxmind: keyInfo("maxmind"),
    nvd: keyInfo("nvd"),
    github: keyInfo("github"),
    key_editing: editingOff
      ? {
          enabled: false,
          reason: "Set SETTINGS_ENCRYPTION_KEY in .env to enable editing keys here.",
        }
      : { enabled: true, reason: null },
    reported_at: minutesAgo(2),
  }
}

const isProvider = (v: unknown): v is ProviderId =>
  v === "abuseipdb" ||
  v === "greynoise" ||
  v === "maxmind" ||
  v === "nvd" ||
  v === "github" ||
  v === "abusech" ||
  v === "virustotal"

const reauthFailed = () =>
  HttpResponse.json(
    { detail: "The password is incorrect.", code: "reauth_failed" },
    { status: 403 },
  )

export const settingsHandlers = [
  http.get("/api/v1/settings/system", async () => {
    await delay(150)
    return HttpResponse.json(systemSettings())
  }),
  http.get("/api/v1/settings/enrichment", async () => {
    await delay(150)
    return HttpResponse.json(enrichmentSettings())
  }),
  http.put("/api/v1/settings/providers/:provider", async ({ params, request }) => {
    await delay(300)
    const id = params.provider
    const body = (await request.json()) as { key?: string; password?: string }
    if (!isProvider(id) || typeof body.key !== "string")
      return new HttpResponse(null, { status: 422 })
    if (!body.password || body.password === PASSWORD_REFUSED) return reauthFailed()
    keys[id] = {
      source: "settings",
      last4: body.key.slice(-4),
      updatedAt: new Date().toISOString(),
      test: null,
      testRequestedAt: null,
      testDoneAt: null,
    }
    return HttpResponse.json({
      provider: id,
      source: "settings",
      last4: keys[id].last4,
      updated_at: keys[id].updatedAt,
    })
  }),
  http.delete("/api/v1/settings/providers/:provider", async ({ params, request }) => {
    await delay(300)
    const id = params.provider
    const body = (await request.json()) as { password?: string }
    if (!isProvider(id)) return new HttpResponse(null, { status: 422 })
    if (!body.password || body.password === PASSWORD_REFUSED) return reauthFailed()
    keys[id] = {
      source: id === "abuseipdb" ? "env" : null,
      last4: null,
      updatedAt: null,
      test: null,
      testRequestedAt: null,
      testDoneAt: null,
    }
    return new HttpResponse(null, { status: 204 })
  }),
  http.post("/api/v1/settings/providers/:provider/test", async ({ params }) => {
    await delay(200)
    const id = params.provider
    if (!isProvider(id) || keys[id].source === null)
      return HttpResponse.json(
        { detail: "There is no key to test.", code: "no_key" },
        { status: 409 },
      )
    keys[id].testRequestedAt = new Date().toISOString()
    keys[id].testDoneAt = Date.now() + 2_500
    return HttpResponse.json(
      { provider: id, requested_at: keys[id].testRequestedAt },
      { status: 202 },
    )
  }),
]
