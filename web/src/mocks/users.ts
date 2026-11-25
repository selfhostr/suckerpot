import { mockRandom } from "./random"
import { delay, http, HttpResponse } from "msw"
import { demoMode } from "@/app/demo-role"
import type { AuthUser, Role } from "@/lib/auth-api"
import type { AuditEntry, UserItem } from "@/lib/users"

const LATENCY_MS = 160
const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString()
const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000).toISOString()

/** Whether the first-login screen has been completed in this page load (mock only). */
let passwordChosen = false

function me(): AuthUser {
  const mode = demoMode()
  const who =
    mode === "viewer"
      ? { username: "colleague", display_name: "A Colleague", role: "viewer" as const }
      : mode === "first-login"
        ? { username: "jordan", display_name: "Jordan Lee", role: "viewer" as const }
        : { username: "admin", display_name: "Admin", role: "admin" as const }
  return {
    ...who,
    is_owner: mode === "admin",
    must_change_password: mode === "first-login" && !passwordChosen,
    read_only: who.role === "viewer",
    last_login_at: daysAgo(1),
  }
}

let nextId = 6
const users: UserItem[] = [
  {
    id: 1,
    username: "colleague",
    display_name: "A Colleague",
    role: "viewer",
    is_owner: false,
    disabled: false,
    must_change_password: false,
    locked_until: null,
    created_at: daysAgo(12),
    created_by: "admin",
    last_login_at: minutesAgo(95),
    password_changed_at: daysAgo(12),
  },
  {
    id: 2,
    username: "sam",
    display_name: "Sam Rivers",
    role: "admin",
    is_owner: false,
    disabled: false,
    must_change_password: false,
    locked_until: null,
    created_at: daysAgo(30),
    created_by: "admin",
    last_login_at: daysAgo(2),
    password_changed_at: daysAgo(9),
  },
  {
    id: 3,
    username: "jordan",
    display_name: "Jordan Lee",
    role: "viewer",
    is_owner: false,
    disabled: false,
    must_change_password: true,
    locked_until: null,
    created_at: minutesAgo(40),
    created_by: "admin",
    last_login_at: null,
    password_changed_at: null,
  },
  {
    id: 4,
    username: "riley",
    display_name: "Riley Chen",
    role: "viewer",
    is_owner: false,
    disabled: false,
    must_change_password: false,
    locked_until: new Date(Date.now() + 11 * 60_000).toISOString(),
    created_at: daysAgo(20),
    created_by: "sam",
    last_login_at: daysAgo(4),
    password_changed_at: daysAgo(20),
  },
  {
    id: 5,
    username: "casey",
    display_name: "Casey Park",
    role: "viewer",
    is_owner: false,
    disabled: true,
    must_change_password: false,
    locked_until: null,
    created_at: daysAgo(45),
    created_by: "admin",
    last_login_at: daysAgo(31),
    password_changed_at: daysAgo(45),
  },
]

function ownerItem(): UserItem {
  return {
    id: null,
    username: "admin",
    display_name: "Admin",
    role: "admin",
    is_owner: true,
    disabled: false,
    must_change_password: false,
    locked_until: null,
    created_at: null,
    created_by: null,
    last_login_at: minutesAgo(3),
    password_changed_at: null,
  }
}

const audit: AuditEntry[] = []
let auditId = 1000
function log(
  ageMinutes: number,
  actor: string,
  action: string,
  target: string | null,
  details: Record<string, unknown> = {},
  ip: string | null = "203.0.113.20",
) {
  audit.push({ id: auditId++, ts: minutesAgo(ageMinutes), actor, action, target, ip, details })
}
log(3, "admin", "auth.login", "admin")
log(40, "admin", "user.create", "jordan", { role: "viewer" })
log(95, "colleague", "auth.login", "colleague", {}, "198.51.100.14")
log(180, "sam", "user.role", "colleague", { from: "admin", to: "viewer" }, "198.51.100.77")
log(300, "system", "user.locked", "riley", { failures: 10, actor_id: "system" }, "192.0.2.55")
log(2_900, "admin", "provider_key.set", "abuseipdb")
log(2_950, "sam", "user.reset_password", "riley", {}, "198.51.100.77")
log(3_000, "admin", "user.disable", "casey")
log(4_100, "sam", "auth.login", "sam", {}, "198.51.100.77")
log(17_000, "admin", "user.create", "riley", { role: "viewer" })
log(17_200, "colleague", "password.change", "colleague", {}, "198.51.100.14")
log(17_300, "admin", "user.create", "colleague", { role: "viewer" })
log(43_000, "admin", "user.create", "sam", { role: "admin" })
log(43_100, "admin", "provider_key.remove", "greynoise")
audit.sort((a, b) => b.ts.localeCompare(a.ts))

function encode(offset: number) {
  return btoa(JSON.stringify({ o: offset })).replace(/=+$/, "")
}
function decode(cursor: string | null): number {
  if (!cursor) return 0
  try {
    const v = JSON.parse(atob(cursor)) as { o?: unknown }
    return typeof v.o === "number" ? v.o : 0
  } catch {
    return 0
  }
}

const forbidden = () =>
  HttpResponse.json(
    { detail: "Administrator access required", code: "admin_required" },
    { status: 403 },
  )
const wrongPassword = () =>
  HttpResponse.json(
    { detail: "The password is incorrect.", code: "reauth_failed" },
    { status: 403 },
  )

const isViewer = () => demoMode() === "viewer"

function temporaryPassword() {
  const chars = "abcdefghjkmnpqrstuvwxyzACDEFGHJKLMNPQRTUVWXYZ2346789"
  const part = () =>
    Array.from({ length: 5 }, () => chars[Math.floor(mockRandom() * chars.length)]).join("")
  return `${part()}-${part()}-${part()}-${part()}`
}

function find(id: unknown) {
  return users.find((u) => u.id === Number(id))
}

/** Handlers for accounts, roles and the audit log. Demo data only: nothing here is real. */
export const userHandlers = [
  http.get("/api/v1/auth/me", () => HttpResponse.json(me())),

  http.post("/api/v1/auth/password", async ({ request }) => {
    await delay(LATENCY_MS)
    const body = (await request.json()) as { current_password?: string; new_password?: string }
    if (body.current_password === "wrong") return wrongPassword()
    if ((body.new_password ?? "").length < 12)
      return HttpResponse.json(
        { detail: "Use at least 12 characters.", code: "weak_password" },
        { status: 422 },
      )
    passwordChosen = true
    return new HttpResponse(null, { status: 204 })
  }),

  http.get("/api/v1/users", async ({ request }) => {
    await delay(LATENCY_MS)
    if (isViewer()) return forbidden()
    const url = new URL(request.url)
    const limit = Number(url.searchParams.get("limit") ?? 50)
    const offset = decode(url.searchParams.get("cursor"))
    const items = users.slice(offset, offset + limit)
    return HttpResponse.json({
      owner: ownerItem(),
      items,
      next_cursor: offset + limit < users.length ? encode(offset + limit) : null,
    })
  }),

  http.post("/api/v1/users", async ({ request }) => {
    await delay(LATENCY_MS)
    if (isViewer()) return forbidden()
    const body = (await request.json()) as {
      username: string
      display_name: string
      role: Role
      password: string
    }
    if (body.password === "wrong") return wrongPassword()
    if (
      body.username.toLowerCase() === "admin" ||
      users.some((u) => u.username.toLowerCase() === body.username.toLowerCase())
    )
      return HttpResponse.json(
        { detail: "That username is already taken.", code: "username_taken" },
        { status: 409 },
      )
    const user: UserItem = {
      id: nextId++,
      username: body.username,
      display_name: body.display_name,
      role: body.role,
      is_owner: false,
      disabled: false,
      must_change_password: true,
      locked_until: null,
      created_at: new Date().toISOString(),
      created_by: "admin",
      last_login_at: null,
      password_changed_at: null,
    }
    users.push(user)
    audit.unshift({
      id: auditId++,
      ts: user.created_at ?? new Date().toISOString(),
      actor: "admin",
      action: "user.create",
      target: user.username,
      ip: "203.0.113.20",
      details: { role: user.role },
    })
    return HttpResponse.json(
      { user, temporary_password: temporaryPassword() },
      { status: 201, headers: { "Cache-Control": "no-store" } },
    )
  }),

  http.patch("/api/v1/users/:id", async ({ params, request }) => {
    await delay(LATENCY_MS)
    if (isViewer()) return forbidden()
    const body = (await request.json()) as {
      role?: Role
      disabled?: boolean
      display_name?: string
      password: string
    }
    if (body.password === "wrong") return wrongPassword()
    const user = find(params.id)
    if (!user) return HttpResponse.json({ detail: "gone", code: "not_found" }, { status: 404 })
    if (body.role) user.role = body.role
    if (body.disabled !== undefined) user.disabled = body.disabled
    if (body.display_name) user.display_name = body.display_name
    return HttpResponse.json(user)
  }),

  http.post("/api/v1/users/:id/reset-password", async ({ params, request }) => {
    await delay(LATENCY_MS)
    if (isViewer()) return forbidden()
    const body = (await request.json()) as { password: string }
    if (body.password === "wrong") return wrongPassword()
    const user = find(params.id)
    if (!user) return HttpResponse.json({ detail: "gone", code: "not_found" }, { status: 404 })
    user.must_change_password = true
    user.locked_until = null
    return HttpResponse.json(
      { temporary_password: temporaryPassword() },
      { headers: { "Cache-Control": "no-store" } },
    )
  }),

  http.post("/api/v1/users/:id/unlock", async ({ params, request }) => {
    await delay(LATENCY_MS)
    if (isViewer()) return forbidden()
    const body = (await request.json()) as { password: string }
    if (body.password === "wrong") return wrongPassword()
    const user = find(params.id)
    if (!user) return HttpResponse.json({ detail: "gone", code: "not_found" }, { status: 404 })
    user.locked_until = null
    return HttpResponse.json(user)
  }),

  http.post("/api/v1/users/:id/revoke-sessions", async ({ request }) => {
    await delay(LATENCY_MS)
    if (isViewer()) return forbidden()
    const body = (await request.json()) as { password: string }
    if (body.password === "wrong") return wrongPassword()
    return new HttpResponse(null, { status: 204 })
  }),

  http.delete("/api/v1/users/:id", async ({ params, request }) => {
    await delay(LATENCY_MS)
    if (isViewer()) return forbidden()
    const body = (await request.json()) as { password: string }
    if (body.password === "wrong") return wrongPassword()
    const at = users.findIndex((u) => u.id === Number(params.id))
    if (at < 0) return HttpResponse.json({ detail: "gone", code: "not_found" }, { status: 404 })
    users.splice(at, 1)
    return new HttpResponse(null, { status: 204 })
  }),

  http.get("/api/v1/audit", async ({ request }) => {
    await delay(LATENCY_MS)
    if (isViewer()) return forbidden()
    const url = new URL(request.url)
    const actor = url.searchParams.get("actor")?.toLowerCase()
    const action = url.searchParams.get("action")
    const limit = Number(url.searchParams.get("limit") ?? 50)
    const offset = decode(url.searchParams.get("cursor"))
    let items = audit
    if (actor) items = items.filter((e) => e.actor.toLowerCase() === actor)
    if (action) items = items.filter((e) => e.action.startsWith(action))
    return HttpResponse.json({
      items: items.slice(offset, offset + limit),
      next_cursor: offset + limit < items.length ? encode(offset + limit) : null,
    })
  }),
]
