/**
 * Users and the audit log (administrators only). Every change asks for the administrator's own
 * password again; the temporary password of a new or reset account is returned once and is never
 * kept: callers hold it in component state until the dialog closes.
 */
import { ApiError, API_BASE, sendJson, type Page } from "@/lib/api"
import { t } from "@/i18n"
import type { Role } from "@/lib/auth-api"
import { PROVIDER_NAMES } from "@/lib/provider-keys"
import type { ProviderId } from "@/lib/settings"

export interface UserItem {
  /** Null for the owner account, which lives in `.env` and has no row. */
  id: number | null
  username: string
  display_name: string
  role: Role
  is_owner: boolean
  disabled: boolean
  must_change_password: boolean
  /** Set while the account is locked after repeated wrong passwords. */
  locked_until: string | null
  created_at: string | null
  created_by: string | null
  last_login_at: string | null
  password_changed_at: string | null
}

export interface UserList {
  owner: UserItem
  items: UserItem[]
  next_cursor: string | null
}

export interface AuditEntry {
  id: number
  ts: string
  actor: string
  action: string
  target: string | null
  ip: string | null
  details: Record<string, unknown>
}

export const ROLE_LABEL: Record<Role, string> = {
  get admin() {
    return t("users_role_admin")
  },
  get viewer() {
    return t("users_role_viewer")
  },
}

export const ROLE_OPTIONS = [
  {
    value: "viewer",
    get label() {
      return t("users_role_viewer")
    },
  },
  {
    value: "admin",
    get label() {
      return t("users_role_admin")
    },
  },
] as const

export const ROLE_HINT: Record<Role, string> = {
  get viewer() {
    return t("users_role_viewer_hint")
  },
  get admin() {
    return t("users_role_admin_hint")
  },
}

export type UserState = "active" | "disabled" | "locked" | "pending"

/** One state per account, the most limiting first. */
export function userState(u: UserItem, now: number = Date.now()): UserState {
  if (u.disabled) return "disabled"
  if (u.locked_until && Date.parse(u.locked_until) > now) return "locked"
  if (u.must_change_password) return "pending"
  return "active"
}

export const STATE_LABEL: Record<UserState, string> = {
  get active() {
    return t("users_state_active")
  },
  get disabled() {
    return t("users_state_disabled")
  },
  get locked() {
    return t("users_state_locked")
  },
  get pending() {
    return t("users_state_pending")
  },
}

/** The finding sentence of the Users card. */
export function usersFinding(list: UserList, now: number = Date.now()): string {
  const all = [list.owner, ...list.items]
  const admins = all.filter((u) => u.role === "admin" && !u.disabled).length
  const viewers = all.filter((u) => u.role === "viewer" && !u.disabled).length
  const people = admins + viewers
  let text =
    people === 1
      ? t("users_finding_owner_only")
      : t("users_finding_people", { people, admins, viewers })
  const locked = all.filter((u) => userState(u, now) === "locked").length
  if (locked > 0) text += ` ${t("users_finding_locked", { count: locked })}`
  const waiting = all.filter((u) => userState(u, now) === "pending").length
  if (waiting > 0) text += ` ${t("users_finding_waiting", { count: waiting })}`
  return text
}

const text = (value: unknown) => (typeof value === "string" ? value : "?")

/** "admin" reads as "administrator" in a sentence, like the role badges. */
const roleWord = (value: unknown) =>
  value === "admin" ? t("users_role_admin_word") : text(value)

/** "abuseipdb" reads as "AbuseIPDB", as on the Settings page. */
const providerName = (id: string) => (id in PROVIDER_NAMES ? PROVIDER_NAMES[id as ProviderId] : id)

/** Entries written by SuckerPot itself (the automatic lockout), not by a person. */
export function isSystemActor(e: AuditEntry): boolean {
  const id = e.details.actor_id
  return id === undefined ? e.actor === "system" : id === "system"
}

/** The name that opens an audit sentence: the actor's username, or "System". */
export function auditActorLabel(e: AuditEntry): string {
  return isSystemActor(e) ? t("users_audit_system") : e.actor
}

/** What the actor did, to follow their name: "created the user colleague (viewer)". */
export function describeAudit(e: AuditEntry): string {
  const who = e.target ?? t("users_audit_an_account")
  const d = e.details
  switch (e.action) {
    case "auth.login":
      return t("users_audit_login")
    case "password.change":
      return t("users_audit_password_change")
    case "user.create":
      return typeof d.role === "string"
        ? t("users_audit_create_role", { who, role: roleWord(d.role) })
        : t("users_audit_create", { who })
    case "user.role":
      return t("users_audit_role", { who, from: roleWord(d.from), to: roleWord(d.to) })
    case "user.disable":
      return t("users_audit_disable", { who })
    case "user.enable":
      return t("users_audit_enable", { who })
    case "user.rename":
      return t("users_audit_rename", { who })
    case "user.reset_password":
      return t("users_audit_reset_password", { who })
    case "user.unlock":
      return t("users_audit_unlock", { who })
    case "user.locked":
      // Older entries name the locked user as the actor; newer ones are written by the system.
      return e.target && (isSystemActor(e) || e.actor !== e.target)
        ? t("users_audit_locked_target", { target: e.target })
        : t("users_audit_locked_self")
    case "user.revoke_sessions":
      return t("users_audit_revoke_sessions", { who })
    case "user.delete":
      return t("users_audit_delete", { who })
    case "provider_key.set":
      return t("users_audit_key_set", { provider: providerName(who) })
    case "provider_key.remove":
      return t("users_audit_key_remove", { provider: providerName(who) })
    case "provider_key.test":
      return t("users_audit_key_test", { provider: providerName(who) })
    default:
      return e.target ? t("users_audit_other_on", { action: e.action, target: e.target }) : e.action
  }
}

/** Action filters of the audit log: the server matches them as prefixes. */
export const AUDIT_GROUPS = [
  {
    value: "",
    get label() {
      return t("common_all")
    },
  },
  {
    value: "auth.",
    get label() {
      return t("users_audit_group_auth")
    },
  },
  {
    value: "user.",
    get label() {
      return t("users_audit_group_users")
    },
  },
  {
    value: "provider_key.",
    get label() {
      return t("users_audit_group_keys")
    },
  },
] as const

export type UserFailure =
  | "wrong-password"
  | "taken"
  | "self"
  | "not-found"
  | "rate-limited"
  | "session"
  | "invalid"
  | "network"
  | "unavailable"
  | "excluded"

export class UserError extends Error {
  constructor(
    readonly reason: UserFailure,
    readonly detail?: string,
  ) {
    super(reason)
    this.name = "UserError"
  }
}

export const USER_MESSAGES: Record<UserFailure, string> = {
  get "wrong-password"() {
    return t("users_msg_wrong_password")
  },
  get taken() {
    return t("users_msg_taken")
  },
  get self() {
    return t("users_msg_self")
  },
  get "not-found"() {
    return t("users_msg_not_found")
  },
  get "rate-limited"() {
    return t("users_msg_rate_limited")
  },
  get session() {
    return t("users_msg_session")
  },
  get invalid() {
    return t("users_msg_invalid")
  },
  get network() {
    return t("users_msg_network")
  },
  get unavailable() {
    return t("users_msg_unavailable")
  },
  get excluded() {
    return t("users_msg_excluded")
  },
}

export function describeUserError(e: unknown): string {
  return USER_MESSAGES[e instanceof UserError ? e.reason : "network"]
}

function toUserError(e: unknown): UserError {
  if (e instanceof UserError) return e
  if (e instanceof ApiError) {
    if (e.code === "reauth_failed") return new UserError("wrong-password")
    if (e.code === "session_revoked") return new UserError("session")
    if (e.code === "username_taken") return new UserError("taken")
    if (e.code === "self_action") return new UserError("self")
    if (e.code === "not_found") return new UserError("not-found")
    if (e.status === 429) return new UserError("rate-limited")
    if (e.status === 422) return new UserError("invalid")
    if (e.status === 401) return new UserError("session")
  }
  return new UserError("network")
}

async function run<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    throw toUserError(e)
  }
}

export const USERNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$/

export type NewUserField = "username" | "displayName"

export function validateNewUser(
  username: string,
  displayName: string,
): Partial<Record<NewUserField, string>> {
  const errors: Partial<Record<NewUserField, string>> = {}
  if (!USERNAME_PATTERN.test(username))
    errors.username = t("users_error_username")
  if (!displayName.trim()) errors.displayName = t("users_error_name_required")
  else if (displayName.trim().length > 64) errors.displayName = t("users_error_name_long")
  return errors
}

async function getJson<T>(path: string, params: Record<string, string | undefined>) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v)
  const res = await fetch(`${API_BASE}${path}${qs.size ? `?${qs.toString()}` : ""}`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
  if (!res.ok) throw new ApiError(res.status, res.statusText)
  return (await res.json()) as T
}

export const usersApi = {
  list: (cursor?: string | null) =>
    getJson<UserList>("/users", { cursor: cursor ?? undefined, limit: "50" }),
  audit: (
    filters: { actor?: string | undefined; action?: string | undefined },
    cursor?: string | null,
  ) =>
    getJson<Page<AuditEntry>>("/audit", {
      actor: filters.actor,
      action: filters.action,
      cursor: cursor ?? undefined,
      limit: "25",
    }),
}

export interface NewUser {
  username: string
  displayName: string
  role: Role
}

/** Creates the account and resolves to the one-time temporary password. */
export function createUser(input: NewUser, password: string): Promise<{ temporary: string }> {
  return run(async () => {
    const res = await sendJson<{ temporary_password: string }>("POST", "/users", {
      username: input.username,
      display_name: input.displayName.trim(),
      role: input.role,
      password,
    })
    return { temporary: res.temporary_password }
  })
}

export function updateUser(
  id: number,
  changes: { role?: Role; disabled?: boolean; display_name?: string },
  password: string,
): Promise<void> {
  return run(async () => {
    await sendJson("PATCH", `/users/${id}`, { ...changes, password })
  })
}

export function resetUserPassword(id: number, password: string): Promise<{ temporary: string }> {
  return run(async () => {
    const res = await sendJson<{ temporary_password: string }>(
      "POST",
      `/users/${id}/reset-password`,
      { password },
    )
    return { temporary: res.temporary_password }
  })
}

export function unlockUser(id: number, password: string): Promise<void> {
  return run(async () => {
    await sendJson("POST", `/users/${id}/unlock`, { password })
  })
}

export function revokeUserSessions(id: number, password: string): Promise<void> {
  return run(async () => {
    await sendJson("POST", `/users/${id}/revoke-sessions`, { password })
  })
}

export function deleteUser(id: number, password: string): Promise<void> {
  return run(async () => {
    await sendJson("DELETE", `/users/${id}`, { password })
  })
}
