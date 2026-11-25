/** Client for /api/v1/auth/*. Cookies are httpOnly: the UI only ever learns who is signed in. */
import { ApiError, API_BASE, sendJson } from "@/lib/api"
import { t, tk } from "@/i18n"
import { withText } from "@/lib/utils"

export type Role = "admin" | "viewer"

export interface AuthUser {
  username: string
  display_name: string
  role: Role
  /** The account from `.env`: always an administrator, its password lives in `.env` too. */
  is_owner: boolean
  /** True until the user has chosen their own password: nothing else is reachable. */
  must_change_password: boolean
  /** True for a viewer: the whole interface is read-only. */
  read_only: boolean
  /** The sign-in before this one, if there was one. */
  last_login_at: string | null
}

/** Resolves to the signed-in user, or null when there is no valid session. */
export async function fetchMe(): Promise<AuthUser | null> {
  const res = await fetch(`${API_BASE}/auth/me`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
  if (res.status === 401) return null
  if (!res.ok) throw new ApiError(res.status, res.statusText)
  return (await res.json()) as AuthUser
}

export type LoginFailure = "invalid" | "rate-limited" | "origin" | "network"

export class LoginError extends Error {
  constructor(
    readonly reason: LoginFailure,
    readonly retryAfterSeconds?: number,
  ) {
    super(reason)
    this.name = "LoginError"
  }
}

/** Never reveals which of the two fields was wrong. */
export async function loginRequest(username: string, password: string): Promise<void> {
  try {
    await sendJson(
      "POST",
      "/auth/login",
      { username, password },
      { csrf: false, notifyUnauthorized: false },
    )
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.status === 429) throw new LoginError("rate-limited")
      if (e.status === 401) throw new LoginError("invalid")
      if (e.status === 403) throw new LoginError("origin")
    }
    throw new LoginError("network")
  }
}

export async function logoutRequest(): Promise<void> {
  try {
    await sendJson("POST", "/auth/logout", undefined, { notifyUnauthorized: false })
  } catch (e) {
    // 401: already signed out. Anything else: the cookie may live on, but the UI still leaves.
    if (!(e instanceof ApiError)) throw e
  }
}

/** Only same-app paths are valid redirect targets (no open redirect, no loop through /login). */
export function safeNext(raw: string | null | undefined): string {
  const fallback = "/"
  // eslint-disable-next-line no-control-regex -- control characters and whitespace are the point
  if (!raw || /[\x00-\x20\x7f]/.test(raw) || !raw.startsWith("/") || raw.startsWith("//")) {
    return fallback
  }
  if (raw.includes("\\")) return fallback
  let url: URL
  try {
    url = new URL(raw, window.location.origin)
  } catch {
    return fallback
  }
  if (url.origin !== window.location.origin || url.pathname.startsWith("//")) return fallback
  if (url.pathname === "/login") return fallback
  return raw
}

export type PasswordFailure =
  "wrong-password" | "weak" | "owner" | "rate-limited" | "session" | "network"

export class PasswordError extends Error {
  constructor(
    readonly reason: PasswordFailure,
    /** The API's own sentence, shown for `weak`. */
    readonly detail?: string,
  ) {
    super(reason)
    this.name = "PasswordError"
  }
}

export const PASSWORD_MESSAGES: Record<Exclude<PasswordFailure, "weak">, string> = withText(
  {
    "wrong-password": tk("auth_pwd_wrong"),
    owner: tk("auth_pwd_owner"),
    "rate-limited": tk("auth_rate_limited"),
    session: tk("auth_pwd_session"),
    network: tk("auth_network"),
  },
  {},
)

export function describePasswordError(e: unknown): string {
  if (e instanceof PasswordError) {
    if (e.reason === "weak") return e.detail ?? t("auth_pwd_choose_different")
    return PASSWORD_MESSAGES[e.reason]
  }
  return PASSWORD_MESSAGES.network
}

/** Changes the signed-in user's own password. The current one is required; the new one is
 * checked again by the server. Other sessions of the user end, this browser stays signed in. */
export async function changePasswordRequest(current: string, next: string): Promise<void> {
  try {
    await sendJson("POST", "/auth/password", { current_password: current, new_password: next })
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.code === "reauth_failed") throw new PasswordError("wrong-password")
      if (e.code === "weak_password") throw new PasswordError("weak", e.message)
      if (e.code === "owner_password_in_env") throw new PasswordError("owner")
      if (e.status === 429) throw new PasswordError("rate-limited")
      if (e.status === 401) throw new PasswordError("session")
    }
    throw new PasswordError("network")
  }
}

export const MIN_PASSWORD_LENGTH = 12
export const MAX_PASSWORD_LENGTH = 256

/** The same rules the server enforces (it checks again, and also rejects common passwords). */
export function validateNewPassword(
  password: string,
  username: string,
  current?: string,
): string | null {
  if (password.length < MIN_PASSWORD_LENGTH)
    return t("auth_pwd_min_length", { count: MIN_PASSWORD_LENGTH })
  if (password.length > MAX_PASSWORD_LENGTH)
    return t("auth_pwd_max_length", { count: MAX_PASSWORD_LENGTH })
  if (username && password.toLowerCase().includes(username.trim().toLowerCase()))
    return t("auth_pwd_contains_username")
  if (current !== undefined && password === current)
    return t("auth_pwd_same_as_current")
  return null
}
