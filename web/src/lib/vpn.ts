/**
 * VPN configuration (M23): shapes of `/api/v1/settings/vpn` (docs/dev/design/m23.md section 6 is the
 * contract), the plain-English sentences of the tab, and the calls. The uploaded file text is
 * only ever passed through: it is never stored or logged here.
 */
import { ApiError, getJson, sendJson } from "./api"
import { UserError } from "./users"

/** The server refuses a file bigger than this (413). */
export const VPN_CONF_MAX_BYTES = 4096

/** After "Check now" the tab looks every 3 seconds, for one minute at most. */
export const CHECK_POLL_MS = 3_000
export const CHECK_WATCH_MS = 60_000

/** How long the tab keeps looking after an upload, and how often. */
export const SWITCH_WATCH_MS = 120_000
export const SWITCH_POLL_MS = 5_000

export interface VpnGate {
  state: "open" | "closed"
  reason: string | null
  egress_ip: string | null
  /** The network the exit address belongs to, when enrichment knows it. */
  egress_asn: number | null
  egress_org: string | null
  checked_at: string | null
}

export interface TrustedExit {
  id: number
  cidr: string
  created_at: string
  created_by: string
}

export interface VpnStatus {
  source: "env" | "upload"
  uploaded_at: string | null
  uploaded_by: string | null
  endpoint_ip: string | null
  endpoint_port: number | null
  addresses: string[] | null
  peer_key_fingerprint: string | null
  gate: VpnGate
  trusted_exits: TrustedExit[]
  /** The /24 or /48 the gate observed and the owner may trust; null when there is none. */
  trust_candidate: string | null
  /** Why the exit cannot be trusted at all (then `trust_candidate` is null). */
  trust_blocked: "exit_is_self" | "exit_asn_denied" | null
  /** False when the vpn-config volume is not mounted or not writable. */
  config_writable: boolean
  /** The most recent "Check now" request, or null when none was made. */
  last_check_request?: VpnCheckRequest | null
}

/** The last "Check now" request (M24), so the tab can tell when ingest has answered it. */
export interface VpnCheckRequest {
  requested_at: string
  done_at: string | null
}

export const vpnKeys = { status: ["settings", "vpn"] as const }

// --- Sentences -------------------------------------------------------------------

/** Parser problem codes (422 `problems`), as readable sentences. Unknown codes fall back. */
const PROBLEMS: Record<string, string> = {
  too_large: "The file is bigger than 4 KiB.",
  not_ascii: "The file contains characters that are not plain text.",
  empty: "The file is empty.",
  missing_private_key: "The [Interface] section has no PrivateKey.",
  bad_private_key: "The PrivateKey is not a valid WireGuard key.",
  missing_public_key: "The [Peer] section has no PublicKey.",
  bad_public_key: "The peer PublicKey is not a valid WireGuard key.",
  missing_address: "The [Interface] section has no Address.",
  no_ipv4_address: "The Address list needs at least one IPv4 address.",
  bad_address: "An Address entry is not a valid network address.",
  missing_endpoint: "The [Peer] section has no Endpoint.",
  endpoint_not_ip: "The Endpoint must be an IPv4 address and a port, not a host name.",
  endpoint_not_global: "The Endpoint must be a public address.",
  bad_port: "The Endpoint port must be between 1 and 65535.",
  not_full_tunnel: "AllowedIPs must contain 0.0.0.0/0, so that all traffic uses the tunnel.",
  preshared_key_refused: "A PresharedKey is not supported yet.",
  forbidden_key: "The file uses a setting that is not allowed (such as PostUp or Table).",
  unknown_key: "The file uses a setting that is not recognised.",
  unknown_section: "The file has a section other than [Interface] and [Peer].",
  duplicate_section: "The file has more than one [Interface] or [Peer] section.",
  missing_section: "The file needs one [Interface] and one [Peer] section.",
  duplicate_key: "A setting appears twice in the same section.",
  syntax: "A line in the file is not in the form key = value.",
}

const GENERIC_PROBLEM = "The file is not a valid WireGuard configuration."

export function describeProblem(code: string): string {
  return PROBLEMS[code] ?? GENERIC_PROBLEM
}

/** One sentence per distinct problem, at most five. */
export function describeProblems(codes: readonly string[]): string {
  const unique = [...new Set(codes.map(describeProblem))]
  if (unique.length === 0) return GENERIC_PROBLEM
  return unique.slice(0, 5).join(" ")
}

export const VPN_MESSAGES = {
  tooLarge: "The file is bigger than 4 KiB. A WireGuard configuration is much smaller.",
  noCandidate: "There is no new exit to trust right now. The status has been refreshed.",
  tooMany: "Eight exits are already trusted. Remove one first.",
  unavailable:
    "The VPN configuration store is not available. Check that the vpn-config volume is mounted.",
  exitIsSelf: "This exit is the address of this system itself, so it cannot be trusted.",
  exitAsnDenied: "This exit network is on your deny list, so it cannot be trusted.",
  forbidden: "Only an administrator can change the VPN.",
  notFound: "That entry no longer exists. The status has been refreshed.",
  generic: "The change could not be made. Try again in a moment.",
  checkTooSoon: "Just asked, wait a few seconds.",
  reconnectTooSoon: "The tunnel was restarted a moment ago. Wait a minute, then try again.",
} as const

/** The machine-readable reason, wherever the API put it (`code`, `error` or a string `detail`). */
function reasonOf(e: ApiError): string | undefined {
  if (e.code) return e.code
  const error = e.body?.error
  return typeof error === "string" ? error : e.message
}

function problemCodes(e: ApiError): string[] {
  const detail = e.body?.detail
  const raw =
    e.body?.problems ??
    (detail && typeof detail === "object" ? (detail as Record<string, unknown>).problems : null)
  return Array.isArray(raw) ? raw.filter((p): p is string => typeof p === "string") : []
}

/** Maps an API failure to a UserError the shared password dialog can show. */
export function toVpnError(e: unknown): UserError {
  if (e instanceof UserError) return e
  if (!(e instanceof ApiError)) return new UserError("network")
  const reason = reasonOf(e)
  if (reason === "reauth_failed") return new UserError("wrong-password")
  if (e.status === 401) return new UserError("session")
  if (e.status === 429) return new UserError("rate-limited")
  if (e.status === 413 || reason === "too_large")
    return new UserError("invalid", VPN_MESSAGES.tooLarge)
  if (e.status === 422) return new UserError("invalid", describeProblems(problemCodes(e)))
  if (e.status === 409) {
    const text =
      reason === "too_many"
        ? VPN_MESSAGES.tooMany
        : reason === "exit_is_self"
          ? VPN_MESSAGES.exitIsSelf
          : reason === "exit_asn_denied"
            ? VPN_MESSAGES.exitAsnDenied
            : VPN_MESSAGES.noCandidate
    return new UserError("invalid", text)
  }
  if (e.status === 503 || reason === "vpn_config_unavailable")
    return new UserError("invalid", VPN_MESSAGES.unavailable)
  if (e.status === 403) return new UserError("invalid", VPN_MESSAGES.forbidden)
  if (e.status === 404) return new UserError("not-found", VPN_MESSAGES.notFound)
  return new UserError("invalid", VPN_MESSAGES.generic)
}

/** The sentence above the status card. */
export function describeVpn(v: VpnStatus): string {
  const ip = v.gate.egress_ip
  if (v.gate.state === "closed") {
    if (v.trust_blocked)
      return `The gate is closed: the exit ${ip ?? "address"} looks like ${
        v.trust_blocked === "exit_is_self" ? "your own connection" : "a network you denied"
      }.`
    if (v.trust_candidate && ip) return `The gate is closed: the new exit ${ip} is not trusted yet.`
    return "The gate is closed: outbound lookups are paused."
  }
  const how = v.source === "upload" ? "uploaded configuration" : "settings from .env"
  return ip ? `Traffic leaves through ${ip} (${how}).` : `Using the ${how}.`
}

// --- Calls -----------------------------------------------------------------------

async function guarded<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    throw toVpnError(e)
  }
}

export const vpnApi = {
  status: () => getJson<VpnStatus>("/settings/vpn"),
  upload: (conf: string, password: string) =>
    guarded(() => sendJson<VpnStatus>("PUT", "/settings/vpn", { conf, password })),
  revert: (password: string) => guarded(() => sendJson("DELETE", "/settings/vpn", { password })),
  trust: (password: string) =>
    guarded(() => sendJson<TrustedExit>("POST", "/settings/vpn/trusted-exits", { password })),
  untrust: (id: number, password: string) =>
    guarded(() => sendJson("DELETE", `/settings/vpn/trusted-exits/${id}`, { password })),
  /** Asks ingest to look at the exit now. No password. 429 `too_soon`: asked a moment ago. */
  check: () =>
    guarded(async () => {
      try {
        return await sendJson<{ requested_at?: string } | undefined>("POST", "/settings/vpn/check")
      } catch (e) {
        if (e instanceof ApiError && e.status === 429)
          throw new UserError("rate-limited", VPN_MESSAGES.checkTooSoon)
        throw e
      }
    }),
  /** Restarts the tunnel. Password again. 429: restarted less than a minute ago. */
  reconnect: (password: string) =>
    guarded(async () => {
      try {
        await sendJson("POST", "/settings/vpn/reconnect", { password })
      } catch (e) {
        if (e instanceof ApiError && e.status === 429)
          throw new UserError("rate-limited", VPN_MESSAGES.reconnectTooSoon)
        throw e
      }
    }),
}

/**
 * Has ingest answered the check asked at `since` (epoch ms)? Yes when the gate was looked at
 * after the request, or when the request row itself is marked done.
 */
export function checkAnswered(v: VpnStatus, since: number): boolean {
  const at = v.gate.checked_at ? Date.parse(v.gate.checked_at) : NaN
  if (!Number.isNaN(at) && at > since) return true
  const r = v.last_check_request
  return !!r?.done_at && Date.parse(r.requested_at) >= since
}

/** "AS64500 Example Networks", or null when the network is not known. */
export function describeNetwork(g: Pick<VpnGate, "egress_asn" | "egress_org">): string | null {
  if (g.egress_asn === null && !g.egress_org) return null
  return [g.egress_asn === null ? null : `AS${g.egress_asn}`, g.egress_org]
    .filter(Boolean)
    .join(" ")
}
