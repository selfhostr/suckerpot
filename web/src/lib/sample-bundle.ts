/**
 * The sample bundle: up to 10 stored samples the administrator collects, page by page, before
 * downloading them as one encrypted zip for a public malware repository. The selection lives in
 * this browser tab only (sessionStorage); nothing is uploaded anywhere, the owner does that himself.
 */
import { useSyncExternalStore } from "react"
import { ApiError, sendForDownload } from "./api"
import { t } from "@/i18n"
import { UserError } from "./users"

/** The server refuses more (§8.4 of the M22 design). */
export const BUNDLE_MAX = 10
const KEY = "sp.sample-bundle"
const SHA256 = /^[0-9a-f]{64}$/

const listeners = new Set<() => void>()
let cache: string[] | null = null

function read(): string[] {
  if (cache) return cache
  let list: string[] = []
  try {
    const raw: unknown = JSON.parse(sessionStorage.getItem(KEY) ?? "[]")
    if (Array.isArray(raw))
      list = raw.filter((x): x is string => typeof x === "string" && SHA256.test(x))
  } catch {
    // Storage blocked or corrupt: start empty.
  }
  cache = list.slice(0, BUNDLE_MAX)
  return cache
}

function write(list: string[]): void {
  cache = list
  try {
    sessionStorage.setItem(KEY, JSON.stringify(list))
  } catch {
    // Storage blocked: the selection still works until the tab closes.
  }
  for (const l of listeners) l()
}

export const sampleBundle = {
  list: read,
  has: (sha256: string) => read().includes(sha256),
  add: (sha256: string): boolean => {
    const list = read()
    if (list.includes(sha256)) return true
    if (list.length >= BUNDLE_MAX || !SHA256.test(sha256)) return false
    write([...list, sha256])
    return true
  },
  remove: (sha256: string) => write(read().filter((s) => s !== sha256)),
  clear: () => write([]),
  subscribe: (l: () => void): (() => void) => {
    listeners.add(l)
    return () => listeners.delete(l)
  },
}

/** The hashes in the bundle, kept in step with every page that shows it. */
export function useSampleBundle(): string[] {
  return useSyncExternalStore(sampleBundle.subscribe, read, () => [])
}

/** The sentence above the bundle. */
export function describeBundle(n: number): string {
  if (n === 0) return t("samples_bundle_empty")
  const room = BUNDLE_MAX - n
  return t(room === 0 ? "samples_bundle_full" : "samples_bundle_room", { count: n, room })
}

export interface BundleResult {
  blob: Blob
  filename: string
  /** Hashes the identity check left out of the zip. */
  excluded: string[]
}

/** Admin only; the server asks for the password again. Resolves to the encrypted zip. */
export async function downloadBundle(sha256: string[], password: string): Promise<BundleResult> {
  try {
    const { blob, filename, headers } = await sendForDownload("/abuse/exports/samples", {
      sha256,
      password,
    })
    const excluded = (headers.get("X-Excluded-Samples") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => SHA256.test(s))
    return { blob, filename: filename ?? "samples.zip", excluded }
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.code === "reauth_failed") throw new UserError("wrong-password")
      if (e.code === "all_excluded") throw new UserError("excluded")
      if (e.status === 429) throw new UserError("rate-limited")
      if (e.status === 404) throw new UserError("unavailable")
      if (e.status === 401) throw new UserError("session")
      if (e.status === 422) throw new UserError("invalid")
    }
    throw new UserError("network")
  }
}
