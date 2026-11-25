/** Probable command-and-control addresses (read-only): types, wording and the page sentence. */
import { t } from "@/i18n"
import { safeReference } from "./infrastructure"

export type C2Confidence = "high" | "medium"

export interface C2Hash {
  sha256: string
  family: string | null
}

export interface C2Address {
  /** Raw address. Never rendered: the UI only shows `defanged`. */
  address: string
  defanged: string
  kind: "ip" | "domain"
  port: number | null
  confidence: C2Confidence
  sources: ("virustotal" | "threatfox")[]
  families: string[]
  hashes: C2Hash[]
  hash_count: number
  sessions: number
  first_seen: string
  last_seen: string
  references: string[]
}

export interface C2Page {
  items: C2Address[]
  next_cursor: string | null
}

export const C2_CONFIDENCE_LABELS: Record<C2Confidence, string> = {
  get high() {
    return t("c2_confidence_high")
  },
  get medium() {
    return t("c2_confidence_medium")
  },
}

/** Only the https links to the intel services are ever shown. */
export function c2References(item: Pick<C2Address, "references">): string[] {
  return item.references.map(safeReference).filter((u): u is string => u !== null)
}

export function referenceLabel(url: string): string {
  return url.startsWith("https://www.virustotal.com/") ? "VirusTotal" : "ThreatFox"
}

/** The sentence the section opens with. */
export function describeC2(items: readonly C2Address[], more: boolean): string {
  if (items.length === 0) return t("c2_describe_none")
  const single = items.length === 1 && !more
  const high = items.filter((i) => i.confidence === "high").length
  return t("c2_describe", {
    shown: `${items.length}${more ? "+" : ""}`,
    single: single ? "yes" : "no",
    high,
  })
}
