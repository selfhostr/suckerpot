/**
 * Plain-English definitions of the security terms the UI uses, for the `Term` component.
 * Written for IT staff who are not security specialists: one or two short sentences, no jargon
 * inside the definition itself, nothing that needs a second lookup.
 */
import { tk } from "@/i18n"
import { withText } from "@/lib/utils"

export interface GlossaryEntry {
  /** The word as shown when a screen does not give its own text. */
  term: string
  /** Shown in the tooltip: at most about 200 characters. */
  short: string
}

export const GLOSSARY = {
  asn: withText({ term: tk("glossary_asn_term"), short: tk("glossary_asn_short") }, {}),
  cve: withText({ term: tk("glossary_cve_term"), short: tk("glossary_cve_short") }, {}),
  kev: withText({ term: tk("glossary_kev_term"), short: tk("glossary_kev_short") }, {}),
  rce: withText({ term: tk("glossary_rce_term"), short: tk("glossary_rce_short") }, {}),
  exploit: withText({ term: tk("glossary_exploit_term"), short: tk("glossary_exploit_short") }, {}),
  payload: withText({ term: tk("glossary_payload_term"), short: tk("glossary_payload_short") }, {}),
  "brute-force": withText(
    { term: tk("glossary_brute_force_term"), short: tk("glossary_brute_force_short") },
    {},
  ),
  "credential-stuffing": withText(
    {
      term: tk("glossary_credential_stuffing_term"),
      short: tk("glossary_credential_stuffing_short"),
    },
    {},
  ),
  botnet: withText({ term: tk("glossary_botnet_term"), short: tk("glossary_botnet_short") }, {}),
  c2: withText({ term: tk("glossary_c2_term"), short: tk("glossary_c2_short") }, {}),
  campaign: withText(
    { term: tk("glossary_campaign_term"), short: tk("glossary_campaign_short") },
    {},
  ),
  technique: withText(
    { term: tk("glossary_technique_term"), short: tk("glossary_technique_short") },
    {},
  ),
  indicator: withText(
    { term: tk("glossary_indicator_term"), short: tk("glossary_indicator_short") },
    {},
  ),
  hash: withText({ term: tk("glossary_hash_term"), short: tk("glossary_hash_short") }, {}),
  defanged: withText(
    { term: tk("glossary_defanged_term"), short: tk("glossary_defanged_short") },
    {},
  ),
  "research-scanner": withText(
    { term: tk("glossary_research_scanner_term"), short: tk("glossary_research_scanner_short") },
    {},
  ),
  honeypot: withText(
    { term: tk("glossary_honeypot_term"), short: tk("glossary_honeypot_short") },
    {},
  ),
  "known-scanner": withText(
    { term: tk("glossary_known_scanner_term"), short: tk("glossary_known_scanner_short") },
    {},
  ),
  "abuse-score": withText(
    { term: tk("glossary_abuse_score_term"), short: tk("glossary_abuse_score_short") },
    {},
  ),
  blocklist: withText(
    { term: tk("glossary_blocklist_term"), short: tk("glossary_blocklist_short") },
    {},
  ),
  malware: withText({ term: tk("glossary_malware_term"), short: tk("glossary_malware_short") }, {}),
  scanner: withText({ term: tk("glossary_scanner_term"), short: tk("glossary_scanner_short") }, {}),
  ssh: withText({ term: tk("glossary_ssh_term"), short: tk("glossary_ssh_short") }, {}),
  telnet: withText({ term: tk("glossary_telnet_term"), short: tk("glossary_telnet_short") }, {}),
  rdp: withText({ term: tk("glossary_rdp_term"), short: tk("glossary_rdp_short") }, {}),
  consensus: withText(
    { term: tk("glossary_consensus_term"), short: tk("glossary_consensus_short") },
    {},
  ),
  "blinded-indicator": withText(
    { term: tk("glossary_blinded_indicator_term"), short: tk("glossary_blinded_indicator_short") },
    {},
  ),
  "eligible-node": withText(
    { term: tk("glossary_eligible_node_term"), short: tk("glossary_eligible_node_short") },
    {},
  ),
  "inbound-list": withText(
    { term: tk("glossary_inbound_list_term"), short: tk("glossary_inbound_list_short") },
    {},
  ),
  "outbound-list": withText(
    { term: tk("glossary_outbound_list_term"), short: tk("glossary_outbound_list_short") },
    {},
  ),
  "high-tier": withText(
    { term: tk("glossary_high_tier_term"), short: tk("glossary_high_tier_short") },
    {},
  ),
  "k-support": withText(
    { term: tk("glossary_k_support_term"), short: tk("glossary_k_support_short") },
    {},
  ),
  "ip-address": withText(
    { term: tk("glossary_ip_address_term"), short: tk("glossary_ip_address_short") },
    {},
  ),
} as const satisfies Record<string, GlossaryEntry>

export type TermId = keyof typeof GLOSSARY

export const TERM_IDS = Object.keys(GLOSSARY) as TermId[]

export function isTermId(id: string): id is TermId {
  return Object.hasOwn(GLOSSARY, id)
}

export function lookupTerm(id: string): GlossaryEntry | undefined {
  return isTermId(id) ? GLOSSARY[id] : undefined
}

/** The words in running text that open a definition (matched whole, case-insensitively). */
const SURFACE: [RegExp, TermId][] = [
  [/\bASNs?\b/i, "asn"],
  [/\bCVEs?\b/i, "cve"],
  [/\bKEV\b/, "kev"],
  [/\bRCE\b/, "rce"],
  [/\bexploits?\b/i, "exploit"],
  [/\bpayloads?\b/i, "payload"],
  [/\bbrute[- ]force\b/i, "brute-force"],
  [/\bcredential stuffing\b/i, "credential-stuffing"],
  [/\bbotnets?\b/i, "botnet"],
  [/\bC2\b/, "c2"],
  [/\bcampaigns?\b/i, "campaign"],
  [/\bindicators?\b/i, "indicator"],
  [/\bhoneypot\b/i, "honeypot"],
  [/\bblocklists?\b/i, "blocklist"],
  [/\bconsensus\b/i, "consensus"],
  [/\bblinded (?:indicator|link|domain)s?\b/i, "blinded-indicator"],
  [/\beligible nodes?\b/i, "eligible-node"],
]

export type TextPart = string | { id: TermId; text: string }

/**
 * Cut `text` into plain strings and glossary hits. Each term is explained once (its first
 * mention); `only` limits which terms may be picked. Overlaps resolve to the earliest match.
 */
export function splitTerms(text: string, only?: readonly TermId[]): TextPart[] {
  const hits: { start: number; end: number; id: TermId }[] = []
  for (const [pattern, id] of SURFACE) {
    if (only && !only.includes(id)) continue
    const m = pattern.exec(text)
    if (m) hits.push({ start: m.index, end: m.index + m[0].length, id })
  }
  hits.sort((a, b) => a.start - b.start)
  const parts: TextPart[] = []
  let at = 0
  for (const h of hits) {
    if (h.start < at) continue
    if (h.start > at) parts.push(text.slice(at, h.start))
    parts.push({ id: h.id, text: text.slice(h.start, h.end) })
    at = h.end
  }
  if (at < text.length) parts.push(text.slice(at))
  return parts.length ? parts : [text]
}
