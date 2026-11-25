import { Binoculars, Microscope, ShieldCheck, type LucideIcon } from "lucide-react"

/** The three sections of the product: what is happening, what it means, what to do about it. */
export type SectionId = "observe" | "understand" | "defend"

/** One page of the app: a route of its own, with its own address. */
export interface NavPage {
  to: string
  /** The page's name: its title, the last crumb of the header. */
  label: string
  /** The name in the switch at the top of its entry's pages, when shorter ("Networks", "Rules"). */
  tab?: string
  /** Path prefixes (besides `to` and what sits below it) on which this page is current. */
  also?: readonly string[]
  /**
   * The filters this page applies, as URL params. The page switch carries these from the page you
   * leave to this one, so a filter set on Sessions is still on when you group by address.
   */
  carries?: readonly string[]
}

/**
 * One sidebar entry. An entry with several pages (Attacks: Sessions, Attackers, Attacker
 * networks) is one row in the sidebar and a switch at the top of each of its pages; every page
 * keeps its own address, so links, filters and Back work as before.
 */
export interface NavEntry {
  label: string
  /** In reading order; the first is where the sidebar row leads. */
  pages: readonly NavPage[]
}

export interface NavSection {
  id: SectionId
  label: string
  icon: LucideIcon
  entries: readonly NavEntry[]
}

/**
 * Observe, Understand, Defend. The sidebar, the mobile drawer, the page switch, the header
 * breadcrumb and the page list (`allPages`, which the help texts are checked against) all read
 * this one table.
 */
export const NAV_SECTIONS: readonly NavSection[] = [
  {
    id: "observe",
    label: "Observe",
    icon: Binoculars,
    entries: [
      // Today carries the live map and the day's figures: /live and /overview lead here.
      { label: "Today", pages: [{ to: "/", label: "Today" }] },
      {
        label: "Attacks",
        pages: [
          {
            to: "/attacks",
            label: "Sessions",
            carries: ["sensor", "country", "asn", "tag", "since", "until"],
          },
          { to: "/attackers", label: "Attackers", carries: ["sensor", "country", "asn", "tag"] },
          {
            to: "/networks",
            label: "Attacker networks",
            tab: "Networks",
            carries: ["country", "since"],
          },
        ],
      },
    ],
  },
  {
    id: "understand",
    label: "Understand",
    icon: Microscope,
    entries: [
      {
        label: "Campaigns",
        pages: [
          { to: "/campaigns", label: "Campaigns" },
          { to: "/techniques", label: "Techniques" },
        ],
      },
      {
        label: "Payloads",
        pages: [
          { to: "/scripts", label: "Scripts" },
          { to: "/malware", label: "Files" },
          { to: "/infrastructure", label: "Hosts & URLs" },
        ],
      },
      { label: "Patterns", pages: [{ to: "/trends", label: "Patterns" }] },
    ],
  },
  {
    id: "defend",
    label: "Defend",
    icon: ShieldCheck,
    entries: [
      {
        label: "Block",
        pages: [
          { to: "/defend/blocklists", label: "Blocklists", tab: "Lists" },
          { to: "/defend/detections", label: "Detections", tab: "Rules" },
        ],
      },
      {
        label: "Exposure",
        pages: [
          { to: "/defend/exposure", label: "Your exposure", tab: "Services" },
          { to: "/cves", label: "CVE watch", tab: "CVEs" },
        ],
      },
      {
        label: "Reports",
        pages: [
          { to: "/defend/abuse", label: "Abuse reports", tab: "Queue" },
          { to: "/defend/results", label: "Results" },
        ],
      },
      {
        label: "Network",
        pages: [
          { to: "/network", label: "SuckerPot network", tab: "Overview" },
          { to: "/network/members", label: "Network members", tab: "Members" },
        ],
      },
    ],
  },
]

/**
 * The foot of the sidebar. The styleguide is reached from Settings, and the weekly reports from its
 * Alerts tab, so both count as Settings.
 */
export const SETTINGS_PAGE: NavPage = {
  to: "/settings",
  label: "Settings",
  also: ["/styleguide", "/reports"],
}
/** Where the alert rules, the recent alerts and the weekly reports live (the old /defend/alerts). */
export const ALERTS_SETTINGS = "/settings?tab=alert-rules"
export const STYLEGUIDE_PAGE: NavPage = { to: "/styleguide", label: "Styleguide" }
export const SETTINGS_ENTRY: NavEntry = { label: SETTINGS_PAGE.label, pages: [SETTINGS_PAGE] }

export const DOCS_URL = "https://suckerpot.selfhostr.io/docs/"
export const GITHUB_URL = "https://github.com/selfhostr/suckerpot"

/** Does `pathname` equal `prefix` or sit below it ("/attacks/42" is under "/attacks")? */
export function isUnder(pathname: string, prefix: string): boolean {
  if (prefix === "/") return pathname === "/"
  return pathname === prefix || pathname.startsWith(`${prefix}/`)
}

/** Where a sidebar entry leads: its first page. */
export function entryHome(entry: NavEntry): string {
  return entry.pages[0]?.to ?? "/"
}

/** Every page of a section, entries flattened. */
export function sectionPages(section: NavSection): NavPage[] {
  return section.entries.flatMap((e) => e.pages)
}

export interface ActivePage {
  page: NavPage
  entry: NavEntry
  /** Undefined for Settings, which sits outside the three sections. */
  section?: NavSection
}

/**
 * The page that is current on `pathname`, detail routes included (a session is under Sessions).
 * The longest matching prefix wins: "/network/members" is Network members, not SuckerPot network.
 */
export function activePage(
  pathname: string,
  sections: readonly NavSection[] = NAV_SECTIONS,
): ActivePage | undefined {
  let best: ActivePage | undefined
  let bestLength = -1
  const consider = (page: NavPage, entry: NavEntry, section?: NavSection) => {
    for (const prefix of [page.to, ...(page.also ?? [])]) {
      if (isUnder(pathname, prefix) && prefix.length > bestLength) {
        best = section ? { page, entry, section } : { page, entry }
        bestLength = prefix.length
      }
    }
  }
  for (const section of sections)
    for (const entry of section.entries)
      for (const page of entry.pages) consider(page, entry, section)
  consider(SETTINGS_PAGE, SETTINGS_ENTRY)
  return best
}

/**
 * The entry whose page switch shows on `pathname`: only on the pages themselves (lists and
 * hubs), not on a detail route below them, and only for an entry with more than one page.
 */
export function switchFor(pathname: string): { entry: NavEntry; current: NavPage } | undefined {
  for (const section of NAV_SECTIONS)
    for (const entry of section.entries) {
      if (entry.pages.length < 2) continue
      const current = entry.pages.find((p) => p.to === pathname)
      if (current) return { entry, current }
    }
  return undefined
}

export interface Crumb {
  label: string
  /** Set when the crumb leads somewhere other than the current address. */
  to?: string
}

/**
 * What the header says about where you are: "Observe / Attacks / Attackers". The entry is left
 * out when the page has its name ("Understand / Campaigns"); on a detail route the page is a
 * link back to its list.
 */
export function crumbsFor(pathname: string): Crumb[] {
  if (isUnder(pathname, STYLEGUIDE_PAGE.to))
    return [{ label: SETTINGS_PAGE.label, to: SETTINGS_PAGE.to }, { label: STYLEGUIDE_PAGE.label }]
  if (isUnder(pathname, "/reports"))
    return [{ label: SETTINGS_PAGE.label, to: ALERTS_SETTINGS }, { label: "Weekly report" }]
  const active = activePage(pathname)
  if (!active) return []
  const { page, entry, section } = active
  const crumbs: Crumb[] = section ? [{ label: section.label }] : []
  if (page.label !== entry.label) crumbs.push({ label: entry.label })
  crumbs.push(pathname === page.to ? { label: page.label } : { label: page.label, to: page.to })
  return crumbs
}

/** Every individual page, flattened: what the help texts and a page list cover. */
export function allPages(): NavPage[] {
  return [...NAV_SECTIONS.flatMap(sectionPages), SETTINGS_PAGE, STYLEGUIDE_PAGE]
}
