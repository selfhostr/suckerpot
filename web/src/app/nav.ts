import { Binoculars, Microscope, ShieldCheck, type LucideIcon } from "lucide-react"

/** The three sections of the product: what is happening, what it means, what to do about it. */
export type SectionId = "observe" | "understand" | "defend"

/** One page of the app, listed in the sidebar under its section. */
export interface NavPage {
  to: string
  label: string
  /** Path prefixes (besides `to` and what sits below it) on which this page is current. */
  also?: readonly string[]
}

export interface NavSection {
  id: SectionId
  label: string
  icon: LucideIcon
  /**
   * The pages in reading order. Pages that belong together (Sessions, Attackers and Attacker
   * networks) form one cluster; the sidebar draws a little air between clusters, nothing more.
   */
  clusters: readonly (readonly NavPage[])[]
}

/**
 * Observe, Understand, Defend. Every page is an ordinary route, so deep links and filters in the
 * URL keep working; the sidebar, the mobile drawer, the header breadcrumb and the page list
 * (`allPages`, which the help texts are checked against) all read this one table.
 */
export const NAV_SECTIONS: readonly NavSection[] = [
  {
    id: "observe",
    label: "Observe",
    icon: Binoculars,
    clusters: [
      [
        { to: "/", label: "Today" },
        { to: "/live", label: "Live" },
      ],
      [
        { to: "/attacks", label: "Sessions" },
        { to: "/attackers", label: "Attackers" },
        { to: "/networks", label: "Attacker networks" },
      ],
    ],
  },
  {
    id: "understand",
    label: "Understand",
    icon: Microscope,
    clusters: [
      [
        { to: "/campaigns", label: "Campaigns" },
        { to: "/techniques", label: "Techniques" },
      ],
      [
        { to: "/scripts", label: "Scripts" },
        { to: "/malware", label: "Malware" },
        { to: "/infrastructure", label: "Infrastructure" },
      ],
      [
        { to: "/overview", label: "Overview" },
        { to: "/trends", label: "Trends" },
      ],
    ],
  },
  {
    id: "defend",
    label: "Defend",
    icon: ShieldCheck,
    clusters: [
      [
        { to: "/defend/blocklists", label: "Blocklists" },
        { to: "/defend/detections", label: "Detections" },
      ],
      [
        { to: "/defend/exposure", label: "Your exposure" },
        { to: "/cves", label: "CVE watch" },
      ],
      [{ to: "/defend/alerts", label: "Alerts", also: ["/reports"] }],
      [
        { to: "/defend/abuse", label: "Abuse reports" },
        { to: "/defend/results", label: "Results" },
      ],
      [
        { to: "/network", label: "SuckerPot network" },
        { to: "/network/members", label: "Network members" },
      ],
    ],
  },
]

/** The foot of the sidebar. The styleguide is reached from Settings, so it counts as Settings. */
export const SETTINGS_PAGE: NavPage = { to: "/settings", label: "Settings", also: ["/styleguide"] }
export const STYLEGUIDE_PAGE: NavPage = { to: "/styleguide", label: "Styleguide" }

export const DOCS_URL = "https://suckerpot.selfhostr.io/docs/"
export const GITHUB_URL = "https://github.com/selfhostr/suckerpot"

/** Does `pathname` equal `prefix` or sit below it ("/attacks/42" is under "/attacks")? */
export function isUnder(pathname: string, prefix: string): boolean {
  if (prefix === "/") return pathname === "/"
  return pathname === prefix || pathname.startsWith(`${prefix}/`)
}

/** Every page of a section, clusters flattened. */
export function sectionPages(section: NavSection): NavPage[] {
  return section.clusters.flat()
}

export interface ActivePage {
  page: NavPage
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
  const consider = (page: NavPage, section?: NavSection) => {
    for (const prefix of [page.to, ...(page.also ?? [])]) {
      if (isUnder(pathname, prefix) && prefix.length > bestLength) {
        best = section ? { page, section } : { page }
        bestLength = prefix.length
      }
    }
  }
  for (const section of sections) for (const page of sectionPages(section)) consider(page, section)
  consider(SETTINGS_PAGE)
  return best
}

export interface Crumb {
  label: string
  /** Set when the crumb leads somewhere other than the current address. */
  to?: string
}

/** What the header says about where you are: "Observe / Attackers", or "Settings / Styleguide". */
export function crumbsFor(pathname: string): Crumb[] {
  if (isUnder(pathname, STYLEGUIDE_PAGE.to))
    return [{ label: SETTINGS_PAGE.label, to: SETTINGS_PAGE.to }, { label: STYLEGUIDE_PAGE.label }]
  const active = activePage(pathname)
  if (!active) return []
  const { page, section } = active
  const here: Crumb =
    pathname === page.to ? { label: page.label } : { label: page.label, to: page.to }
  return section ? [{ label: section.label }, here] : [here]
}

/** Every individual page, flattened: what the help texts and a page list cover. */
export function allPages(): NavPage[] {
  return [...NAV_SECTIONS.flatMap(sectionPages), SETTINGS_PAGE, STYLEGUIDE_PAGE]
}
