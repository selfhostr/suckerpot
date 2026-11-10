import {
  Bell,
  Crosshair,
  FileCode2,
  Flag,
  MailWarning,
  Radar,
  Radio,
  Settings,
  Share2,
  ShieldCheck,
  Sun,
  SwatchBook,
  TrendingUp,
  type LucideIcon,
} from "lucide-react"

/** The three spaces of the product, plus the footer. */
export type Space = "observe" | "understand" | "defend" | "footer"

/** One page of the app: a sidebar entry on its own, or a tab of a hub. */
export interface NavPage {
  to: string
  label: string
}

export interface NavItem {
  /** Where the sidebar entry links to: the first page of the hub. */
  to: string
  label: string
  icon: LucideIcon
  space: Space
  /** Small pill after the label, e.g. a count or "New". */
  badge?: string
  /** Hub only: the pages shown as a tab strip at the top of each of them. */
  tabs?: readonly NavPage[]
  /** Path prefixes (besides those of the tabs) on which the entry is active. */
  also?: readonly string[]
  /** Shown in development builds only. */
  devOnly?: boolean
}

export interface NavGroup {
  space: Space
  label: string
  items: NavItem[]
}

/**
 * Observe: what is happening. Understand: what it means. Defend: what to do about it.
 * A hub is one entry with `tabs`; every tab is still an ordinary route, so deep links keep working.
 * Sidebar, tab strips, the mobile drawer and the page list all read this one table.
 */
export const NAV_ITEMS: NavItem[] = [
  { space: "observe", to: "/", label: "Today", icon: Sun },
  { space: "observe", to: "/live", label: "Live", icon: Radio },
  {
    space: "observe",
    to: "/attacks",
    label: "Attacks",
    icon: Crosshair,
    tabs: [
      { to: "/attacks", label: "Sessions" },
      { to: "/attackers", label: "Attackers" },
      { to: "/networks", label: "Networks" },
    ],
  },

  {
    space: "understand",
    to: "/campaigns",
    label: "Campaigns",
    icon: Flag,
    tabs: [
      { to: "/campaigns", label: "Campaigns" },
      { to: "/techniques", label: "Techniques" },
    ],
  },
  {
    space: "understand",
    to: "/scripts",
    label: "Tools",
    icon: FileCode2,
    tabs: [
      { to: "/scripts", label: "Scripts" },
      { to: "/malware", label: "Malware" },
      { to: "/infrastructure", label: "Infrastructure" },
    ],
  },
  {
    space: "understand",
    to: "/overview",
    label: "Trends",
    icon: TrendingUp,
    // The routes stay /overview and /trends; only the grouping changed.
    tabs: [
      { to: "/overview", label: "Activity" },
      { to: "/trends", label: "Patterns" },
    ],
  },

  {
    space: "defend",
    to: "/defend/blocklists",
    label: "Protection",
    icon: ShieldCheck,
    tabs: [
      { to: "/defend/blocklists", label: "Blocklists" },
      { to: "/defend/detections", label: "Detections" },
    ],
  },
  {
    space: "defend",
    to: "/defend/exposure",
    label: "Exposure",
    icon: Radar,
    tabs: [
      { to: "/defend/exposure", label: "Your exposure" },
      { to: "/cves", label: "CVE watch" },
    ],
  },
  {
    space: "defend",
    to: "/defend/alerts",
    label: "Alerts",
    icon: Bell,
    also: ["/reports"],
  },
  {
    space: "defend",
    to: "/defend/abuse",
    label: "Abuse reports",
    icon: MailWarning,
    tabs: [
      { to: "/defend/abuse", label: "Reports" },
      { to: "/defend/results", label: "Results" },
    ],
  },
  {
    space: "defend",
    to: "/network",
    label: "Network",
    icon: Share2,
    tabs: [
      { to: "/network", label: "Overview" },
      { to: "/network/members", label: "Members" },
    ],
  },

  { space: "footer", to: "/settings", label: "Settings", icon: Settings },
  { space: "footer", to: "/styleguide", label: "Styleguide", icon: SwatchBook, devOnly: true },
]

const SPACE_LABEL: Record<Space, string> = {
  observe: "Observe",
  understand: "Understand",
  defend: "Defend",
  footer: "System",
}

/** Does `pathname` equal `prefix` or sit below it ("/attacks/42" is under "/attacks")? */
export function isUnder(pathname: string, prefix: string): boolean {
  if (prefix === "/") return pathname === "/"
  return pathname === prefix || pathname.startsWith(`${prefix}/`)
}

/** The sidebar entry (hub or single page) that owns `pathname`, if any. */
export function itemForPath(
  pathname: string,
  items: readonly NavItem[] = NAV_ITEMS,
): NavItem | undefined {
  return items.find((i) => {
    const prefixes = [i.to, ...(i.tabs ?? []).map((t) => t.to), ...(i.also ?? [])]
    return prefixes.some((p) => isUnder(pathname, p))
  })
}

/** The hub `pathname` belongs to, or undefined on a page without tabs. */
export function hubForPath(pathname: string): NavItem | undefined {
  const item = itemForPath(pathname)
  return item?.tabs ? item : undefined
}

/** The tab of `hub` that is current on `pathname` (detail routes count for their list). */
export function activeTab(hub: NavItem, pathname: string): NavPage | undefined {
  return hub.tabs?.find((t) => isUnder(pathname, t.to))
}

/** Every individual page, flattened: what a search or command palette lists. */
export function allPages(items: readonly NavItem[] = NAV_ITEMS): NavPage[] {
  return items.flatMap((i) =>
    i.tabs ? i.tabs.map((t) => ({ to: t.to, label: t.label })) : [{ to: i.to, label: i.label }],
  )
}

/** The sidebar, grouped by space. Development-only entries are left out of production builds. */
export function buildNav(dev: boolean = import.meta.env.DEV): NavGroup[] {
  return (["observe", "understand", "defend", "footer"] as const).map((space) => ({
    space,
    label: SPACE_LABEL[space],
    items: NAV_ITEMS.filter((i) => i.space === space && (dev || !i.devOnly)),
  }))
}

export const NAV: NavGroup[] = buildNav()
