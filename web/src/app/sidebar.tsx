import { BookOpen, ChevronRight, PanelLeftClose, PanelLeftOpen, Settings } from "lucide-react"
import { Link, useLocation } from "react-router"
import { ScannerToggle } from "@/components/scanner-toggle"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useVersion } from "@/hooks/use-version"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"
import { hasUpdate } from "@/lib/version"
import { AccountMenu } from "./account-menu"
import { GithubMark } from "./github-mark"
import { Logo } from "./logo"
import {
  DOCS_URL,
  GITHUB_URL,
  NAV_SECTIONS,
  SETTINGS_PAGE,
  activePage,
  entryHome,
  type NavEntry,
  type NavSection,
} from "./nav"
import { useOpenSections } from "./sidebar-state"
import { useLiveStatus } from "./use-live-status"

/** Ctrl B on Windows and Linux, ⌘B on a Mac: shown next to the fold switch. */
function toggleHint(): string {
  return typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent)
    ? "⌘B"
    : "Ctrl B"
}

/**
 * Whether the live feed is connected, as a still dot beside "Today", which carries the live map
 * (never animated: it sits on every page). Green while connected, dimmed while connecting, a
 * hollow ring when offline.
 */
function LiveDot({ className }: { className?: string }) {
  const { status } = useLiveStatus()
  return (
    <span
      className={cn("inline-flex items-center", className)}
      title={t("sidebar_live_title", { status })}
    >
      <span
        aria-hidden
        className={cn(
          "size-1.5 rounded-full",
          status === "live" && "bg-status-ok",
          (status === "connecting" || status === "reconnecting") && "bg-status-off opacity-60",
          status === "offline" && "border border-status-off",
        )}
      />
      <span className="sr-only">{t("sidebar_live_sr", { status })}</span>
    </span>
  )
}

function UpdateDot({ className }: { className?: string }) {
  const version = useVersion().data
  if (!hasUpdate(version)) return null
  return (
    <span className={cn("inline-flex", className)}>
      <span aria-hidden className="size-1.5 rounded-full bg-primary" />
      <span className="sr-only">{t("sidebar_update_available_sr")}</span>
    </span>
  )
}

/** A tooltip to the right of a rail icon. */
function RailTip({
  label,
  children,
  side = "right",
}: {
  label: React.ReactNode
  children: React.ReactNode
  side?: "right" | "top"
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side={side} sideOffset={8}>
        {label}
      </TooltipContent>
    </Tooltip>
  )
}

/* --- Expanded: sections that open onto their entries ------------------------------------------ */

/** Today carries the live map, so the dot of the live feed sits beside it. */
const LIVE_ENTRY_HOME = "/"

function EntryLink({
  entry,
  current,
  onNavigate,
}: {
  entry: NavEntry
  current: boolean
  onNavigate?: (() => void) | undefined
}) {
  const to = entryHome(entry)
  return (
    <li className="relative">
      {/* The guide line of the section turns solid beside the current entry. */}
      {current ? <span aria-hidden className="absolute inset-y-1 -left-px w-px bg-fg" /> : null}
      <Link
        to={to}
        onClick={onNavigate}
        aria-current={current ? "page" : undefined}
        className={cn(
          "flex h-10 items-center gap-2 rounded-md px-2.5 text-sm transition-colors duration-150 lg:h-7",
          current
            ? "bg-surface-hover font-medium text-fg"
            : "text-fg-muted hover:bg-surface-hover/60 hover:text-fg",
        )}
      >
        <span className="min-w-0 flex-1 truncate">{entry.label}</span>
        {to === LIVE_ENTRY_HOME ? <LiveDot /> : null}
      </Link>
    </li>
  )
}

function SectionGroup({
  section,
  open,
  onToggle,
  currentEntry,
  onNavigate,
}: {
  section: NavSection
  open: boolean
  onToggle: () => void
  currentEntry: NavEntry | undefined
  onNavigate?: (() => void) | undefined
}) {
  const Icon = section.icon
  const holdsCurrent = !!currentEntry && section.entries.includes(currentEntry)
  const listId = `nav-list-${section.id}`
  const labelId = `nav-${section.id}`
  return (
    <div role="group" aria-labelledby={labelId}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={listId}
        className={cn(
          "group flex h-10 w-full items-center gap-2.5 rounded-md px-2.5 text-left text-sm font-medium transition-colors duration-150 hover:bg-surface-hover/60 lg:h-8",
          holdsCurrent ? "text-fg" : "text-fg-muted hover:text-fg",
          // Folded with the current page inside: the section itself shows where you are.
          holdsCurrent && !open && "bg-surface-hover",
        )}
      >
        <Icon
          aria-hidden
          strokeWidth={1.85}
          className={cn(
            "size-4 shrink-0",
            holdsCurrent ? "text-fg" : "text-fg-subtle group-hover:text-fg-muted",
          )}
        />
        <span id={labelId} className="min-w-0 flex-1 truncate">
          {section.label}
        </span>
        <ChevronRight
          aria-hidden
          className={cn(
            "size-3.5 shrink-0 text-fg-subtle transition-transform duration-150",
            open && "rotate-90",
          )}
        />
      </button>
      {open ? (
        <ul id={listId} className="mt-0.5 mb-1 ml-[1.0625rem] border-l pl-2">
          {section.entries.map((entry) => (
            <EntryLink
              key={entry.label}
              entry={entry}
              current={entry === currentEntry}
              onNavigate={onNavigate}
            />
          ))}
        </ul>
      ) : null}
    </div>
  )
}

/* --- Folded: one icon per section, its entries in a flyout ------------------------------------ */

function SectionFlyout({
  section,
  currentEntry,
}: {
  section: NavSection
  currentEntry: NavEntry | undefined
}) {
  const Icon = section.icon
  const holdsCurrent = !!currentEntry && section.entries.includes(currentEntry)
  return (
    <DropdownMenu>
      <RailTip label={section.label}>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            aria-label={section.label}
            className={cn(
              "grid size-10 shrink-0 place-items-center rounded-lg transition-colors duration-150 hover:bg-surface-hover hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none aria-expanded:bg-surface-hover aria-expanded:text-fg",
              holdsCurrent ? "bg-surface-hover text-fg" : "text-fg-muted",
            )}
          >
            <Icon aria-hidden strokeWidth={1.75} className="size-[1.125rem]" />
          </button>
        </DropdownMenuTrigger>
      </RailTip>
      <DropdownMenuContent side="right" align="start" sideOffset={10} className="w-52">
        <DropdownMenuLabel className="text-xs font-medium text-fg-subtle">
          {section.label}
        </DropdownMenuLabel>
        {section.entries.map((entry) => {
          const current = entry === currentEntry
          const to = entryHome(entry)
          return (
            <DropdownMenuItem key={entry.label} asChild>
              <Link
                to={to}
                aria-current={current ? "page" : undefined}
                className={cn(current ? "bg-surface-hover font-medium text-fg" : "text-fg-muted")}
              >
                <span className="min-w-0 flex-1 truncate">{entry.label}</span>
                {to === LIVE_ENTRY_HOME ? <LiveDot /> : null}
              </Link>
            </DropdownMenuItem>
          )
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/* --- Foot: Settings, Docs, GitHub, then the account ------------------------------------------- */

const RAIL_ICON =
  "relative grid size-10 shrink-0 place-items-center rounded-lg text-fg-muted transition-colors duration-150 hover:bg-surface-hover hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
/**
 * The expanded foot's three buttons share the width of the sidebar equally: plain icon buttons
 * (hover background only), named by a tooltip and an aria-label.
 */
const FOOT_BUTTON =
  "relative grid h-10 min-w-0 flex-1 place-items-center rounded-md text-fg-muted transition-colors duration-150 hover:bg-surface-hover hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"

function Foot({
  rail,
  settingsCurrent,
  onNavigate,
}: {
  rail: boolean
  settingsCurrent: boolean
  onNavigate?: (() => void) | undefined
}) {
  if (rail) {
    return (
      <div className="flex shrink-0 flex-col items-start gap-1 px-2 pt-2 pb-3">
        <RailTip label={t("nav_settings")}>
          <Link
            to={SETTINGS_PAGE.to}
            aria-label={t("nav_settings")}
            aria-current={settingsCurrent ? "page" : undefined}
            className={cn(RAIL_ICON, settingsCurrent && "bg-surface-hover text-fg")}
          >
            <Settings aria-hidden strokeWidth={1.75} className="size-[1.125rem]" />
            <UpdateDot className="absolute top-2 right-2" />
          </Link>
        </RailTip>
        <RailTip label={t("sidebar_docs")}>
          <a href={DOCS_URL} target="_blank" rel="noopener noreferrer" className={RAIL_ICON}>
            <BookOpen aria-hidden strokeWidth={1.75} className="size-[1.125rem]" />
            <span className="sr-only">{t("sidebar_docs_new_tab")}</span>
          </a>
        </RailTip>
        <RailTip label={t("sidebar_github")}>
          <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer" className={RAIL_ICON}>
            <GithubMark className="size-[1.0625rem]" />
            <span className="sr-only">{t("sidebar_github_new_tab")}</span>
          </a>
        </RailTip>
        <AccountMenu variant="rail" />
      </div>
    )
  }
  // Unfolded: the three links share the full width above the profile block.
  return (
    <div className="flex shrink-0 flex-col gap-2 px-3 pt-3 pb-3">
      <div className="flex items-stretch gap-1">
        <RailTip label={t("nav_settings")} side="top">
          <Link
            to={SETTINGS_PAGE.to}
            onClick={onNavigate}
            aria-label={t("nav_settings")}
            aria-current={settingsCurrent ? "page" : undefined}
            className={cn(FOOT_BUTTON, settingsCurrent && "bg-surface-hover text-fg")}
          >
            <Settings aria-hidden strokeWidth={1.85} className="size-[1.125rem]" />
            <UpdateDot className="absolute top-2 right-[calc(50%-1.25rem)]" />
          </Link>
        </RailTip>
        <RailTip label={t("sidebar_docs")} side="top">
          <a href={DOCS_URL} target="_blank" rel="noopener noreferrer" className={FOOT_BUTTON}>
            <BookOpen aria-hidden strokeWidth={1.85} className="size-[1.125rem]" />
            <span className="sr-only">{t("sidebar_docs_new_tab")}</span>
          </a>
        </RailTip>
        <RailTip label={t("sidebar_github")} side="top">
          <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer" className={FOOT_BUTTON}>
            <GithubMark className="size-[1.0625rem]" />
            <span className="sr-only">{t("sidebar_github_new_tab")}</span>
          </a>
        </RailTip>
      </div>
      <AccountMenu />
    </div>
  )
}

/* --- The sidebar ------------------------------------------------------------------------------ */

export type SidebarVariant = "expanded" | "rail" | "drawer"

/**
 * The navigation column. `expanded` and `rail` are the desktop sidebar, unfolded and folded to
 * icons (`onToggle` switches between them); `drawer` is the same column in the phone drawer, with
 * the research-scanner switch the phone header has no room for.
 */
export function Sidebar({
  variant,
  onToggle,
  onNavigate,
}: {
  variant: SidebarVariant
  onToggle?: () => void
  onNavigate?: () => void
}) {
  const { pathname } = useLocation()
  const active = activePage(pathname)
  const currentEntry = active?.entry
  const settingsCurrent = active?.page === SETTINGS_PAGE
  const sections = useOpenSections()
  const rail = variant === "rail"
  const hint = toggleHint()

  return (
    <div className="flex h-full min-h-0 flex-col">
      {variant === "drawer" ? null : rail ? (
        <div className="flex h-14 shrink-0 items-center px-2">
          {/* Folded: the mark is the switch, and turns into the "expand" icon under the pointer. */}
          <RailTip
            label={
              <>
                {t("sidebar_expand")} <kbd className="ml-1.5 font-sans opacity-70">{hint}</kbd>
              </>
            }
          >
            <button
              type="button"
              onClick={onToggle}
              aria-label={t("sidebar_expand")}
              aria-expanded={false}
              aria-controls="sidebar"
              aria-keyshortcuts="Control+B Meta+B"
              className="group grid size-10 place-items-center rounded-lg text-fg transition-colors duration-150 hover:bg-surface-hover focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
            >
              <span className="col-start-1 row-start-1 transition-opacity duration-150 group-hover:opacity-0 group-focus-visible:opacity-0">
                <Logo withName={false} />
              </span>
              <PanelLeftOpen
                aria-hidden
                strokeWidth={1.75}
                className="col-start-1 row-start-1 size-[1.125rem] opacity-0 transition-opacity duration-150 group-hover:opacity-100 group-focus-visible:opacity-100"
              />
            </button>
          </RailTip>
        </div>
      ) : (
        <div className="flex h-14 shrink-0 items-center justify-between gap-2 pr-2 pl-5">
          <Link
            to="/"
            className="rounded-md focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
          >
            <Logo />
          </Link>
          <RailTip
            label={
              <>
                {t("sidebar_collapse")} <kbd className="ml-1.5 font-sans opacity-70">{hint}</kbd>
              </>
            }
          >
            <button
              type="button"
              onClick={onToggle}
              aria-label={t("sidebar_collapse")}
              aria-expanded
              aria-controls="sidebar"
              aria-keyshortcuts="Control+B Meta+B"
              className="grid size-8 place-items-center rounded-md text-fg-subtle transition-colors duration-150 hover:bg-surface-hover hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
            >
              <PanelLeftClose aria-hidden strokeWidth={1.75} className="size-4" />
            </button>
          </RailTip>
        </div>
      )}

      {rail ? (
        <nav
          aria-label={t("sidebar_main_nav")}
          className="flex min-h-0 flex-1 flex-col items-start gap-1 overflow-y-auto px-2 pt-1"
        >
          {NAV_SECTIONS.map((s) => (
            <SectionFlyout key={s.id} section={s} currentEntry={currentEntry} />
          ))}
        </nav>
      ) : (
        // Only the sections scroll on a short window: the foot stays in reach.
        <nav
          aria-label={t("sidebar_main_nav")}
          className="scroll-fade-y flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto overscroll-contain px-3 pt-1 pb-3"
        >
          {NAV_SECTIONS.map((s) => (
            <SectionGroup
              key={s.id}
              section={s}
              open={sections.isOpen(s.id)}
              onToggle={() => sections.toggle(s.id)}
              currentEntry={currentEntry}
              onNavigate={onNavigate}
            />
          ))}
        </nav>
      )}

      {variant === "drawer" ? <ScannerToggle className="border-t px-5 pt-3 pb-2" /> : null}
      <Foot rail={rail} settingsCurrent={settingsCurrent} onNavigate={onNavigate} />
    </div>
  )
}
