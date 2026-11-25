import { ChevronRight, Menu } from "lucide-react"
import { Fragment, useCallback, useEffect, useMemo, useState } from "react"
import { Link, Outlet, ScrollRestoration, useLocation, useMatches } from "react-router"
import { PipelineBanner } from "@/components/pipeline-banner"
import { ScannerToggle } from "@/components/scanner-toggle"
import { SetupRedirect } from "@/components/setup/redirect"
import { SearchPaletteProvider, SearchTrigger } from "@/components/search/search-palette"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"
import { Logo } from "./logo"
import { crumbsFor } from "./nav"
import { PAGE_FRAME_CLASS, PAGE_WIDTH_CLASS, pageWidth } from "./page-width"
import { HelpSlotContext } from "./help-slot"
import { PageSwitch } from "./page-switch"
import { Sidebar } from "./sidebar"
import { useSidebarCollapsed } from "./sidebar-state"
import { TourProvider } from "./tour"
import { VersionFooter } from "./version-footer"

/** Is the key press meant for a text field (or anything else that edits text)? */
function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  return (
    target.isContentEditable ||
    target.tagName === "INPUT" ||
    target.tagName === "TEXTAREA" ||
    target.tagName === "SELECT"
  )
}

/**
 * Ctrl B (⌘B on a Mac) folds and unfolds the desktop sidebar, as in editors; never while typing,
 * under a dialog, or on a phone, where the sidebar is a drawer.
 */
function useFoldShortcut(toggle: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.repeat || e.altKey || e.shiftKey) return
      if (!(e.ctrlKey || e.metaKey) || e.key.toLowerCase() !== "b") return
      if (isTyping(e.target) || document.querySelector('[role="dialog"], [role="alertdialog"]'))
        return
      if (!window.matchMedia("(min-width: 64rem)").matches) return
      e.preventDefault()
      toggle()
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [toggle])
}

/**
 * "Observe / Attacks / Attackers": where you are, the page a link back to its list on a detail
 * route.
 */
function Breadcrumb({ pathname }: { pathname: string }) {
  const crumbs = crumbsFor(pathname)
  if (!crumbs.length) return <div className="min-w-0 flex-1" />
  return (
    <nav aria-label={t("shell_breadcrumb")} className="min-w-0 flex-1">
      <ol className="flex min-w-0 items-center gap-1.5 text-sm">
        {crumbs.map((c, i) => {
          const last = i === crumbs.length - 1
          return (
            <Fragment key={c.label}>
              {i > 0 ? (
                <li aria-hidden className="text-fg-subtle">
                  <ChevronRight className="size-3.5" />
                </li>
              ) : null}
              <li className="min-w-0 truncate">
                {c.to ? (
                  <Link
                    to={c.to}
                    className={cn(
                      "rounded-sm transition-colors duration-150 hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
                      last ? "font-medium text-fg" : "text-fg-muted",
                    )}
                  >
                    {c.label}
                  </Link>
                ) : (
                  <span
                    aria-current={last ? "page" : undefined}
                    className={last ? "font-medium text-fg" : "text-fg-muted"}
                  >
                    {c.label}
                  </span>
                )}
              </li>
            </Fragment>
          )
        })}
      </ol>
    </nav>
  )
}

export function AppShell() {
  const [open, setOpen] = useState(false)
  const [collapsed, setCollapsed] = useSidebarCollapsed()
  const [helpNode, setHelpNode] = useState<HTMLElement | null>(null)
  const helpSlot = useMemo(() => ({ node: helpNode, setNode: setHelpNode }), [helpNode])
  const { pathname } = useLocation()
  const width = pageWidth(useMatches())
  const toggle = useCallback(() => setCollapsed(!collapsed), [collapsed, setCollapsed])
  useFoldShortcut(toggle)
  const here = crumbsFor(pathname).at(-1)?.label ?? ""

  return (
    <SearchPaletteProvider>
      <TourProvider>
        <SetupRedirect />
        <div className="min-h-dvh bg-bg lg:flex">
          <a
            href="#main"
            className="sr-only z-50 rounded-md bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
          >
            {t("shell_skip_to_content")}
          </a>

          {/*
           * Desktop sidebar: sticky in the page flow at the height of the window, so the content
           * column takes whatever width is left. Unfolded 240 px, folded to a 56 px icon rail.
           */}
          <aside
            id="sidebar"
            data-collapsed={collapsed ? "" : undefined}
            className={cn(
              "vt-sidebar sticky top-0 z-30 hidden h-dvh shrink-0 self-start overflow-hidden border-r bg-bg lg:block",
              collapsed ? "w-14" : "w-60",
            )}
          >
            <div className={cn("h-full", collapsed ? "w-14" : "w-60")}>
              <Sidebar variant={collapsed ? "rail" : "expanded"} onToggle={toggle} />
            </div>
          </aside>

          <div className="flex min-w-0 flex-1 flex-col">
            {/* Phone and tablet top bar: the drawer, the mark, where you are, search. */}
            <header className="vt-mobilebar sticky top-0 z-30 flex h-14 items-center gap-1 border-b bg-bg px-2 lg:hidden">
              <Sheet open={open} onOpenChange={setOpen}>
                <SheetTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={t("shell_open_navigation")}
                    className="size-10"
                  >
                    <Menu aria-hidden className="size-5" />
                  </Button>
                </SheetTrigger>
                <SheetContent side="left" className="w-72 gap-0 border-r bg-bg p-0">
                  <SheetTitle className="flex h-14 shrink-0 items-center px-5">
                    <Logo />
                  </SheetTitle>
                  <SheetDescription className="sr-only">{t("shell_main_navigation")}</SheetDescription>
                  <div className="min-h-0 flex-1">
                    <Sidebar variant="drawer" onNavigate={() => setOpen(false)} />
                  </div>
                </SheetContent>
              </Sheet>
              <Link
                to="/"
                aria-label={t("nav_today")}
                className="grid size-10 shrink-0 place-items-center rounded-md"
              >
                <Logo withName={false} />
              </Link>
              <span className="min-w-0 flex-1 truncate pl-1 text-sm font-medium text-fg">
                {here}
              </span>
              <SearchTrigger compact />
            </header>

            {/*
             * Desktop header: where you are on the left; on the right what applies to every page
             * (the research-scanner switch) and, flush right, the search box. Opaque on purpose: a
             * backdrop blur under a sticky bar costs a repaint on every scrolled frame.
             */}
            <header className="vt-topbar sticky top-0 z-20 hidden h-14 items-center gap-6 border-b bg-bg px-10 lg:flex">
              <Breadcrumb pathname={pathname} />
              <div className="flex shrink-0 items-center gap-5">
                <ScannerToggle inline />
                <span aria-hidden className="h-4 w-px bg-border" />
                <SearchTrigger className="w-72 xl:w-80" />
              </div>
            </header>

            <main id="main" className="min-w-0 flex-1">
              <div
                data-page-width={width}
                className={cn(
                  // Every page fills the column, with the same gutters; the cap is for ultra-wide
                  // screens only. A `prose` page caps its own column (route table, `handle.width`).
                  "mx-auto w-full px-4 pt-3 pb-10 sm:px-6 lg:px-10 lg:pt-4",
                  PAGE_FRAME_CLASS,
                )}
              >
                <HelpSlotContext value={helpSlot}>
                  <div className={PAGE_WIDTH_CLASS[width]}>
                    <PipelineBanner />
                    {/* Outside the fading page: it stays put while you switch between its pages. */}
                    <PageSwitch pathname={pathname} />
                    {/* A new route fades in softly (off with reduced motion and for screenshots). */}
                    <div key={pathname} className="animate-page-in">
                      <Outlet />
                    </div>
                  </div>
                </HelpSlotContext>
              </div>
            </main>
            <VersionFooter className="mx-auto w-full max-w-page-wide px-4 pb-3 sm:px-6 lg:px-10" />
          </div>
          <ScrollRestoration />
        </div>
      </TourProvider>
    </SearchPaletteProvider>
  )
}
