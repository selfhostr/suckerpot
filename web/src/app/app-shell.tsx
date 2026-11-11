import { Menu } from "lucide-react"
import { useState } from "react"
import { Link, Outlet, ScrollRestoration, useLocation } from "react-router"
import { LiveIndicator } from "@/components/live-indicator"
import { PipelineBanner } from "@/components/pipeline-banner"
import { MaskToggle } from "@/components/mask-toggle"
import { ReadOnlyBadge } from "@/components/read-only-badge"
import { ScannerToggle } from "@/components/scanner-toggle"
import { SetupRedirect } from "@/components/setup/redirect"
import { VersionLabel } from "@/components/setup/version-label"
import { SearchPaletteProvider, SearchTrigger } from "@/components/search/search-palette"
import { ThemeToggle } from "@/components/theme-toggle"
import { TourButton } from "@/components/tour/tour-button"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { cn } from "@/lib/utils"
import { AccountMenu } from "./account-menu"
import { Logo } from "./logo"
import { HubTabs } from "@/components/hub-tabs"
import { NAV, NAV_ITEMS, hubForPath, itemForPath } from "./nav"
import { TourProvider } from "./tour"
import { useLiveStatus } from "./use-live-status"

const MOCK = import.meta.env.VITE_MOCK === "1"

/** The three spaces, then System (Settings and Styleguide). */
function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const { pathname } = useLocation()
  // A hub entry lights up on all of its routes, detail pages included.
  const activeTo = itemForPath(pathname)?.to
  return (
    <nav aria-label="Main" className="flex flex-col gap-5 lg:gap-4">
      {NAV.map((group) => (
        <div
          key={group.space}
          role="group"
          aria-labelledby={`nav-${group.space}`}
          className="flex flex-col gap-0.5"
        >
          <div
            id={`nav-${group.space}`}
            className="px-2.5 pb-1.5 text-2xs font-medium tracking-wide text-fg-subtle uppercase"
          >
            {group.label}
          </div>
          {group.items.map(({ to, label, icon: Icon, badge }) => {
            const isActive = to === activeTo
            return (
              <Link
                key={to}
                to={to}
                onClick={onNavigate}
                aria-current={isActive ? "page" : undefined}
                className={cn(
                  "group flex h-8 items-center gap-2.5 rounded-md px-2.5 text-sm font-medium transition-colors duration-150 lg:h-7",
                  isActive
                    ? "bg-surface-hover text-fg"
                    : "text-fg-muted hover:bg-surface-hover/60 hover:text-fg",
                )}
              >
                {
                  <>
                    <Icon
                      aria-hidden
                      className={cn(
                        "size-4",
                        isActive ? "text-fg" : "text-fg-subtle group-hover:text-fg-muted",
                      )}
                      strokeWidth={1.85}
                    />
                    {label}
                    {badge ? (
                      <span className="ml-auto rounded-full border px-1.5 text-2xs font-medium text-fg-muted">
                        {badge}
                      </span>
                    ) : null}
                  </>
                }
              </Link>
            )
          })}
        </div>
      ))}
    </nav>
  )
}

function MockBadge() {
  return MOCK ? (
    <span className="rounded-sm border px-1.5 py-0.5 text-2xs font-medium text-fg-muted">
      Mock data
    </span>
  ) : null
}

/**
 * Desktop: theme, masking and the account (live status and the scanner switch sit in the header,
 * so the navigation keeps its height). The phone drawer carries everything.
 */
function StatusFooter({
  drawer = false,
  onNavigate,
}: {
  drawer?: boolean
  onNavigate?: () => void
}) {
  const { status, detail } = useLiveStatus()
  return (
    <div className="flex flex-col gap-3 border-t px-3 pt-4">
      {drawer ? (
        <div className="flex items-center justify-between gap-2 px-1">
          <LiveIndicator status={status} detail={detail} />
          <MockBadge />
        </div>
      ) : null}
      <div className="flex items-center justify-between gap-2 px-1">
        <span className="text-xs text-fg-muted">Theme</span>
        <ThemeToggle />
      </div>
      {drawer ? <ScannerToggle className="px-1" /> : null}
      <MaskToggle className="px-1" />
      <div className="flex flex-col gap-2 border-t pt-3">
        <ReadOnlyBadge className="mx-1 self-start" />
        <AccountMenu />
      </div>
      <VersionLabel onNavigate={onNavigate} />
    </div>
  )
}

function currentLabel(pathname: string): string {
  const item = itemForPath(pathname, NAV_ITEMS)
  if (!item) return ""
  const tab = item.tabs?.find((t) => pathname === t.to || pathname.startsWith(`${t.to}/`))
  return tab?.label ?? item.label
}

export function AppShell() {
  const [open, setOpen] = useState(false)
  const { pathname } = useLocation()
  const hub = hubForPath(pathname)
  const { status, detail: liveDetail } = useLiveStatus()

  return (
    <SearchPaletteProvider>
      <TourProvider>
        <SetupRedirect />
        <div className="min-h-dvh bg-bg">
          <a
            href="#main"
            className="sr-only z-50 rounded-md bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
          >
            Skip to content
          </a>

          {/* Desktop sidebar */}
          {/* The whole sidebar scrolls when the window is short, so a group is never cut in half;
            on tall windows the spacer keeps System and the status footer at the bottom. */}
          <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col overflow-y-auto overscroll-contain border-r bg-bg py-4 lg:flex">
            <div className="px-5 pt-1 pb-5">
              <Logo />
            </div>
            {/* One scroll area, System last: on a 900 px laptop screen Defend stays in view. */}
            <div className="flex-1 px-3 pb-3">
              <NavList />
            </div>
            <StatusFooter />
          </aside>

          {/* Mobile top bar */}
          <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-bg/85 px-2 backdrop-blur-md lg:hidden">
            <Sheet open={open} onOpenChange={setOpen}>
              <SheetTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label="Open navigation"
                  className="size-10"
                >
                  <Menu aria-hidden className="size-5" />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-72 gap-0 border-r bg-bg p-0 py-4">
                <SheetTitle className="px-5 pt-1 pb-6">
                  <Logo />
                </SheetTitle>
                <SheetDescription className="sr-only">Main navigation</SheetDescription>
                <div className="flex-1 overflow-y-auto px-3">
                  <NavList onNavigate={() => setOpen(false)} />
                </div>
                <StatusFooter drawer onNavigate={() => setOpen(false)} />
              </SheetContent>
            </Sheet>
            {/* Mark only: the name does not fit next to five controls at 390 px. */}
            <Logo withName={false} />
            <span className="sr-only">{currentLabel(pathname)}</span>
            <div className="min-w-0 flex-1" />
            <SearchTrigger compact />
            <TourButton className="size-10" />
            <ReadOnlyBadge short />
            <LiveIndicator status={status} className="mx-1" />
            <AccountMenu variant="compact" />
          </header>

          <main id="main" className="lg:pl-60">
            {/*
             * Desktop header: search on the left; on the right what applies to every page (the
             * scanner filter) and whether the feed is live. Phones get these in the top bar and drawer.
             */}
            <div className="sticky top-0 z-20 hidden h-14 items-center gap-6 border-b bg-bg/85 px-10 backdrop-blur-md lg:flex">
              <SearchTrigger className="max-w-md min-w-0 flex-1" />
              <div className="ml-auto flex shrink-0 items-center gap-5">
                <TourButton />
                <ScannerToggle inline />
                <span aria-hidden className="h-4 w-px bg-border" />
                <div className="flex items-center gap-2">
                  <LiveIndicator status={status} detail={liveDetail} />
                  <MockBadge />
                </div>
              </div>
            </div>
            <div
              className={cn(
                "mx-auto w-full px-4 pt-6 pb-16 sm:px-6 lg:px-10 lg:pt-8",
                // Live is the wall screen: its map uses the whole width. Other pages stay readable.
                pathname.startsWith("/live") ? "max-w-[2400px]" : "max-w-[1200px]",
              )}
            >
              {/* A new route fades in softly (off under reduced motion and for screenshots). */}
              <PipelineBanner />
              {hub ? <HubTabs hub={hub} pathname={pathname} /> : null}
              <div key={pathname} className="animate-page-in">
                <Outlet />
              </div>
            </div>
          </main>
          <ScrollRestoration />
        </div>
      </TourProvider>
    </SearchPaletteProvider>
  )
}
