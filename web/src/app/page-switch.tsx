import { Link, useLocation } from "react-router"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"
import { switchFor, type NavPage } from "./nav"

/**
 * The switch between the pages of one sidebar entry (Sessions, Attackers, Networks): a row of
 * tabs on a hairline at the top of each of them, drawn by the shell outside the fading page so it
 * stays put while the page changes under it. It is navigation, so it does not look like the
 * segmented controls that filter a page. Plain links with `aria-current`, not an ARIA tablist:
 * every page keeps its own address. It never scrolls: on a phone the tabs share the width
 * equally (the short `tab` names fit three to a 390 px row).
 */
export function PageSwitch({ pathname }: { pathname: string }) {
  const { search } = useLocation()
  const found = switchFor(pathname)
  if (!found) return null
  const { entry, current } = found
  const here = new URLSearchParams(search)
  // The filters the next page also applies come along, so the tabs group the same view.
  const target = (p: NavPage) => {
    const next = new URLSearchParams()
    for (const key of p.carries ?? []) {
      const v = here.get(key)
      if (v && current.carries?.includes(key)) next.set(key, v)
    }
    const qs = next.toString()
    return qs ? `${p.to}?${qs}` : p.to
  }
  return (
    <nav aria-label={t("nav_switch_label", { name: entry.label })} className="vt-pageswitch mb-6 border-b lg:mb-7">
      <ul className="-mb-px flex min-w-0 sm:gap-6">
        {entry.pages.map((p) => {
          const active = p === current
          return (
            <li key={p.to} className="flex min-w-0 flex-1 basis-0 sm:flex-none sm:basis-auto">
              <Link
                to={active ? p.to + search : target(p)}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "relative flex h-10 w-full min-w-0 items-center justify-center rounded-t-sm border-b-2 px-1 text-sm sm:px-0.5 font-medium whitespace-nowrap transition-colors duration-150 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none focus-visible:ring-inset sm:justify-start",
                  active
                    ? "border-fg text-fg"
                    : "border-transparent text-fg-muted hover:border-border-strong hover:text-fg",
                )}
              >
                <span className="truncate">{p.tab ?? p.label}</span>
              </Link>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
