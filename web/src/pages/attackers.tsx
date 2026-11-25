import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { Network, SearchX, Users } from "lucide-react"
import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { Term } from "@/components/term"
import { Link, Navigate, useLocation, useSearchParams } from "react-router"
import { AttackerRow, ATTACKER_GRID } from "@/components/attacker-row"
import { CountryFlag } from "@/components/country-flag"
import { AttacksFilterBar } from "@/components/attacks-filter-bar"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { StickyFilters } from "@/components/sticky-filters"
import { Button } from "@/components/ui/button"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { useUrlParam } from "@/hooks/use-url-param"
import {
  api,
  ASN_LIMIT,
  queryKeys,
  type AsnItem,
  type AttackerFilters,
} from "@/lib/api"
import { countryName, formatNumber } from "@/lib/format"
import {
  ATTACKER_PARAMS,
  clearParams,
  filterNetworks,
  NETWORK_PARAMS,
  parseAttackerFilters,
  parseNetworkView,
} from "@/lib/list-filters"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50

function AttackerList({ filters }: { filters: AttackerFilters }) {
  const [, setParams] = useSearchParams()
  const query = useInfiniteQuery({
    queryKey: queryKeys.attackers(filters),
    queryFn: ({ pageParam }) => api.attackers(filters, pageParam, PAGE_SIZE),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const rows = query.data?.pages.flatMap((p) => p.items) ?? []

  const listRef = useRef<HTMLDivElement>(null)
  const [scrollMargin, setScrollMargin] = useState(0)
  useLayoutEffect(() => {
    const el = listRef.current
    if (!el) return
    const measure = () => setScrollMargin(el.getBoundingClientRect().top + window.scrollY)
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(document.body)
    return () => ro.disconnect()
  }, [query.isPending])

  const count = rows.length + (query.hasNextPage ? 1 : 0)
  const virtualizer = useWindowVirtualizer({
    count,
    estimateSize: () => 57,
    overscan: 12,
    scrollMargin,
    getItemKey: (i) => rows[i]?.ip ?? `loader-${i}`,
  })
  const items = virtualizer.getVirtualItems()
  const lastIndex = items.at(-1)?.index ?? -1
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query
  useEffect(() => {
    if (lastIndex >= rows.length - 10 && hasNextPage && !isFetchingNextPage) void fetchNextPage()
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  return (
    <>
      <div className="overflow-clip rounded-lg border bg-surface shadow-sm">
        <div
          className={cn(
            "sticky top-[calc(3.5rem+var(--filters-h,0px))] z-10 hidden border-b bg-surface px-5 py-2.5 type-column text-fg-subtle md:grid",
            ATTACKER_GRID,
          )}
        >
          <span>{t("attackers_col_ip")}</span>
          <span>{t("attackers_col_country")}</span>
          <span className="hidden 2xl:block">{t("attackers_col_network")}</span>
          <span>{t("attackers_col_what")}</span>
          <span className="text-right">{t("attackers_col_sensors_tags")}</span>
          <span className="text-right">{t("attackers_col_sessions")}</span>
          <span className="hidden text-right 2xl:block">{t("attackers_col_events")}</span>
          <span className="text-right">{t("attackers_col_last_seen")}</span>
        </div>
        {query.isPending ? (
          <SkeletonList rows={10} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title={t("attackers_error_title")}
            description={query.error.message}
            action={
              <Button variant="outline" size="sm" onClick={() => void query.refetch()}>
                {t("common_try_again")}
              </Button>
            }
          />
        ) : rows.length === 0 ? (
          <EmptyState
            variant="bare"
            icon={Users}
            title={t("attackers_empty_title")}
            description={t("attackers_empty_description")}
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => setParams((p) => clearParams(p, ATTACKER_PARAMS))}
              >
                {t("filters_clear_all")}
              </Button>
            }
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label={t("attackers_list_label")}
            aria-busy={isFetchingNextPage}
            className="relative w-full"
            style={{ height: virtualizer.getTotalSize() }}
          >
            {items.map((item) => {
              const attacker = rows[item.index]
              return (
                <div
                  key={item.key}
                  role="listitem"
                  data-index={item.index}
                  ref={virtualizer.measureElement}
                  className={cn("absolute top-0 left-0 w-full", item.index > 0 && "border-t")}
                  style={{
                    transform: `translateY(${item.start - virtualizer.options.scrollMargin}px)`,
                  }}
                >
                  {attacker ? <AttackerRow attacker={attacker} /> : <SkeletonRow />}
                </div>
              )
            })}
          </div>
        )}
      </div>
      {query.isSuccess && rows.length > 0 && !hasNextPage ? (
        <p className="mt-4 text-center text-xs text-fg-subtle">
          {t("attackers_end_of_list", { count: rows.length })}
        </p>
      ) : null}
    </>
  )
}

function AsnList() {
  const [params, setParams] = useSearchParams()
  const view = parseNetworkView(params)
  const q = useQuery({
    queryKey: queryKeys.asns(view.sort, view.since),
    queryFn: () => api.asns(view.sort, ASN_LIMIT, view.since),
  })
  const all = q.data?.items ?? []
  // The API takes no text or country filter for networks: narrow the loaded list here. When the
  // API cut the list at its page size, the search only sees the busiest networks; say so.
  const complete = all.length < ASN_LIMIT
  const items = filterNetworks(all, view)
  const filtered = Boolean(view.q || view.country)
  const grid = "md:grid-cols-[minmax(0,1fr)_9rem_5.5rem_5.5rem_5.5rem_6rem] md:gap-x-4"
  return (
    <>
      <div className="overflow-clip rounded-lg border bg-surface shadow-sm">
        <div
          className={cn(
            "sticky top-[calc(3.5rem+var(--filters-h,0px))] z-10 hidden border-b bg-surface px-5 py-2.5 type-column text-fg-subtle md:grid",
            grid,
          )}
        >
          <span>{t("attackers_col_network")}</span>
          <span>{t("attackers_col_country")}</span>
          <span className="text-right">{t("attackers_col_addresses")}</span>
          <span className="text-right">{t("attackers_col_sessions")}</span>
          <span className="text-right">{t("attackers_col_events")}</span>
          <span className="text-right">{t("attackers_col_last_seen")}</span>
        </div>
        {q.isPending ? (
          <SkeletonList rows={8} />
        ) : q.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title={t("attackers_networks_error_title")}
            description={q.error.message}
            action={
              <Button variant="outline" size="sm" onClick={() => void q.refetch()}>
                {t("common_try_again")}
              </Button>
            }
          />
        ) : items.length === 0 ? (
          <EmptyState
            variant="bare"
            icon={Network}
            title={
              filtered || view.since
                ? t("attackers_networks_empty_filtered_title")
                : t("attackers_networks_empty_title")
            }
            description={
              filtered || view.since
                ? t("attackers_networks_empty_filtered_description")
                : t("attackers_networks_empty_description")
            }
            action={
              filtered || view.since ? (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setParams((p) => clearParams(p, NETWORK_PARAMS))}
                >
                  {t("filters_clear_all")}
                </Button>
              ) : undefined
            }
          />
        ) : (
          <ul aria-label={t("attackers_networks_list_label")}>
            {items.map((n: AsnItem, i) => (
              <li key={n.asn} className={cn(i > 0 && "border-t")}>
                <Link
                  to={`/attackers?asn=${n.asn}`}
                  className={cn(
                    "grid grid-cols-3 items-center gap-y-1 px-4 py-3 transition-colors duration-150 hover:bg-surface-hover/50 sm:px-5",
                    grid,
                  )}
                >
                  <span className="col-span-3 flex min-w-0 items-baseline gap-2.5 md:col-span-1">
                    <span className="shrink-0 font-mono text-xs text-fg-muted">AS{n.asn}</span>
                    <span className="text-sm text-fg">{n.org ?? t("filters_network_unknown")}</span>
                  </span>
                  <span className="col-span-3 text-xs text-fg-muted md:col-span-1">
                    {n.country ? (
                      <CountryFlag code={n.country} showName />
                    ) : (
                      <span className="text-fg-subtle">{t("common_unknown")}</span>
                    )}
                  </span>
                  <Metric label={t("attackers_metric_addresses")} value={n.ips} />
                  <Metric label={t("attackers_metric_sessions")} value={n.sessions} />
                  <Metric
                    label={t("attackers_metric_events")}
                    value={n.events}
                    className="hidden md:block"
                  />
                  <span className="hidden justify-self-end md:block">
                    <RelativeTime iso={n.last_seen} className="text-xs" />
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
      {q.isSuccess && items.length > 0 ? (
        <p className="mt-4 text-center text-xs text-fg-subtle">
          {t("attackers_networks_count", {
            count: items.length,
            filtered: filtered ? "yes" : "no",
            complete: complete ? "yes" : "no",
            limit: ASN_LIMIT,
          })}
        </p>
      ) : null}
    </>
  )
}

function Metric({ label, value, className }: { label: string; value: number; className?: string }) {
  return (
    <span className={cn("text-sm text-fg tabular-nums md:text-right", className)}>
      {formatNumber(value)}
      <span className="ml-1 text-xs text-fg-subtle md:hidden">{label}</span>
    </span>
  )
}

/** Addresses. The old `?view=asns` link now lives at /networks. */
export function AttackersPage() {
  const [view] = useUrlParam("view")
  const { search } = useLocation()
  if (view === "asns") {
    const rest = new URLSearchParams(search)
    rest.delete("view")
    const qs = rest.toString()
    return <Navigate to={`/networks${qs ? `?${qs}` : ""}`} replace />
  }
  return <AttackersView asns={false} />
}

/** Hosting providers and networks (ASNs). */
export function NetworksPage() {
  return <AttackersView asns />
}

function AttackersView({ asns }: { asns: boolean }) {
  const [params] = useSearchParams()
  const { filters, sort, order } = parseAttackerFilters(params)

  const summaryCountry = filters.country ? (countryName(filters.country) ?? filters.country) : null
  const ascending = order === "asc"
  const description = asns
    ? tNodes("attackers_networks_description", {}, { asn: <Term id="asn">ASN</Term> })
    : summaryCountry
      ? t("attackers_description_country", {
          country: summaryCountry,
          order: ascending ? "asc" : "desc",
          sort,
        })
      : t("attackers_description")

  return (
    <>
      <PageHeader
        help={asns ? "networks" : "attackers"}
        title={asns ? t("attackers_networks_title") : t("attackers_title")}
        description={description}
      />

      <StickyFilters filters={<AttacksFilterBar group={asns ? "networks" : "attackers"} />}>
        {asns ? <AsnList /> : <AttackerList filters={filters} />}
      </StickyFilters>
    </>
  )
}
