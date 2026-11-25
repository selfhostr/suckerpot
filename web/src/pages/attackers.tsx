import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { Network, SearchX, Users } from "lucide-react"
import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { Term } from "@/components/term"
import { Link, Navigate, useLocation, useSearchParams } from "react-router"
import { AttackerRow, ATTACKER_GRID } from "@/components/attacker-row"
import { CountryFlag } from "@/components/country-flag"
import { EmptyState } from "@/components/empty-state"
import { FilterBar, SensorFilter } from "@/components/filter-bar"
import {
  CountryFilter,
  NetworkFilter,
  PeriodFilter,
  SearchFilter,
  SortFilter,
  TagFilter,
} from "@/components/list-filters"
import { PageHeader } from "@/components/page-header"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { StickyFilters } from "@/components/sticky-filters"
import { Button } from "@/components/ui/button"
import { useUrlParam } from "@/hooks/use-url-param"
import {
  api,
  ASN_LIMIT,
  ATTACKER_SORTS,
  queryKeys,
  type AsnItem,
  type AttackerFilters,
} from "@/lib/api"
import { countryName, formatNumber, plural } from "@/lib/format"
import {
  ASN_SORTS,
  ATTACKER_PARAMS,
  ATTACKER_SORT_LABELS,
  clearParams,
  filterNetworks,
  NETWORK_PARAMS,
  parseAttackerFilters,
  parseNetworkView,
} from "@/lib/list-filters"
import { parseInstant, windowLabel } from "@/lib/story"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50

const IP_SORTS = ATTACKER_SORTS.map((id) => ({ id, label: ATTACKER_SORT_LABELS[id] }))

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
          <span>IP address</span>
          <span>Country</span>
          <span className="hidden 2xl:block">Network</span>
          <span>What it did</span>
          <span className="text-right">Sensors and tags</span>
          <span className="text-right">Sessions</span>
          <span className="hidden text-right 2xl:block">Events</span>
          <span className="text-right">Last seen</span>
        </div>
        {query.isPending ? (
          <SkeletonList rows={10} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title="Could not load attackers"
            description={query.error.message}
            action={
              <Button variant="outline" size="sm" onClick={() => void query.refetch()}>
                Try again
              </Button>
            }
          />
        ) : rows.length === 0 ? (
          <EmptyState
            variant="bare"
            icon={Users}
            title="No attackers match these filters"
            description="Try other filters or a shorter IP prefix, or clear them to see every attacker."
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => setParams((p) => clearParams(p, ATTACKER_PARAMS))}
              >
                Clear all
              </Button>
            }
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label="Attackers"
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
          End of the list · {plural(rows.length, "attacker")}
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
          <span>Network</span>
          <span>Country</span>
          <span className="text-right">Addresses</span>
          <span className="text-right">Sessions</span>
          <span className="text-right">Events</span>
          <span className="text-right">Last seen</span>
        </div>
        {q.isPending ? (
          <SkeletonList rows={8} />
        ) : q.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title="Could not load networks"
            description={q.error.message}
            action={
              <Button variant="outline" size="sm" onClick={() => void q.refetch()}>
                Try again
              </Button>
            }
          />
        ) : items.length === 0 ? (
          <EmptyState
            variant="bare"
            icon={Network}
            title={filtered || view.since ? "No networks match these filters" : "No networks yet"}
            description={
              filtered || view.since
                ? "Try other filters, or clear them to see every network."
                : "Networks appear once GeoIP and ASN enrichment has run on incoming events."
            }
            action={
              filtered || view.since ? (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setParams((p) => clearParams(p, NETWORK_PARAMS))}
                >
                  Clear all
                </Button>
              ) : undefined
            }
          />
        ) : (
          <ul aria-label="Attacker networks">
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
                    <span className="text-sm text-fg">{n.org ?? "Unknown network"}</span>
                  </span>
                  <span className="col-span-3 text-xs text-fg-muted md:col-span-1">
                    {n.country ? (
                      <CountryFlag code={n.country} showName />
                    ) : (
                      <span className="text-fg-subtle">Unknown</span>
                    )}
                  </span>
                  <Metric label="Addresses" value={n.ips} />
                  <Metric label="Sessions" value={n.sessions} />
                  <Metric label="Events" value={n.events} className="hidden md:block" />
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
          {filtered
            ? `${plural(items.length, "network")} match${items.length === 1 ? "es" : ""}`
            : plural(items.length, "network")}
          {complete ? "" : ` among the ${ASN_LIMIT} busiest`}
        </p>
      ) : null}
    </>
  )
}

function Metric({ label, value, className }: { label: string; value: number; className?: string }) {
  return (
    <span className={cn("text-sm text-fg tabular-nums md:text-right", className)}>
      {formatNumber(value)}
      <span className="ml-1 text-xs text-fg-subtle md:hidden">{label.toLowerCase()}</span>
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

const countryChip = {
  param: "country",
  label: "Country",
  render: (v: string) => <CountryFlag code={v.toUpperCase()} showName className="text-fg" />,
}

function AttackersView({ asns }: { asns: boolean }) {
  const [params] = useSearchParams()
  const { filters, sort, order } = parseAttackerFilters(params)

  const summaryCountry = filters.country ? (countryName(filters.country) ?? filters.country) : null
  const ascending = order === "asc"
  const description = asns ? (
    <>
      Hosting providers and networks (<Term id="asn">ASN</Term>) the attacks come from. Open one to
      see its addresses.
    </>
  ) : summaryCountry ? (
    `Addresses from ${summaryCountry}, ${ascending ? "lowest" : "highest"} ${ATTACKER_SORT_LABELS[sort].toLowerCase()} first.`
  ) : (
    "Every address that touched a sensor, with the story of what it did."
  )

  return (
    <>
      <PageHeader
        help={asns ? "networks" : "attackers"}
        title={asns ? "Attacker networks" : "Attackers"}
        description={description}
      />

      {asns ? (
        <StickyFilters
          filters={
            <FilterBar
              alsoClears={[...NETWORK_PARAMS]}
              trailing={
                <SortFilter options={ASN_SORTS} defaultSort="sessions" directional={false} />
              }
              chips={[
                {
                  param: "q",
                  label: "Search",
                  render: (v) => <span>{v}</span>,
                },
                countryChip,
                {
                  param: "since",
                  label: "Period",
                  render: (v) => <span>{windowLabel(parseInstant(v), undefined)}</span>,
                },
              ]}
            >
              <SearchFilter
                fields={[
                  {
                    param: "q",
                    label: "Network",
                    placeholder: "AS number, network or country",
                  },
                ]}
                clean={(_, raw) => raw.trim().slice(0, 64) || undefined}
              />
              <CountryFilter />
              <PeriodFilter sinceOnly />
            </FilterBar>
          }
        >
          <AsnList />
        </StickyFilters>
      ) : (
        <StickyFilters
          filters={
            <FilterBar
              alsoClears={[...ATTACKER_PARAMS]}
              trailing={<SortFilter options={IP_SORTS} defaultSort="last_seen" />}
              chips={[
                {
                  param: "q",
                  label: "IP prefix",
                  render: (v) => <span className="font-mono">{v}</span>,
                },
                countryChip,
                {
                  param: "asn",
                  label: "Network",
                  render: (v) => <span className="font-mono">AS{v}</span>,
                },
                {
                  param: "tag",
                  label: "Tag",
                  render: (v) => <span className="font-mono">{v}</span>,
                },
              ]}
            >
              <SearchFilter
                fields={[
                  {
                    param: "q",
                    label: "IP prefix",
                    placeholder: "IP prefix, e.g. 203.0.113",
                  },
                ]}
                clean={(_, raw) =>
                  /^[0-9a-fA-F.:]{1,45}$/.test(raw.trim()) ? raw.trim() : undefined
                }
              />
              <SensorFilter />
              <CountryFilter />
              <NetworkFilter />
              <TagFilter />
            </FilterBar>
          }
        >
          <AttackerList filters={filters} />
        </StickyFilters>
      )}
    </>
  )
}
