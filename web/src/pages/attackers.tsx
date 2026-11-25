import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { Network, Search, SearchX, Users } from "lucide-react"
import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { Term } from "@/components/term"
import { Link, Navigate, useLocation, useSearchParams } from "react-router"
import { AttackerRow, ATTACKER_GRID } from "@/components/attacker-row"
import { CountryFlag } from "@/components/country-flag"
import { EmptyState } from "@/components/empty-state"
import { FilterBar, SensorFilter } from "@/components/filter-bar"
import { PageHeader } from "@/components/page-header"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { SegmentedControl } from "@/components/segmented-control"
import { useUrlParam } from "@/hooks/use-url-param"
import {
  api,
  ATTACKER_SORTS,
  queryKeys,
  type AsnItem,
  type AttackerFilters,
  type AttackerSort,
} from "@/lib/api"
import { countryName, formatNumber, plural } from "@/lib/format"
import { parseSensors } from "@/lib/sensors"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50

const IP_SORTS: readonly { id: AttackerSort; label: string }[] = [
  { id: "last_seen", label: "Last seen" },
  { id: "sessions", label: "Sessions" },
  { id: "events", label: "Events" },
]
const ASN_SORTS = [
  { id: "sessions", label: "Sessions" },
  { id: "ips", label: "Addresses" },
  { id: "events", label: "Events" },
] as const
type AsnSort = (typeof ASN_SORTS)[number]["id"]

function SortSwitch({
  options,
  value,
  onChange,
}: {
  options: readonly { id: string; label: string }[]
  value: string
  onChange: (id: string) => void
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-fg-subtle">Sort by</span>
      <SegmentedControl
        label="Sort by"
        value={value}
        onChange={onChange}
        options={options.map((o) => ({ value: o.id, label: o.label }))}
      />
    </div>
  )
}

/** IP-prefix search: typing updates the URL after a short pause. */
function IpSearch() {
  const [q, setQ] = useUrlParam("q")
  const [text, setText] = useState(q ?? "")
  const inputRef = useRef<HTMLInputElement>(null)
  useEffect(() => {
    // The URL changed from elsewhere (e.g. "Clear filters"): mirror it unless the user is typing.
    if (document.activeElement === inputRef.current) return
    const id = setTimeout(() => setText(q ?? ""), 0)
    return () => clearTimeout(id)
  }, [q])
  useEffect(() => {
    const clean = text.trim()
    if (clean === (q ?? "")) return
    const id = setTimeout(() => setQ(/^[0-9a-fA-F.:]{1,45}$/.test(clean) ? clean : null), 250)
    return () => clearTimeout(id)
  }, [text, q, setQ])
  return (
    <div className="relative w-full sm:w-56">
      <Search
        aria-hidden
        className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-fg-subtle"
      />
      <Input
        ref={inputRef}
        value={text}
        onChange={(e) => setText(e.target.value)}
        inputMode="text"
        autoComplete="off"
        spellCheck={false}
        maxLength={45}
        placeholder="IP prefix, e.g. 203.0.113"
        aria-label="Search by IP prefix"
        className="h-8 pl-8 font-mono text-xs md:text-xs"
      />
    </div>
  )
}

function useIpFilters(): { filters: AttackerFilters; sort: AttackerSort } {
  const [p] = useSearchParams()
  const sensor = parseSensors(p.get("sensor"))
  const rawSort = p.get("sort")
  const sort = ATTACKER_SORTS.includes(rawSort as AttackerSort)
    ? (rawSort as AttackerSort)
    : "last_seen"
  return {
    sort,
    filters: {
      sort,
      sensor: sensor.length ? sensor : undefined,
      country: p.get("country") ?? undefined,
      asn: p.get("asn") ?? undefined,
      tag: p.get("tag") ?? undefined,
      q: p.get("q") ?? undefined,
    },
  }
}

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
            "sticky top-14 z-10 hidden border-b bg-surface px-5 py-2.5 text-2xs font-medium tracking-wide text-fg-subtle uppercase md:grid",
            ATTACKER_GRID,
          )}
        >
          <span>Address</span>
          <span>Profile</span>
          <span className="text-right">Sensors and tags</span>
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
            description="Try another sensor or a shorter IP prefix, or clear the filters."
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() =>
                  setParams((p) => {
                    const next = new URLSearchParams()
                    const sort = p.get("sort")
                    if (sort) next.set("sort", sort)
                    return next
                  })
                }
              >
                Clear filters
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

function AsnList({ sort }: { sort: AsnSort }) {
  const q = useQuery({ queryKey: queryKeys.asns(sort), queryFn: () => api.asns(sort, 100) })
  const items = q.data?.items ?? []
  const grid = "md:grid-cols-[minmax(0,1fr)_5.5rem_5.5rem_5.5rem_6rem] md:gap-x-4"
  return (
    <div className="overflow-clip rounded-lg border bg-surface shadow-sm">
      <div
        className={cn(
          "sticky top-14 z-10 hidden border-b bg-surface px-5 py-2.5 text-2xs font-medium tracking-wide text-fg-subtle uppercase md:grid",
          grid,
        )}
      >
        <span>Network</span>
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
        />
      ) : items.length === 0 ? (
        <EmptyState
          variant="bare"
          icon={Network}
          title="No networks yet"
          description="Networks appear once GeoIP and ASN enrichment has run on incoming events."
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
                <span className="col-span-3 flex min-w-0 items-center gap-2.5 md:col-span-1">
                  {n.country ? <CountryFlag code={n.country} showName={false} /> : null}
                  <span className="shrink-0 font-mono text-xs text-fg-muted">AS{n.asn}</span>
                  <span className="truncate text-sm text-fg">{n.org ?? "Unknown network"}</span>
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

function AttackersView({ asns }: { asns: boolean }) {
  const [rawSort, setSort] = useUrlParam("sort")
  const { filters, sort } = useIpFilters()
  const asnSort: AsnSort = ASN_SORTS.some((o) => o.id === rawSort)
    ? (rawSort as AsnSort)
    : "sessions"

  const summaryCountry = filters.country ? (countryName(filters.country) ?? filters.country) : null
  const description = asns ? (
    <>
      Hosting providers and networks (<Term id="asn">ASN</Term>) the attacks come from. Open one to
      see its addresses.
    </>
  ) : summaryCountry ? (
    `Addresses from ${summaryCountry}, ${IP_SORTS.find((o) => o.id === sort)?.label.toLowerCase()} first.`
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
        <>
          <div className="mb-4">
            <SortSwitch
              options={ASN_SORTS}
              value={asnSort}
              onChange={(v) => setSort(v === "sessions" ? null : v)}
            />
          </div>
          <AsnList sort={asnSort} />
        </>
      ) : (
        <>
          <FilterBar
            className="mb-4"
            alsoClears={["sensor", "q"]}
            chips={[
              {
                param: "country",
                label: "Country",
                render: (v) => <CountryFlag code={v} showName className="text-fg" />,
              },
              {
                param: "asn",
                label: "Network",
                render: (v) => <span className="font-mono">AS{v}</span>,
              },
              { param: "tag", label: "Tag", render: (v) => <span className="font-mono">{v}</span> },
            ]}
          >
            <SensorFilter />
            <IpSearch />
            <div className="sm:ml-auto">
              <SortSwitch
                options={IP_SORTS}
                value={sort}
                onChange={(v) => setSort(v === "last_seen" ? null : v)}
              />
            </div>
          </FilterBar>
          <AttackerList filters={filters} />
        </>
      )}
    </>
  )
}
