import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { Download, Network, Search, SearchX } from "lucide-react"
import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { EmptyState } from "@/components/empty-state"
import { FilterBar } from "@/components/filter-bar"
import { FindingCard } from "@/components/finding-card"
import { C2Section } from "@/components/infrastructure/c2-section"
import { FlowDiagram } from "@/components/infrastructure/flow-diagram"
import { FlowList } from "@/components/infrastructure/flow-list"
import { IndicatorDrawer } from "@/components/infrastructure/indicator-drawer"
import { INDICATOR_GRID, IndicatorRow } from "@/components/infrastructure/indicator-row"
import { PageHeader } from "@/components/page-header"
import { SegmentedControl } from "@/components/segmented-control"
import { Skeleton } from "@/components/ui/skeleton"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useUrlParam } from "@/hooks/use-url-param"
import { api, queryKeys } from "@/lib/api"
import { formatNumber, plural } from "@/lib/format"
import {
  describeInfrastructure,
  exportHref,
  WINDOWS,
  windowHours,
  windowPhrase,
} from "@/lib/infrastructure"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50

const TYPE_OPTIONS = [
  { value: "all", label: "All" },
  { value: "domain", label: "Domains" },
  { value: "ip", label: "IPs" },
  { value: "url", label: "URLs" },
  { value: "hash", label: "Hashes" },
] as const

const ROLE_OPTIONS = [
  { value: "all", label: "Any role" },
  { value: "download_host", label: "Payload sources" },
  { value: "contacted_host", label: "Contacted" },
] as const

const KNOWN_OPTIONS = [
  { value: "all", label: "Any verdict" },
  { value: "true", label: "Known malicious" },
  { value: "false", label: "Not known" },
] as const

/** Substring search: typing updates the URL after a short pause. */
function IndicatorSearch() {
  const [q, setQ] = useUrlParam("q")
  const [text, setText] = useState(q ?? "")
  const inputRef = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (document.activeElement === inputRef.current) return
    const id = setTimeout(() => setText(q ?? ""), 0)
    return () => clearTimeout(id)
  }, [q])
  useEffect(() => {
    const clean = text.trim()
    if (clean === (q ?? "")) return
    const id = setTimeout(() => setQ(clean || null), 250)
    return () => clearTimeout(id)
  }, [text, q, setQ])
  return (
    <div className="relative w-full sm:w-64">
      <Search
        aria-hidden
        className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-fg-subtle"
      />
      <Input
        ref={inputRef}
        value={text}
        onChange={(e) => setText(e.target.value)}
        autoComplete="off"
        spellCheck={false}
        maxLength={128}
        placeholder="Search, e.g. bins/x86"
        aria-label="Search indicators"
        size="sm"
        className="pl-8 font-mono"
      />
    </div>
  )
}

export function InfrastructurePage() {
  const [win, setWin] = useUrlParam("window")
  const [type, setType] = useUrlParam("type")
  const [role, setRole] = useUrlParam("role")
  const [known, setKnown] = useUrlParam("known")
  const [family] = useUrlParam("family")
  const [range, setRange] = useUrlParam("range")
  const [q] = useUrlParam("q")
  const [openId, setOpenId] = useUrlParam("indicator")
  const hours = windowHours(win)
  const filters = {
    type: type ?? undefined,
    role: role ?? undefined,
    known: known ?? undefined,
    family: family ?? undefined,
    hours: range === "all" ? undefined : String(hours),
    q: q ?? undefined,
  }
  const open = (id: number) => setOpenId(String(id))
  const openNumber = openId !== null && /^\d{1,15}$/.test(openId) ? Number(openId) : null

  const graph = useQuery({
    queryKey: queryKeys.infrastructureGraph(hours, ""),
    queryFn: () => api.infrastructureGraph(hours),
  })
  const query = useInfiniteQuery({
    queryKey: queryKeys.indicators(filters),
    queryFn: ({ pageParam }) => api.indicators(filters, pageParam, PAGE_SIZE),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const rows = query.data?.pages.flatMap((p) => p.items) ?? []
  const filtered = Boolean(type ?? role ?? known ?? family ?? q)

  const finding = graph.data ? describeInfrastructure(graph.data.summary, hours) : null
  const headline = graph.data
    ? graph.data.summary.indicators === 0
      ? "Nothing recorded yet."
      : `${plural(graph.data.summary.indicators, "indicator")} from ${plural(
          graph.data.summary.sources,
          "address",
          "addresses",
        )} ${windowPhrase(hours)}.`
    : "URLs, hosts and file hashes attackers used."

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

  // Row height differs between the stacked phone layout and the desktop grid.
  const [wide] = useState(() =>
    "matchMedia" in window ? window.matchMedia("(min-width: 768px)").matches : true,
  )
  const count = rows.length + (query.hasNextPage ? 1 : 0)
  const virtualizer = useWindowVirtualizer({
    count,
    // Close to the real row heights, so the list never shows blank space below the drawn rows.
    estimateSize: () => (wide ? 62 : 120),
    overscan: 10,
    scrollMargin,
    getItemKey: (i) => rows[i]?.id ?? `loader-${i}`,
  })
  const items = virtualizer.getVirtualItems()
  const lastIndex = items.at(-1)?.index ?? -1
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query
  useEffect(() => {
    if (lastIndex >= rows.length - 10 && hasNextPage && !isFetchingNextPage) void fetchNextPage()
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  const exportButtons = (
    <>
      {(["csv", "stix"] as const).map((f) => (
        <Button key={f} variant="outline" size="sm" asChild>
          <a
            href={exportHref(f, filters)}
            download
            aria-label={`Download ${f === "csv" ? "CSV" : "STIX 2.1 bundle"} of the indicators matching the filters`}
          >
            <Download aria-hidden />
            {f === "csv" ? "CSV" : "STIX 2.1"}
          </a>
        </Button>
      ))}
    </>
  )

  return (
    <>
      <PageHeader
        help="infrastructure"
        title="Hosts & URLs"
        description={headline}
        actions={exportButtons}
      />

      {/* From 2xl the diagram and the control servers sit side by side, above the table. */}
      <div className="mb-8 grid grid-cols-1 gap-4 2xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <FindingCard
          className="min-w-0"
          eyebrow="Sources, indicators and malware families"
          finding={finding?.finding ?? "Reading the infrastructure…"}
          detail={finding?.detail}
          action={
            <SegmentedControl
              label="Time window"
              value={String(hours)}
              onChange={(v) => setWin(v === "168" ? null : v)}
              options={WINDOWS.map((w) => ({ value: w.value, label: w.label }))}
            />
          }
        >
          {graph.isPending ? (
            <div role="status" aria-label="Loading" className="space-y-3">
              <Skeleton className="h-64 w-full" />
            </div>
          ) : graph.isError ? (
            <EmptyState
              variant="bare"
              icon={SearchX}
              title="Could not load the infrastructure"
              description={graph.error.message}
              action={
                <Button variant="outline" size="sm" onClick={() => void graph.refetch()}>
                  Try again
                </Button>
              }
            />
          ) : graph.data.nodes.length === 0 ? (
            <EmptyState
              variant="bare"
              icon={Network}
              title="No infrastructure to draw yet"
              description="When a session downloads a file or names a host, it appears here with the addresses that used it."
            />
          ) : (
            <>
              <div className="hidden md:block">
                <FlowDiagram graph={graph.data} onOpenIndicator={open} />
              </div>
              <div className="md:hidden">
                <FlowList graph={graph.data} onOpenIndicator={open} />
                <p className="mt-3 text-xs text-fg-muted">
                  The diagram needs a wider screen. The table below lists every indicator.
                </p>
              </div>
            </>
          )}
        </FindingCard>

        <C2Section className="min-w-0" />
      </div>

      <div className="mb-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <div className="min-w-0 space-y-1">
          <h2 className="type-section-title text-fg">Indicators</h2>
          <p className="max-w-2xl type-lede text-fg-muted">
            {range === "all"
              ? "Every indicator on record, most recently seen first."
              : `Seen in the last ${WINDOWS.find((w) => w.hours === hours)?.label ?? `${Math.round(hours / 24)} days`}, the same window as the diagram.`}
          </p>
        </div>
        <SegmentedControl
          label="Table time range"
          value={range === "all" ? "all" : "window"}
          onChange={(v) => setRange(v === "all" ? "all" : null)}
          options={[
            { value: "window", label: "Diagram window" },
            { value: "all", label: "All time" },
          ]}
        />
      </div>

      <FilterBar
        className="mb-4"
        chips={[{ param: "family", label: "Family" }]}
        alsoClears={["type", "role", "known", "q", "range"]}
      >
        <SegmentedControl
          label="Indicator type"
          value={type ?? "all"}
          onChange={(v) => setType(v === "all" ? null : v)}
          options={TYPE_OPTIONS}
        />
        <SegmentedControl
          label="Role"
          value={role ?? "all"}
          onChange={(v) => setRole(v === "all" ? null : v)}
          options={ROLE_OPTIONS}
        />
        <SegmentedControl
          label="Verdict"
          value={known ?? "all"}
          onChange={(v) => setKnown(v === "all" ? null : v)}
          options={KNOWN_OPTIONS}
        />
        <IndicatorSearch />
      </FilterBar>

      <div className="overflow-clip rounded-lg border bg-surface shadow-sm">
        <div
          className={cn(
            "sticky top-14 z-10 hidden border-b bg-surface px-5 py-2.5 type-column text-fg-subtle md:grid",
            INDICATOR_GRID,
          )}
        >
          <span>Indicator</span>
          <span>Threat intelligence</span>
          <span>Family</span>
          <span className="text-right">Addresses</span>
          <span className="text-right">Sightings</span>
          <span className="text-right">Last seen</span>
          <span className="sr-only">Copy</span>
        </div>
        {query.isPending ? (
          <SkeletonList rows={8} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title="Could not load indicators"
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
            icon={Network}
            title={filtered ? "No indicators match" : "No indicators yet"}
            description={
              filtered
                ? "Try another type or a shorter search, or clear the filters."
                : "Indicators are extracted from downloads, commands and requests as they are recorded."
            }
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label="Indicators"
            aria-busy={isFetchingNextPage}
            className="relative w-full"
            style={{ height: virtualizer.getTotalSize() }}
          >
            {items.map((item) => {
              const row = rows[item.index]
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
                  {row ? <IndicatorRow item={row} onOpen={open} /> : <SkeletonRow />}
                </div>
              )
            })}
          </div>
        )}
      </div>
      {query.isSuccess && rows.length > 0 && !hasNextPage ? (
        <p className="mt-4 text-center text-xs text-fg-subtle">
          End of the list · {formatNumber(rows.length)} indicators
        </p>
      ) : null}
      <p className="mt-4 text-xs text-fg-subtle">
        Passive view: indicators were only observed. Nothing here is fetched, opened or reported.
        Exports hold up to 5,000 indicators matching the filters.
      </p>

      <IndicatorDrawer id={openNumber} onClose={() => setOpenId(null)} onSelect={open} />
    </>
  )
}
