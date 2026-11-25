import { useInfiniteQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { Flag, Search, SearchX } from "lucide-react"
import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { CAMPAIGN_GRID, CampaignRow } from "@/components/campaigns/campaign-row"
import { EmptyState } from "@/components/empty-state"
import { FilterBar, SensorFilter } from "@/components/filter-bar"
import { PageHeader } from "@/components/page-header"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useUrlParam } from "@/hooks/use-url-param"
import { api, queryKeys } from "@/lib/api"
import {
  CAMPAIGN_WINDOWS,
  describeCampaigns,
  windowDays,
  type CampaignFilters,
  type CampaignStatus,
} from "@/lib/campaigns"
import { formatNumber, plural } from "@/lib/format"
import { parseSensors } from "@/lib/sensors"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50

const STATUS_OPTIONS = [
  { value: "any", label: "Any" },
  { value: "active", label: "Active" },
  { value: "quiet", label: "Quiet" },
] as const

/** Substring search on the campaign name: typing updates the URL after a short pause. */
function CampaignSearch() {
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
    <div className="relative w-full sm:w-56">
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
        maxLength={64}
        placeholder="Search by name"
        aria-label="Search campaigns by name"
        className="h-8 pl-8 text-xs md:text-xs"
      />
    </div>
  )
}

function useCampaignFilters() {
  const [statusParam, setStatus] = useUrlParam("status")
  const [windowParam, setWindow] = useUrlParam("window")
  const [technique] = useUrlParam("technique")
  const [family] = useUrlParam("family")
  const [q] = useUrlParam("q")
  const [sensorParam] = useUrlParam("sensor")
  const sensor = parseSensors(sensorParam)
  const days = windowDays(windowParam)
  const status: CampaignStatus | undefined =
    statusParam === "active" || statusParam === "quiet" ? statusParam : undefined
  const filters: CampaignFilters = {
    status,
    sensor: sensor.length ? sensor : undefined,
    // Same shapes the API accepts; anything else is ignored instead of failing with a 422.
    technique: /^T\d{4}(\.\d{3})?$/.test(technique ?? "") ? (technique ?? undefined) : undefined,
    family: family && family.length <= 32 ? family : undefined,
    days: days || undefined,
    q: q ?? undefined,
  }
  return { filters, days, status, windowParam, setStatus, setWindow }
}

export function CampaignsPage() {
  const { filters, days, status, windowParam, setStatus, setWindow } = useCampaignFilters()
  const query = useInfiniteQuery({
    queryKey: queryKeys.campaigns(filters),
    queryFn: ({ pageParam }) => api.campaigns(filters, pageParam, PAGE_SIZE),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const rows = query.data?.pages.flatMap((p) => p.items) ?? []
  const filtered = Boolean(
    filters.status ?? filters.sensor ?? filters.technique ?? filters.family ?? filters.q,
  )

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
    estimateSize: () => (wide ? 76 : 170),
    overscan: 8,
    scrollMargin,
    getItemKey: (i) => rows[i]?.id ?? `loader-${i}`,
  })
  const items = virtualizer.getVirtualItems()
  const lastIndex = items.at(-1)?.index ?? -1
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query
  useEffect(() => {
    if (lastIndex >= rows.length - 8 && hasNextPage && !isFetchingNextPage) void fetchNextPage()
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  const headline = query.isSuccess
    ? describeCampaigns(rows, { days, more: hasNextPage })
    : "Groups of attacks that share the same tools, scripts or servers."

  return (
    <>
      <PageHeader help="campaigns" title="Campaigns" description={headline} />

      <FilterBar
        className="mb-4"
        alsoClears={["sensor", "status", "q", "window"]}
        chips={[
          {
            param: "technique",
            label: "Technique",
            render: (v) => <span className="font-mono">{v}</span>,
          },
          {
            param: "family",
            label: "Family",
            render: (v) => <span className="font-mono">{v}</span>,
          },
        ]}
      >
        <SensorFilter />
        <SegmentedControl
          label="Status"
          value={status ?? "any"}
          onChange={(v) => setStatus(v === "any" ? null : v)}
          options={STATUS_OPTIONS}
        />
        <SegmentedControl
          label="Last seen"
          value={
            windowParam && CAMPAIGN_WINDOWS.some((w) => w.value === windowParam)
              ? windowParam
              : "30"
          }
          onChange={(v) => setWindow(v === "30" ? null : v)}
          options={CAMPAIGN_WINDOWS.map((w) => ({ value: w.value, label: w.label }))}
        />
        <CampaignSearch />
      </FilterBar>

      <div className="overflow-clip rounded-lg border bg-surface shadow-sm">
        <div
          className={cn(
            "sticky top-14 z-10 hidden border-b bg-surface px-5 py-2.5 text-2xs font-medium tracking-wide text-fg-subtle uppercase md:grid",
            CAMPAIGN_GRID,
          )}
        >
          <span>Campaign</span>
          <span>Playbook</span>
          <span>Targets</span>
          <span className="text-right">Status</span>
        </div>
        {query.isPending ? (
          <SkeletonList rows={8} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title="Could not load campaigns"
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
            icon={Flag}
            title={filtered ? "No campaigns match" : "No campaigns yet"}
            description={
              filtered
                ? "Try another window or sensor, or clear the filters."
                : "A campaign appears when the same script, server or exploit shows up from two different addresses. It can take a few minutes after the sessions end."
            }
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label="Campaigns"
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
                  {row ? <CampaignRow campaign={row} /> : <SkeletonRow />}
                </div>
              )
            })}
          </div>
        )}
      </div>
      {query.isSuccess && rows.length > 0 && !hasNextPage ? (
        <p className="mt-4 text-center text-xs text-fg-subtle">
          End of the list · {plural(rows.length, "campaign")} ·{" "}
          {formatNumber(rows.reduce((n, c) => n + c.sessions, 0))} sessions
        </p>
      ) : null}
      <p className="mt-4 text-xs text-fg-subtle">
        Campaigns are grouped automatically from what sessions have in common. Research scanners are
        left out.
      </p>
    </>
  )
}
