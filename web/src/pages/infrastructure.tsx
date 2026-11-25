import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { Download, Network, Search, SearchX, Workflow } from "lucide-react"
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
import { t, tk } from "@/i18n"
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
  { value: "all", labelKey: tk("common_all") },
  { value: "domain", labelKey: tk("infra_filter_type_domains") },
  { value: "ip", labelKey: tk("infra_filter_type_ips") },
  { value: "url", labelKey: tk("infra_filter_type_urls") },
  { value: "hash", labelKey: tk("infra_filter_type_hashes") },
] as const

const ROLE_OPTIONS = [
  { value: "all", labelKey: tk("infra_filter_role_any") },
  { value: "download_host", labelKey: tk("infra_filter_role_download_host") },
  { value: "contacted_host", labelKey: tk("infra_filter_role_contacted_host") },
  { value: "hash", labelKey: tk("infra_filter_role_hash") },
] as const

const KNOWN_OPTIONS = [
  { value: "all", labelKey: tk("infra_filter_known_any") },
  { value: "true", labelKey: tk("infra_filter_known_true") },
  { value: "false", labelKey: tk("infra_filter_known_false") },
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
        placeholder={t("infra_search_placeholder")}
        aria-label={t("infra_search_label")}
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
  const [diagram, setDiagram] = useUrlParam("diagram")
  const showDiagram = diagram === "1"
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
      ? t("infra_headline_none")
      : t("infra_headline", {
          indicators: graph.data.summary.indicators,
          sources: graph.data.summary.sources,
          when: windowPhrase(hours),
        })
    : t("infra_headline_loading")

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
            aria-label={t("infra_export_label", { format: f })}
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
        title={t("infra_title")}
        description={headline}
        actions={exportButtons}
      />

      {/* The diagram is off until asked for. From 2xl it sits beside the control servers. */}
      <div
        className={cn(
          "mb-8 grid grid-cols-1 gap-4",
          showDiagram && "2xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]",
        )}
      >
        <FindingCard
          className="min-w-0"
          eyebrow={t("infra_eyebrow")}
          finding={finding?.finding ?? t("infra_loading")}
          detail={finding?.detail}
          action={
            <div className="flex flex-wrap items-center gap-2">
              <SegmentedControl
                label={t("infra_window_label")}
                value={String(hours)}
                onChange={(v) => setWin(v === "168" ? null : v)}
                options={WINDOWS.map((w) => ({ value: w.value, label: w.label }))}
              />
              <Button
                variant="outline"
                size="sm"
                aria-pressed={showDiagram}
                onClick={() => setDiagram(showDiagram ? null : "1")}
              >
                <Workflow aria-hidden />
                {showDiagram ? t("infra_diagram_hide") : t("infra_diagram_show")}
              </Button>
            </div>
          }
        >
          {!showDiagram ? null : graph.isPending ? (
            <div role="status" aria-label={t("common_loading")} className="space-y-3">
              <Skeleton className="h-64 w-full" />
            </div>
          ) : graph.isError ? (
            <EmptyState
              variant="bare"
              icon={SearchX}
              title={t("infra_error_graph")}
              description={graph.error.message}
              action={
                <Button variant="outline" size="sm" onClick={() => void graph.refetch()}>
                  {t("common_try_again")}
                </Button>
              }
            />
          ) : graph.data.nodes.length === 0 ? (
            <EmptyState
              variant="bare"
              icon={Network}
              title={t("infra_graph_empty_title")}
              description={t("infra_graph_empty_description")}
            />
          ) : (
            <>
              <div className="hidden md:block">
                <FlowDiagram graph={graph.data} onOpenIndicator={open} />
              </div>
              <div className="md:hidden">
                <FlowList graph={graph.data} onOpenIndicator={open} />
                <p className="mt-3 text-xs text-fg-muted">
                  {t("infra_diagram_narrow")}
                </p>
              </div>
            </>
          )}
        </FindingCard>

        <C2Section className="min-w-0" />
      </div>

      <div className="mb-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <div className="min-w-0 space-y-1">
          <h2 className="type-section-title text-fg">{t("infra_indicators_title")}</h2>
          <p className="max-w-2xl type-lede text-fg-muted">
            {range === "all"
              ? t("infra_indicators_all")
              : t("infra_indicators_window", {
                  window:
                    WINDOWS.find((w) => w.hours === hours)?.label ??
                    t("infra_days", { count: Math.round(hours / 24) }),
                })}
          </p>
        </div>
        <SegmentedControl
          label={t("infra_range_label")}
          value={range === "all" ? "all" : "window"}
          onChange={(v) => setRange(v === "all" ? "all" : null)}
          options={[
            { value: "window", label: t("infra_range_window") },
            { value: "all", label: t("infra_range_all") },
          ]}
        />
      </div>

      <FilterBar
        className="mb-4"
        chips={[{ param: "family", label: t("infra_filter_family") }]}
        alsoClears={["type", "role", "known", "q", "range"]}
      >
        <SegmentedControl
          label={t("infra_filter_type_label")}
          value={type ?? "all"}
          onChange={(v) => setType(v === "all" ? null : v)}
          options={TYPE_OPTIONS.map((o) => ({ value: o.value, label: t(o.labelKey) }))}
        />
        <SegmentedControl
          label={t("infra_filter_role_label")}
          value={role ?? "all"}
          onChange={(v) => setRole(v === "all" ? null : v)}
          options={ROLE_OPTIONS.map((o) => ({ value: o.value, label: t(o.labelKey) }))}
        />
        <SegmentedControl
          label={t("infra_filter_known_label")}
          value={known ?? "all"}
          onChange={(v) => setKnown(v === "all" ? null : v)}
          options={KNOWN_OPTIONS.map((o) => ({ value: o.value, label: t(o.labelKey) }))}
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
          <span className="truncate">{t("infra_col_indicator")}</span>
          <span className="truncate">{t("infra_col_intel")}</span>
          <span className="truncate">{t("infra_col_family")}</span>
          <span className="truncate text-right">{t("infra_col_addresses")}</span>
          <span className="truncate text-right">{t("infra_col_sightings")}</span>
          <span className="truncate text-right">{t("infra_col_last_seen")}</span>
          <span className="sr-only">{t("common_copy")}</span>
        </div>
        {query.isPending ? (
          <SkeletonList rows={8} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title={t("infra_error_indicators")}
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
            icon={Network}
            title={filtered ? t("infra_empty_filtered_title") : t("infra_empty_title")}
            description={
              filtered
                ? t("infra_empty_filtered_description")
                : t("infra_empty_description")
            }
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label={t("infra_indicators_title")}
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
          {t("infra_end_of_list", { count: rows.length })}
        </p>
      ) : null}
      <p className="mt-4 text-xs text-fg-subtle">
        {t("infra_passive_note")}
      </p>

      <IndicatorDrawer id={openNumber} onClose={() => setOpenId(null)} onSelect={open} />
    </>
  )
}
