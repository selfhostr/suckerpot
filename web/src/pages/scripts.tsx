import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { FileCode2, Search, SearchX } from "lucide-react"
import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { EmptyState } from "@/components/empty-state"
import { FilterBar, SensorFilter } from "@/components/filter-bar"
import { PageHeader } from "@/components/page-header"
import { ScriptRow, SCRIPT_GRID } from "@/components/scripts/script-row"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useSensorFilter, sensorParam } from "@/hooks/use-sensor-filter"
import { useUrlParam } from "@/hooks/use-url-param"
import { t } from "@/i18n"
import {
  describeScripts,
  scriptKeys,
  scriptsApi,
  type ScriptFilters,
  type ScriptSort,
} from "@/lib/scripts"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50
type View = "recent" | "common" | "new"

const VIEWS: Record<View, { sort: ScriptSort; new?: string }> = {
  recent: { sort: "recent" },
  common: { sort: "common" },
  new: { sort: "newest", new: "true" },
}

/** Free-text search in the commands: typing updates the URL after a short pause. */
function CommandSearch() {
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
        placeholder={t("scripts_search_placeholder")}
        aria-label={t("scripts_search_label")}
        size="sm"
        className="pl-8 font-mono"
      />
    </div>
  )
}

export function ScriptsPage() {
  const [viewRaw, setView] = useUrlParam("view")
  const view: View = viewRaw === "common" || viewRaw === "new" ? viewRaw : "recent"
  const [technique] = useUrlParam("technique")
  const [campaign] = useUrlParam("campaign_id")
  const [q] = useUrlParam("q")
  const [sensors] = useSensorFilter()
  const filters: ScriptFilters = {
    ...VIEWS[view],
    sensor: sensorParam(sensors),
    technique: technique ?? undefined,
    campaign_id: campaign ?? undefined,
    q: q ?? undefined,
  }

  const summary = useQuery({ queryKey: scriptKeys.summary, queryFn: scriptsApi.summary })
  const query = useInfiniteQuery({
    queryKey: scriptKeys.list(filters),
    queryFn: ({ pageParam }) => scriptsApi.list(filters, pageParam, PAGE_SIZE),
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
    estimateSize: () => 128,
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

  const filtered = Boolean(technique ?? campaign ?? q) || sensors.length > 0 || view === "new"

  return (
    <>
      <PageHeader
        help="scripts"
        title={t("scripts_page_title")}
        description={
          <span className="normal-nums">
            {summary.data ? describeScripts(summary.data) : t("scripts_page_description")}
          </span>
        }
      />

      <FilterBar
        className="mb-4"
        chips={[
          {
            param: "technique",
            label: t("scripts_filter_technique"),
            render: (v) => <span className="font-mono">{v}</span>,
          },
          {
            param: "campaign_id",
            label: t("scripts_filter_campaign"),
            render: (v) => <span>#{v}</span>,
          },
        ]}
        alsoClears={["q", "sensor", "view"]}
      >
        <SegmentedControl
          label={t("scripts_filter_which")}
          value={view}
          onChange={(v) => setView(v === "recent" ? null : v)}
          options={[
            { value: "recent", label: t("scripts_view_latest") },
            { value: "common", label: t("scripts_view_common") },
            { value: "new", label: t("scripts_row_new") },
          ]}
        />
        <SensorFilter />
        <CommandSearch />
      </FilterBar>

      <div className="overflow-clip rounded-lg border bg-surface shadow-sm">
        <div
          className={cn(
            "sticky top-14 z-10 hidden border-b bg-surface px-5 py-2.5 type-column text-fg-subtle md:grid",
            SCRIPT_GRID,
          )}
        >
          <span>{t("scripts_col_what")}</span>
          <span className="text-right">{t("campaign_meta_sessions")}</span>
          <span className="text-right">{t("campaign_meta_addresses")}</span>
          <span className="text-right">{t("campaign_meta_last_seen")}</span>
        </div>
        {query.isPending ? (
          <SkeletonList rows={6} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title={t("scripts_error_title")}
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
            icon={FileCode2}
            title={filtered ? t("scripts_empty_filtered_title") : t("scripts_empty_title")}
            description={filtered ? t("scripts_empty_filtered_hint") : t("scripts_empty_hint")}
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label={t("scripts_page_title")}
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
                  {row ? <ScriptRow item={row} /> : <SkeletonRow />}
                </div>
              )
            })}
          </div>
        )}
      </div>
      {query.isSuccess && rows.length > 0 && !hasNextPage ? (
        <p className="mt-4 text-center text-xs text-fg-subtle">
          {t("scripts_end_of_list", { count: rows.length })}
        </p>
      ) : null}
    </>
  )
}
