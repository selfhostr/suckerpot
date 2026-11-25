import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { ArrowRight, FileSearch, Info, Search, SearchX } from "lucide-react"
import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { EmptyState } from "@/components/empty-state"
import { FilterBar } from "@/components/filter-bar"
import { FindingCard } from "@/components/finding-card"
import { BundleCard, BundleToggle } from "@/components/samples/bundle"
import { SampleRow, SAMPLE_GRID, SAMPLE_GRID_ACTION } from "@/components/samples/sample-row"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useUrlParam } from "@/hooks/use-url-param"
import { t } from "@/i18n"
import {
  describeCollector,
  describeSamples,
  sampleKeys,
  samplesApi,
  type SampleFilters,
} from "@/lib/samples"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50
const KINDS = ["ELF", "Script", "PE"] as const

function kindLabel(k: (typeof KINDS)[number]): string {
  return k === "Script" ? t("samples_kind_script") : k
}

function HashSearch() {
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
        maxLength={200}
        placeholder={t("samples_search_placeholder")}
        aria-label={t("samples_search_label")}
        size="sm"
        className="pl-8 font-mono"
      />
    </div>
  )
}

/** The Files page: files the collector fetched and analysed. */
export function SamplesTab() {
  const { canWrite } = useAuth()
  const [kind, setKind] = useUrlParam("kind")
  const [q] = useUrlParam("q")
  const [arch] = useUrlParam("arch")
  const [family] = useUrlParam("family")
  const [yara] = useUrlParam("yara")
  const filters: SampleFilters = {
    kind: kind ?? undefined,
    q: q ?? undefined,
    arch: arch ?? undefined,
    family: family ?? undefined,
    yara: yara ?? undefined,
  }
  const query = useInfiniteQuery({
    queryKey: sampleKeys.list(filters),
    queryFn: ({ pageParam }) => samplesApi.list(filters, pageParam, PAGE_SIZE),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const rows = query.data?.pages.flatMap((p) => p.items) ?? []
  const filtered = Boolean(kind ?? q ?? arch ?? family ?? yara)
  // With nothing collected, say why: the collector is off, paused or still working.
  const none = query.isSuccess && rows.length === 0 && !filtered
  const egress = useQuery({
    queryKey: sampleKeys.egress,
    queryFn: samplesApi.egress,
    enabled: none,
  })
  const collector = describeCollector(egress.data)

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
    estimateSize: () => 76,
    overscan: 10,
    scrollMargin,
    getItemKey: (i) => rows[i]?.sha256 ?? `loader-${i}`,
  })
  const items = virtualizer.getVirtualItems()
  const lastIndex = items.at(-1)?.index ?? -1
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query
  useEffect(() => {
    if (lastIndex >= rows.length - 10 && hasNextPage && !isFetchingNextPage) void fetchNextPage()
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  return (
    <>
      {none ? (
        <FindingCard
          className="mb-4"
          eyebrow={t("samples_collector_eyebrow")}
          finding={egress.isPending ? t("samples_collector_checking") : collector.finding}
          detail={
            <span className="inline-flex items-start gap-2">
              <Info aria-hidden className="mt-0.5 size-4 shrink-0" />
              <span>
                {collector.detail}{" "}
                <Link
                  to="/settings"
                  className="inline-flex items-center gap-1 font-medium text-fg underline-offset-4 hover:underline"
                >
                  {t("samples_collector_settings_link")}
                  <ArrowRight aria-hidden className="size-3.5" />
                </Link>
              </span>
            </span>
          }
        />
      ) : (
        <FindingCard
          className="mb-4"
          eyebrow={t("samples_files_eyebrow")}
          finding={
            query.isPending
              ? t("samples_files_counting")
              : filtered && rows.length === 0
                ? t("samples_files_no_match")
                : describeSamples(rows, query.hasNextPage)
          }
          detail={t("samples_files_detail")}
        />
      )}

      {canWrite ? <BundleCard className="mb-4" /> : null}

      <FilterBar
        className="mb-4"
        chips={[
          { param: "arch", label: t("samples_filter_arch") },
          { param: "family", label: t("samples_filter_family") },
          {
            param: "yara",
            label: t("samples_filter_rule"),
            render: (v) => <span className="font-mono">{v}</span>,
          },
        ]}
        alsoClears={["kind", "q"]}
      >
        <SegmentedControl
          label={t("samples_filter_kind")}
          value={kind ?? "all"}
          onChange={(v) => setKind(v === "all" ? null : v)}
          options={[
            { value: "all", label: t("samples_filter_all_kinds") },
            ...KINDS.map((k) => ({ value: k, label: kindLabel(k) })),
          ]}
        />
        <HashSearch />
      </FilterBar>

      <div className="overflow-clip rounded-lg border bg-surface shadow-sm">
        <div
          className={cn(
            "sticky top-14 z-10 hidden border-b bg-surface px-5 py-2.5 type-column text-fg-subtle md:grid",
            canWrite ? SAMPLE_GRID_ACTION : SAMPLE_GRID,
          )}
        >
          <span>{t("samples_col_family_kind")}</span>
          <span className="text-right">{t("samples_col_size")}</span>
          <span className="text-right">{t("samples_col_urls")}</span>
          <span className="text-right">{t("samples_col_sessions")}</span>
          <span className="text-right">{t("samples_col_last_seen")}</span>
          {canWrite ? <span className="sr-only">{t("samples_col_bundle")}</span> : null}
        </div>
        {query.isPending ? (
          <SkeletonList rows={8} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title={t("samples_error_title")}
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
            icon={FileSearch}
            title={filtered ? t("samples_empty_filtered_title") : t("samples_summary_empty")}
            description={filtered ? t("samples_empty_filtered_hint") : t("samples_empty_hint")}
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label={t("samples_list_label")}
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
                  {row ? (
                    <SampleRow
                      item={row}
                      action={
                        !canWrite ? undefined : row.stored ? (
                          <BundleToggle sha256={row.sha256} compact />
                        ) : (
                          <span aria-hidden />
                        )
                      }
                    />
                  ) : (
                    <SkeletonRow />
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
      {query.isSuccess && rows.length > 0 && !hasNextPage ? (
        <p className="mt-4 text-center text-xs text-fg-subtle">
          {t("samples_end_of_list", { count: rows.length })}
        </p>
      ) : null}
    </>
  )
}
