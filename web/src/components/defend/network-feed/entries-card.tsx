import { useInfiniteQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { SearchX } from "lucide-react"
import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react"
import { t } from "@/i18n"
import { UrlSearch } from "@/components/defend/url-search"
import { EmptyState } from "@/components/empty-state"
import { FilterBar } from "@/components/filter-bar"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { useUrlParam } from "@/hooks/use-url-param"
import {
  entriesFinding,
  FEED_LIST_IDS,
  feedApi,
  feedKeys,
  LIST_META,
  type FeedFilters,
  type FeedListId,
} from "@/lib/network-feed"
import { cn } from "@/lib/utils"
import { EntryRow, FEED_GRID } from "./entry-row"

const PAGE_SIZE = 50

const isListId = (v: string | null): v is FeedListId =>
  v !== null && (FEED_LIST_IDS as readonly string[]).includes(v)

const LIST_OPTIONS = [
  {
    value: "all",
    get label() {
      return t("common_all")
    },
  },
  {
    value: "outbound",
    get label() {
      return t("nfeed_list_outbound")
    },
  },
  {
    value: "inbound",
    get label() {
      return t("nfeed_list_inbound")
    },
  },
  {
    value: "outbound-domains",
    get label() {
      return t("nfeed_list_domains")
    },
  },
] as const

const TIER_OPTIONS = [
  {
    value: "all",
    get label() {
      return t("nfeed_tier_all")
    },
  },
  {
    value: "high",
    get label() {
      return t("nfeed_tier_high")
    },
  },
] as const

/** The entries of the lists: filters in the URL (`list`, `tier`, `seen_here`, `q`), loaded by page. */
export function EntriesCard() {
  const [listParam, setListParam] = useUrlParam("list")
  const [tierParam, setTierParam] = useUrlParam("tier")
  const [seenParam, setSeenParam] = useUrlParam("seen_here")
  const [q] = useUrlParam("q")
  const seenId = useId()
  const list = isListId(listParam) ? listParam : undefined
  const tier = tierParam === "high" ? "high" : undefined
  const seenHere = seenParam === "1"
  const filters: FeedFilters = useMemo(
    () => ({ list, tier, q: q ?? undefined, seen_here: seenHere || undefined }),
    [list, tier, q, seenHere],
  )

  const query = useInfiniteQuery({
    queryKey: feedKeys.entries(filters),
    queryFn: ({ pageParam }) => feedApi.entries(filters, pageParam, PAGE_SIZE),
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

  const virtualizer = useWindowVirtualizer({
    count: rows.length + (query.hasNextPage ? 1 : 0),
    estimateSize: () => 96,
    overscan: 8,
    scrollMargin,
    getItemKey: (i) => {
      const r = rows[i]
      return r ? `${r.list}:${r.value}` : `loader-${i}`
    },
  })
  const items = virtualizer.getVirtualItems()
  const lastIndex = items.at(-1)?.index ?? -1
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query
  useEffect(() => {
    if (lastIndex >= rows.length - 6 && hasNextPage && !isFetchingNextPage) void fetchNextPage()
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  const filtered = Boolean(list ?? tier ?? q) || seenHere

  return (
    <section aria-labelledby="feed-entries-title">
      <h2 id="feed-entries-title" className="type-section-title text-fg">
        {t("blocklists_entries")}
      </h2>
      <p className="mt-1.5 max-w-2xl type-lede text-fg-muted">{entriesFinding(filters)}</p>

      <FilterBar
        className="mt-4 mb-4"
        chips={[
          {
            param: "list",
            label: t("nfeed_filter_list"),
            render: (v) => (isListId(v) ? LIST_META[v].title : v),
          },
          {
            param: "tier",
            label: t("nfeed_filter_tier"),
            render: (v) => (v === "high" ? t("nfeed_tier_high") : v),
          },
        ]}
        alsoClears={["q", "seen_here"]}
      >
        <SegmentedControl
          label={t("nfeed_filter_list")}
          value={list ?? "all"}
          onChange={(v) => setListParam(v === "all" ? null : v)}
          options={LIST_OPTIONS}
        />
        <SegmentedControl
          label={t("nfeed_filter_tier")}
          value={tier ?? "all"}
          onChange={(v) => setTierParam(v === "all" ? null : v)}
          options={TIER_OPTIONS}
        />
        <UrlSearch
          label={t("nfeed_search_label")}
          placeholder={t("blocklists_search_placeholder")}
        />
        <label
          htmlFor={seenId}
          className="inline-flex h-(--control-sm) items-center gap-2 rounded-md border bg-bg px-2.5 text-xs text-fg-muted"
        >
          <Switch
            id={seenId}
            size="sm"
            checked={seenHere}
            onCheckedChange={(on) => setSeenParam(on ? "1" : null)}
          />
          {t("nfeed_only_seen")}
        </label>
      </FilterBar>

      <div className="overflow-clip rounded-lg border bg-surface shadow-sm">
        <div
          className={cn(
            "sticky top-14 z-10 hidden border-b bg-surface px-5 py-2.5 type-column text-fg-subtle",
            FEED_GRID,
          )}
        >
          <span>{t("blocklists_col_value")}</span>
          <span>{t("nfeed_col_what")}</span>
          <span>{t("nfeed_col_dates")}</span>
          <span className="sr-only">{t("nfeed_col_badges")}</span>
        </div>
        {query.isPending ? (
          <SkeletonList rows={6} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title={t("nfeed_load_error")}
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
            icon={SearchX}
            title={filtered ? t("blocklists_no_match") : t("nfeed_no_entries")}
            description={filtered ? t("nfeed_no_match_hint") : t("nfeed_no_entries_hint")}
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label={t("nfeed_entries_list")}
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
                  {row ? <EntryRow entry={row} /> : <SkeletonRow />}
                </div>
              )
            })}
          </div>
        )}
      </div>
      {query.isSuccess && rows.length > 0 && !hasNextPage ? (
        <p className="mt-4 text-center text-xs text-fg-subtle">
          {t("blocklists_end", { count: rows.length })}
        </p>
      ) : null}
    </section>
  )
}
