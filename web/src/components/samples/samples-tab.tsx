import { useInfiniteQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { FileSearch, Search, SearchX } from "lucide-react"
import { useEffect, useLayoutEffect, useRef, useState } from "react"
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
import { formatNumber } from "@/lib/format"
import { describeSamples, sampleKeys, samplesApi, type SampleFilters } from "@/lib/samples"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50
const KINDS = ["ELF", "Script", "PE"] as const

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
        placeholder="Hash start or URL part"
        aria-label="Search samples by hash or URL"
        size="sm"
        className="pl-8 font-mono"
      />
    </div>
  )
}

/** The Samples tab of the Malware page: files the collector fetched and analysed. */
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
      <FindingCard
        className="mb-4"
        eyebrow="Collected files"
        finding={
          query.isPending
            ? "Counting the collected files…"
            : filtered && rows.length === 0
              ? "No sample matches these filters."
              : describeSamples(rows, query.hasNextPage)
        }
        detail="Files are fetched by the collector, stored under their hash and only ever read, never run."
      />

      {canWrite ? <BundleCard className="mb-4" /> : null}

      <FilterBar
        className="mb-4"
        chips={[
          { param: "arch", label: "Architecture" },
          { param: "family", label: "Family" },
          { param: "yara", label: "Rule", render: (v) => <span className="font-mono">{v}</span> },
        ]}
        alsoClears={["kind", "q"]}
      >
        <SegmentedControl
          label="File kind"
          value={kind ?? "all"}
          onChange={(v) => setKind(v === "all" ? null : v)}
          options={[
            { value: "all", label: "All kinds" },
            ...KINDS.map((k) => ({ value: k, label: k })),
          ]}
        />
        <HashSearch />
      </FilterBar>

      <div className="overflow-hidden rounded-lg border bg-surface shadow-sm">
        <div
          className={cn(
            "hidden border-b px-5 py-2.5 type-column text-fg-subtle md:grid",
            canWrite ? SAMPLE_GRID_ACTION : SAMPLE_GRID,
          )}
        >
          <span>Family and kind</span>
          <span className="text-right">Size</span>
          <span className="text-right">URLs</span>
          <span className="text-right">Sessions</span>
          <span className="text-right">Last seen</span>
          {canWrite ? <span className="sr-only">Bundle</span> : null}
        </div>
        {query.isPending ? (
          <SkeletonList rows={8} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title="Could not load the samples"
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
            icon={FileSearch}
            title={filtered ? "No samples match" : "No samples collected yet"}
            description={
              filtered
                ? "Try another kind or a shorter search, or clear the filters."
                : "When the collector fetches a file from a download URL, it appears here with its analysis."
            }
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label="Samples"
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
          End of the list · {formatNumber(rows.length)} samples
        </p>
      ) : null}
    </>
  )
}
