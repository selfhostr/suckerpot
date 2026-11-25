import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { Search, SearchX, ShieldAlert } from "lucide-react"
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react"
import { Link } from "react-router"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { CveDrawer } from "@/components/cves/cve-drawer"
import { CVE_GRID, CveRow } from "@/components/cves/cve-row"
import { EmptyState } from "@/components/empty-state"
import { FilterBar } from "@/components/filter-bar"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { RelativeTime } from "@/components/relative-time"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useUrlParam } from "@/hooks/use-url-param"
import { api, queryKeys } from "@/lib/api"
import {
  describeCves,
  describeSource,
  SEVERITY_FILTERS,
  SINCE_OPTIONS,
  SOURCE_LABELS,
  sinceParam,
  type CveFilters,
} from "@/lib/cves"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 25
const DEFAULT_SINCE = "30"

function CveSearch() {
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
    <div className="relative w-full sm:w-60">
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
        maxLength={100}
        placeholder="Search, e.g. redis or CVE-2026"
        aria-label="Search CVEs"
        className="h-8 pl-8 text-xs normal-nums md:text-xs"
      />
    </div>
  )
}

function SyncCard() {
  const q = useQuery({ queryKey: queryKeys.cveSync, queryFn: api.cveSync, staleTime: 60_000 })
  const s = q.data
  const newest = s?.sources
    .map((x) => x.last_success_at)
    .filter((x): x is string => x !== null)
    .sort()
    .at(-1)
  return (
    <FindingCard
      className="mt-6"
      eyebrow="Feed status"
      finding={
        !s ? (
          "Checking the CVE feeds…"
        ) : newest ? (
          <>
            {formatNumber(s.total)} CVEs tracked, {formatNumber(s.relevant)} relevant to our
            services. Last updated <RelativeTime iso={newest} className="text-base text-fg" />.
          </>
        ) : (
          "The CVE feeds have not run yet. They update once a day."
        )
      }
      detail="Public data from CISA, the NVD and GitHub, fetched once a day by the ingest service within fixed quotas. Nothing is deployed from it."
    >
      {s ? (
        <ul aria-label="Feed sources" className="divide-y">
          {s.sources.map((src) => (
            <li
              key={src.source}
              className="grid grid-cols-1 items-baseline gap-x-4 gap-y-1 py-2.5 first:pt-0 last:pb-0 sm:grid-cols-[10rem_minmax(0,1fr)_auto]"
            >
              <span className="text-sm font-medium text-fg">{SOURCE_LABELS[src.source]}</span>
              <span className="text-xs text-fg-muted">{describeSource(src)}</span>
              <span className="text-xs text-fg-subtle sm:text-right">
                {src.last_success_at ? (
                  <>
                    Updated <RelativeTime iso={src.last_success_at} className="text-xs" />
                  </>
                ) : (
                  "Never updated"
                )}
                {src.source !== "kev" ? (
                  <>
                    {" · "}
                    {(src.source === "nvd" ? s.nvd_key_configured : s.github_key_configured)
                      ? "API key set"
                      : "No API key (lower rate limit)"}
                  </>
                ) : null}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
      <p className="mt-3 text-xs text-fg-muted">
        NVD and GitHub keys are optional. Add them in{" "}
        <Link to="/settings" className="text-fg underline underline-offset-4">
          Settings
        </Link>{" "}
        for higher rate limits.
      </p>
    </FindingCard>
  )
}

export function CvesPage() {
  const [relevanceParam, setRelevance] = useUrlParam("relevance")
  const [severity, setSeverity] = useUrlParam("severity")
  const [sinceDays, setSinceDays] = useUrlParam("since")
  const [kev, setKev] = useUrlParam("kev")
  const [q] = useUrlParam("q")
  const [openId, setOpenId] = useUrlParam("cve")

  const relevance = relevanceParam === "all" ? "all" : "relevant"
  const days = sinceDays ?? DEFAULT_SINCE
  const since = sinceParam(days)
  const filters: CveFilters = useMemo(
    () => ({
      relevance: relevance === "all" ? undefined : "relevant",
      severity: severity ?? undefined,
      kev: kev === "1" ? "true" : undefined,
      since,
      q: q ?? undefined,
    }),
    [relevance, severity, kev, since, q],
  )

  const query = useInfiniteQuery({
    queryKey: queryKeys.cves(filters, PAGE_SIZE),
    queryFn: ({ pageParam }) => api.cves(filters, pageParam, PAGE_SIZE),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const rows = query.data?.pages.flatMap((p) => p.items) ?? []
  const total = query.data?.pages[0]?.total ?? 0

  // The headline sentence is about this week and our services, whatever the filters say.
  const weekFilters: CveFilters = { relevance: "relevant", since: sinceParam("7") }
  const week = useQuery({
    queryKey: queryKeys.cves(weekFilters, 100),
    queryFn: () => api.cves(weekFilters, null, 100),
  })
  const finding = week.data
    ? describeCves({
        critical: week.data.items.filter((c) => c.cvss_severity === "CRITICAL").length,
        relevant: week.data.total,
        kevRelevant: week.data.items.filter((c) => c.in_kev).length,
        seen: week.data.items.filter((c) => c.seen_sessions > 0).length,
      })
    : "Recent vulnerabilities, ranked by how much they matter to the services we emulate."

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
    estimateSize: () => 96,
    overscan: 8,
    scrollMargin,
    getItemKey: (i) => rows[i]?.cve_id ?? `loader-${i}`,
  })
  const items = virtualizer.getVirtualItems()
  const lastIndex = items.at(-1)?.index ?? -1
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query
  useEffect(() => {
    if (lastIndex >= rows.length - 6 && hasNextPage && !isFetchingNextPage) void fetchNextPage()
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  const filtered = Boolean(severity ?? kev ?? q ?? sinceDays) || relevance === "all"

  return (
    <>
      <PageHeader help="cves" title="CVE watch" description={finding} />

      <FilterBar
        className="mb-4"
        chips={[]}
        alsoClears={["relevance", "severity", "since", "kev", "q"]}
      >
        <SegmentedControl
          label="Relevance"
          value={relevance}
          onChange={(v) => setRelevance(v === "all" ? "all" : null)}
          options={[
            { value: "relevant", label: "Our services" },
            { value: "all", label: "All CVEs" },
          ]}
        />
        <SegmentedControl
          label="Severity"
          value={severity ?? "any"}
          onChange={(v) => setSeverity(v === "any" ? null : v)}
          options={[
            { value: "any", label: "Any severity" },
            ...SEVERITY_FILTERS.map((s) => ({
              value: s,
              label: s.charAt(0).toUpperCase() + s.slice(1),
            })),
          ]}
        />
        <SegmentedControl
          label="Published"
          value={days}
          onChange={(v) => setSinceDays(v === DEFAULT_SINCE ? null : v)}
          options={SINCE_OPTIONS.map((o) => ({ value: o.value, label: o.label }))}
        />
        <SegmentedControl
          label="Exploited in the wild"
          value={kev === "1" ? "kev" : "any"}
          onChange={(v) => setKev(v === "kev" ? "1" : null)}
          options={[
            { value: "any", label: "Any" },
            { value: "kev", label: "KEV only" },
          ]}
        />
        <CveSearch />
      </FilterBar>

      <div className="overflow-clip rounded-lg border bg-surface shadow-sm">
        <div
          className={cn(
            "sticky top-14 z-10 hidden border-b bg-surface px-5 py-2.5 text-2xs font-medium tracking-wide text-fg-subtle uppercase md:grid",
            CVE_GRID,
          )}
        >
          <span>Vulnerability</span>
          <span>Severity</span>
          <span>Relevance</span>
          <span className="text-right">Seen in traffic</span>
        </div>
        {query.isPending ? (
          <SkeletonList rows={8} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title="Could not load CVEs"
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
            icon={ShieldAlert}
            title={filtered ? "No CVEs match" : "No CVEs yet"}
            description={
              filtered
                ? "Try another period or severity, or show all CVEs."
                : "The feeds update once a day. New vulnerabilities appear here after the first run."
            }
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label="CVEs"
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
                  {row ? <CveRow item={row} onOpen={setOpenId} /> : <SkeletonRow />}
                </div>
              )
            })}
          </div>
        )}
      </div>
      {query.isSuccess && rows.length > 0 && !hasNextPage ? (
        <p className="mt-4 text-center text-xs text-fg-subtle">
          End of the list · {formatNumber(total)} CVEs
        </p>
      ) : null}

      <SyncCard />
      <CveDrawer id={openId} onClose={() => setOpenId(null)} />
    </>
  )
}
