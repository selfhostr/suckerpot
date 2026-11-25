import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { ChevronDown, Download, SearchX, ShieldCheck, ShieldOff } from "lucide-react"
import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { useSearchParams } from "react-router"
import { useAuth } from "@/app/auth"
import { BLOCKLIST_GRID, BlocklistRow } from "@/components/defend/blocklist-row"
import { ExportPanel } from "@/components/defend/export-panel"
import { KindTiles } from "@/components/defend/kind-tiles"
import { OverrideDialog, type OverrideTarget } from "@/components/defend/override-dialog"
import {
  RemoveOverrideDialog,
  type RemovingOverride,
} from "@/components/defend/remove-override-dialog"
import { OverridesCard } from "@/components/defend/overrides-card"
import { UrlSearch } from "@/components/defend/url-search"
import { EmptyState } from "@/components/empty-state"
import { FilterBar } from "@/components/filter-bar"
import { StickyFilters } from "@/components/sticky-filters"
import { PageHeader } from "@/components/page-header"
import { ReadOnlyBadge } from "@/components/read-only-badge"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { NetworkFeedTab } from "@/components/defend/network-feed/network-feed-tab"
import { Switch } from "@/components/ui/switch"
import { useUrlParam } from "@/hooks/use-url-param"
import {
  blocklistSentence,
  DEFAULT_MIN_SCORE,
  defendApi,
  defendKeys,
  isBlockKind,
  KIND_META,
  parseMinScore,
  reasonLabel,
  SCORE_OPTIONS,
  type BlocklistFilters,
  type BlockEntry,
  type OverrideAction,
} from "@/lib/defend"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50

const TABS = [
  { id: "sensor", label: "This sensor" },
  { id: "network", label: "Network" },
] as const

/**
 * Two views of the blocklists: what this sensor saw, and the community lists built from the
 * network. The tab lives in the URL (`?tab=network`) and switching drops the other filters.
 */
export function BlocklistsPage() {
  const [params, setParams] = useSearchParams()
  const tab = params.get("tab") === "network" ? "network" : "sensor"
  const tabs = (
    <Tabs
      value={tab}
      onValueChange={(next) => setParams(next === "network" ? { tab: "network" } : {})}
      className="mt-2 mb-4"
    >
      <TabsList variant="line" aria-label="Blocklist views" className="justify-start">
        {TABS.map((t) => (
          <TabsTrigger key={t.id} value={t.id} className="flex-none px-3">
            {t.label}
          </TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  )
  if (tab === "network") {
    return (
      <>
        <PageHeader
          help="blocklists-network"
          title="Blocklists"
          description="Free community lists for your firewall, built only from what several independent sensors confirmed."
        />
        {tabs}
        <NetworkFeedTab />
      </>
    )
  }
  return <SensorBlocklists tabs={tabs} />
}

function SensorBlocklists({ tabs }: { tabs: React.ReactNode }) {
  const { canWrite } = useAuth()
  const [kindParam, setKindParam] = useUrlParam("kind")
  const [scoreParam, setScoreParam] = useUrlParam("min_score")
  const [q] = useUrlParam("q")
  const [reason, setReason] = useUrlParam("reason")
  const [benignParam, setBenignParam] = useUrlParam("include_benign")
  const kind = isBlockKind(kindParam) ? kindParam : null
  const minScore = parseMinScore(scoreParam)
  const includeBenign = benignParam === "1"
  const benignId = useId()

  const summary = useQuery({
    queryKey: defendKeys.summary,
    queryFn: defendApi.summary,
    staleTime: 30_000,
  })
  const overrides = useQuery({ queryKey: defendKeys.overrides, queryFn: defendApi.overrides })

  const filters: BlocklistFilters = useMemo(
    () => ({
      kind: kind ?? undefined,
      min_score: minScore,
      q: q ?? undefined,
      reason: reason ?? undefined,
      include_benign: includeBenign || undefined,
    }),
    [kind, minScore, q, reason, includeBenign],
  )
  const query = useInfiniteQuery({
    queryKey: defendKeys.blocklist(filters, PAGE_SIZE),
    queryFn: ({ pageParam }) => defendApi.blocklist(filters, pageParam, PAGE_SIZE),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const rows = query.data?.pages.flatMap((p) => p.items) ?? []

  const [toolsOpen, setToolsOpen] = useState(false)
  const [dialog, setDialog] = useState<{ target: OverrideTarget; action: OverrideAction } | null>(
    null,
  )
  const [removing, setRemoving] = useState<RemovingOverride | null>(null)
  const askRemoveOverride = (entry: BlockEntry) => {
    const found = overrides.data?.items.find(
      (o) => o.kind === entry.kind && o.value === entry.value,
    )
    if (found) setRemoving({ id: found.id, label: entry.value })
  }

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
    estimateSize: () => 92,
    overscan: 8,
    scrollMargin,
    getItemKey: (i) => {
      const r = rows[i]
      return r ? `${r.kind}:${r.value}` : `loader-${i}`
    },
  })
  const items = virtualizer.getVirtualItems()
  const lastIndex = items.at(-1)?.index ?? -1
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query
  useEffect(() => {
    if (lastIndex >= rows.length - 6 && hasNextPage && !isFetchingNextPage) void fetchNextPage()
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  const s = summary.data
  const off = s?.worker_enabled === false
  const nothingSeen = s?.kinds.every((k) => k.total === 0) === true
  const filtered = Boolean(kind ?? q ?? reason) || includeBenign || minScore !== DEFAULT_MIN_SCORE

  const header = (
    <PageHeader
      help="blocklists"
      title="Blocklists"
      description={
        off
          ? "Addresses, domains and files seen attacking you, scored and ready for your firewall."
          : blocklistSentence(s)
      }
      actions={
        <>
          <ReadOnlyBadge />
          {!off ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setToolsOpen(true)
                requestAnimationFrame(() =>
                  document.getElementById("export")?.scrollIntoView({ block: "start" }),
                )
              }}
            >
              <Download aria-hidden />
              Export
            </Button>
          ) : null}
        </>
      }
    />
  )

  if (off || nothingSeen) {
    return (
      <>
        {header}
        {tabs}
        <EmptyState
          icon={off ? ShieldOff : ShieldCheck}
          title={off ? "Blocklists are turned off" : "No entries scored yet"}
          description={
            off ? (
              <>
                <code className="font-mono text-fg">BLOCKLIST_ENABLED=false</code> is set in{" "}
                <code className="font-mono text-fg">.env</code>. Remove that line, or set it to{" "}
                <code className="font-mono text-fg">true</code>, and restart the stack. The scoring
                worker then reads what the decoys recorded and builds the lists.
              </>
            ) : (
              <>
                The worker scores what the decoys recorded about once an hour. Entries show up here
                as soon as attackers have earned a score. If it stays empty, check that{" "}
                <code className="font-mono text-fg">BLOCKLIST_ENABLED=false</code> is not set in{" "}
                <code className="font-mono text-fg">.env</code>.
              </>
            )
          }
        />
      </>
    )
  }

  return (
    <>
      {header}
      {tabs}

      <KindTiles summary={s} kind={kind} onSelect={(k) => setKindParam(k)} />

      {/* The export and your own rules fold away so the entries start near the top of the page;
          "Export" in the page header opens them. */}
      <div className="mt-4">
        <Button
          variant="outline"
          size="sm"
          aria-expanded={toolsOpen}
          aria-controls="blocklist-tools"
          onClick={() => setToolsOpen((v) => !v)}
        >
          <ChevronDown aria-hidden className={cn("transition-none", toolsOpen && "rotate-180")} />
          Export and your own rules
        </Button>
        {toolsOpen ? (
          <div
            id="blocklist-tools"
            className="mt-3 grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] lg:items-start"
          >
            <ExportPanel summary={s} initialKind={kind ?? "ip"} initialScore={minScore} />
            <OverridesCard canWrite={canWrite} />
          </div>
        ) : null}
      </div>

      <h2 className="mt-6 type-section-title text-fg">Entries</h2>

      <StickyFilters
        className="mt-3"
        filters={
          <FilterBar
            chips={[
              {
                param: "kind",
                label: "Type",
                render: (v) => (isBlockKind(v) ? KIND_META[v].label : v),
              },
              { param: "reason", label: "Reason", render: reasonLabel },
            ]}
            alsoClears={["min_score", "q", "include_benign"]}
          >
            <SegmentedControl
              label="Minimum score"
              value={String(minScore)}
              onChange={(v) => setScoreParam(Number(v) === DEFAULT_MIN_SCORE ? null : v)}
              options={SCORE_OPTIONS}
            />
            <UrlSearch label="Search the list" placeholder="Search a value" />
            <label
              htmlFor={benignId}
              className="inline-flex h-(--control-sm) items-center gap-2 rounded-md border bg-bg px-2.5 text-xs text-fg-muted"
            >
              <Switch
                id={benignId}
                size="sm"
                checked={includeBenign}
                onCheckedChange={(on) => setBenignParam(on ? "1" : null)}
              />
              Show research scanners
            </label>
          </FilterBar>
        }
      >
        {s && s.top_reasons.length > 0 && !reason ? (
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <span className="text-xs text-fg-muted">Common reasons</span>
            {s.top_reasons.map((r) => (
              <button
                key={r.reason}
                type="button"
                onClick={() => setReason(r.reason)}
                className="inline-flex h-(--chip) items-center gap-1.5 rounded-sm border border-border-strong px-2 text-xs font-medium text-fg-muted transition-colors hover:border-fg-subtle hover:text-fg"
              >
                {reasonLabel(r.reason)}
                <span className="text-fg-subtle">{formatNumber(r.count)}</span>
              </button>
            ))}
          </div>
        ) : null}

        <div className="overflow-clip rounded-lg border bg-surface shadow-sm">
          <div
            className={cn(
              "sticky top-[calc(3.5rem+var(--filters-h,0px))] z-10 hidden border-b bg-surface px-5 py-2.5 type-column text-fg-subtle",
              BLOCKLIST_GRID,
            )}
          >
            <span>Value</span>
            <span>Score</span>
            <span>Why it is listed</span>
            <span>Seen</span>
            <span className="sr-only">Actions</span>
          </div>
          {query.isPending ? (
            <SkeletonList rows={8} />
          ) : query.isError ? (
            <EmptyState
              variant="bare"
              icon={SearchX}
              title="Could not load the blocklist"
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
              icon={SearchX}
              title={filtered ? "Nothing matches" : "Nothing listed"}
              description={
                filtered
                  ? "Lower the minimum score, or clear a filter to see more."
                  : "No entry has reached this score yet."
              }
            />
          ) : (
            <div
              ref={listRef}
              role="list"
              aria-label="Blocklist entries"
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
                      <BlocklistRow
                        entry={row}
                        canWrite={canWrite}
                        onOverride={(entry, action) =>
                          setDialog({ target: { kind: entry.kind, value: entry.value }, action })
                        }
                        onRemoveOverride={askRemoveOverride}
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
      </StickyFilters>
      {query.isSuccess && rows.length > 0 && !hasNextPage ? (
        <p className="mt-4 text-center text-xs text-fg-subtle">
          End of the list · {formatNumber(rows.length)} {rows.length === 1 ? "entry" : "entries"}
        </p>
      ) : null}
      {s && s.demo_entries > 0 ? (
        <p className="mt-3 text-center text-xs text-fg-subtle">
          {formatNumber(s.demo_entries)} entries are demo data. They are shown here and never
          exported.
        </p>
      ) : null}

      {canWrite ? (
        <RemoveOverrideDialog target={removing} onClose={() => setRemoving(null)} />
      ) : null}
      {dialog ? (
        <OverrideDialog
          open
          onOpenChange={(open) => {
            if (!open) setDialog(null)
          }}
          target={dialog.target}
          action={dialog.action}
        />
      ) : null}
    </>
  )
}
