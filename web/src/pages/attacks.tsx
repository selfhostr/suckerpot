import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { Crosshair, SearchX } from "lucide-react"
import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { useSearchParams } from "react-router"
import { EmptyState } from "@/components/empty-state"
import { AttacksFilterBar } from "@/components/attacks-filter-bar"
import { NewRowsPill } from "@/components/new-rows-pill"
import { PageHeader } from "@/components/page-header"
import { StickyFilters } from "@/components/sticky-filters"
import { SESSION_COLUMNS_GRID, SessionRow } from "@/components/session-row"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { t } from "@/i18n"
import { useNewSessions } from "@/hooks/use-new-sessions"
import { api, queryKeys, type SessionFilters } from "@/lib/api"
import { useIpMask } from "@/app/ip-mask"
import {
  FLOOD_PARAM,
  floodHeadline,
  floodViewFromParam,
  totalConnections,
  type FloodView,
} from "@/lib/floods"
import { maskIp } from "@/lib/format"
import { clearParams, parseSessionFilters, SESSION_PARAMS } from "@/lib/list-filters"
import { SENSOR_META, sensorSetPhrase } from "@/lib/sensors"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50

function useFilters(): SessionFilters {
  const [params] = useSearchParams()
  return parseSessionFilters(params)
}

function useHeadline(
  filters: SessionFilters,
  floods: FloodView,
  loaded: number,
  complete: boolean,
) {
  const { masked } = useIpMask()
  const ip = filters.src_ip && masked ? maskIp(filters.src_ip) : filters.src_ip
  const summary = useQuery({ queryKey: queryKeys.summary, queryFn: api.summary })
  const s = summary.data
  if (filters.src_ip && !filters.username && !filters.command && !filters.url) {
    return complete
      ? t("attacks_headline_from_ip_done", { count: loaded, ip })
      : t("attacks_headline_from_ip", { ip })
  }
  if (
    filters.src_ip ??
    filters.username ??
    filters.command ??
    filters.url ??
    filters.tag ??
    filters.stage ??
    filters.since ??
    filters.until ??
    filters.country ??
    filters.asn ??
    filters.technique ??
    filters.campaign_id
  ) {
    return complete
      ? t("attacks_headline_matching_done", { count: loaded })
      : t("attacks_headline_matching")
  }
  if (!s) return t("attacks_headline_all")
  if (filters.sensor?.length && floods !== "all") {
    return floods === "only"
      ? t("attacks_headline_floods_only")
      : t("attacks_headline_floods_hidden")
  }
  if (!filters.sensor?.length) {
    const sentence = floodHeadline(floods, s)
    if (sentence) return sentence
  }
  if (filters.sensor?.length) {
    const n = filters.sensor.reduce((sum, x) => sum + (s.by_sensor[x]?.sessions ?? 0), 0)
    const [only] = filters.sensor
    return filters.sensor.length === 1 && only
      ? t("attacks_headline_sensor", {
          count: n,
          sensor: SENSOR_META[only].label,
          hours: s.window_hours,
        })
      : t("attacks_headline_sensors", {
          count: n,
          sensors: sensorSetPhrase(filters.sensor),
          hours: s.window_hours,
        })
  }
  return t("attacks_headline_total", {
    sessions: s.sessions,
    ips: s.unique_ips,
    hours: s.window_hours,
  })
}

export function AttacksPage() {
  const filters = useFilters()
  const [params, setParams] = useSearchParams()

  const query = useInfiniteQuery({
    queryKey: queryKeys.sessions(filters),
    queryFn: ({ pageParam }) => api.sessions(filters, pageParam, PAGE_SIZE),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })

  const rows = query.data?.pages.flatMap((p) => p.items) ?? []
  // A flood group is one row for many connections: sentences count connections, not rows.
  const connections = totalConnections(rows)
  const headline = useHeadline(
    filters,
    floodViewFromParam(params.get(FLOOD_PARAM)),
    connections,
    query.isSuccess && !query.hasNextPage,
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

  const count = rows.length + (query.hasNextPage ? 1 : 0)
  const virtualizer = useWindowVirtualizer({
    count,
    estimateSize: () => 53,
    overscan: 12,
    scrollMargin,
    getItemKey: (i) => rows[i]?.session_id ?? `loader-${i}`,
  })
  const items = virtualizer.getVirtualItems()
  const lastIndex = items.at(-1)?.index ?? -1

  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query
  // New sessions slide in at the top, or wait behind a pill once the reader has scrolled down.
  const arrivals = useNewSessions({
    filters,
    rows,
    ready: query.isSuccess,
    listTop: scrollMargin,
  })
  useEffect(() => {
    if (lastIndex >= rows.length - 10 && hasNextPage && !isFetchingNextPage) {
      void fetchNextPage()
    }
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  return (
    <>
      <PageHeader help="attacks" title={t("attacks_title")} description={headline} />

      <StickyFilters filters={<AttacksFilterBar group="sessions" />}>
        <NewRowsPill count={arrivals.pending} more={arrivals.more} onShow={arrivals.show} />
        <div className="overflow-clip rounded-lg border bg-surface shadow-sm">
          <div
            className={cn(
              "sticky top-[calc(3.5rem+var(--filters-h,0px))] z-10 hidden border-b bg-surface px-5 py-2.5 type-column text-fg-subtle md:grid",
              SESSION_COLUMNS_GRID,
            )}
          >
            <span>{t("sessions_col_sensor")}</span>
            <span>{t("sessions_col_source")}</span>
            <span>{t("sessions_col_what")}</span>
            <span className="text-right">{t("sessions_col_tags")}</span>
            <span className="text-right">{t("sessions_col_started")}</span>
          </div>

          {query.isPending ? (
            <SkeletonList rows={10} />
          ) : query.isError ? (
            <EmptyState
              variant="bare"
              icon={SearchX}
              title={t("attacks_error_title")}
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
              icon={Crosshair}
              title={t("attacks_empty_title")}
              description={t("attacks_empty_description")}
              action={
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setParams((p) => clearParams(p, SESSION_PARAMS))}
                >
                  {t("filters_clear_all")}
                </Button>
              }
            />
          ) : (
            <div
              ref={listRef}
              role="list"
              aria-label={t("sessions_list_label")}
              aria-busy={isFetchingNextPage}
              data-arriving={arrivals.gliding ? "" : undefined}
              className="relative w-full"
              style={{ height: virtualizer.getTotalSize() }}
            >
              {items.map((item) => {
                const session = rows[item.index]
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
                    {session ? (
                      <SessionRow
                        session={session}
                        layout="columns"
                        className={
                          arrivals.arriving.has(session.session_id) ? "animate-slide-in" : undefined
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
            {t("attacks_end_of_list", {
              sessions: connections,
              inRows: connections === rows.length ? 0 : rows.length,
            })}
          </p>
        ) : null}
      </StickyFilters>
    </>
  )
}
