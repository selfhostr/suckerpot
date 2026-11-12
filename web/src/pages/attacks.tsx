import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { useWindowVirtualizer } from "@tanstack/react-virtual"
import { Crosshair, SearchX } from "lucide-react"
import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { useSearchParams } from "react-router"
import { CampaignName } from "@/components/campaigns/campaign-name"
import { CountryFlag } from "@/components/country-flag"
import { EmptyState } from "@/components/empty-state"
import { FilterBar, SensorFilter } from "@/components/filter-bar"
import { FloodFilter } from "@/components/flood-filter"
import { PageHeader } from "@/components/page-header"
import { SessionRow } from "@/components/session-row"
import { SkeletonList, SkeletonRow } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { api, queryKeys, type SessionFilters } from "@/lib/api"
import { useIpMask } from "@/app/ip-mask"
import {
  FLOOD_PARAM,
  floodHeadline,
  floodKindFor,
  floodViewFromParam,
  totalConnections,
  type FloodView,
} from "@/lib/floods"
import { formatNumber, maskIp, plural } from "@/lib/format"
import { STAGE_META, parseInstant, parseStage, windowLabel } from "@/lib/story"
import { SENSOR_META, parseSensors, sensorSetPhrase } from "@/lib/sensors"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50

function useFilters(): SessionFilters {
  const [params] = useSearchParams()
  const sensor = parseSensors(params.get("sensor"))
  const tag = params.get("tag")
  const country = params.get("country")
  const asn = params.get("asn")
  const technique = params.get("technique")
  const campaign = params.get("campaign_id")
  const kind = floodKindFor(floodViewFromParam(params.get(FLOOD_PARAM)))
  return {
    sensor: sensor.length ? sensor : undefined,
    src_ip: params.get("src_ip") ?? undefined,
    // Same shapes the API accepts; anything else is ignored instead of failing with a 422.
    tag: /^[a-z0-9-]{1,32}$/.test(tag ?? "") ? (tag ?? undefined) : undefined,
    country: /^[A-Za-z]{2}$/.test(country ?? "") ? country?.toUpperCase() : undefined,
    asn: /^\d{1,10}$/.test(asn ?? "") ? (asn ?? undefined) : undefined,
    technique: /^T\d{4}(\.\d{3})?$/.test(technique ?? "") ? (technique ?? undefined) : undefined,
    campaign_id: /^\d{1,15}$/.test(campaign ?? "") ? (campaign ?? undefined) : undefined,
    stage: parseStage(params.get("stage")),
    since: parseInstant(params.get("since")),
    until: parseInstant(params.get("until")),
    kind,
  }
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
  if (filters.src_ip) {
    return complete
      ? `${formatNumber(loaded)} ${loaded === 1 ? "session" : "sessions"} from ${ip}.`
      : `Every session from ${ip}, newest first.`
  }
  if (
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
      ? `${formatNumber(loaded)} matching ${loaded === 1 ? "session" : "sessions"}, newest first.`
      : "Matching sessions, newest first."
  }
  if (!s) return "Every session the sensors recorded, newest first."
  if (filters.sensor?.length && floods !== "all") {
    return floods === "only"
      ? "Flood groups on the chosen sensors, newest first."
      : "Sessions on the chosen sensors, without the floods, newest first."
  }
  if (!filters.sensor?.length) {
    const sentence = floodHeadline(floods, s)
    if (sentence) return sentence
  }
  if (filters.sensor?.length) {
    const n = filters.sensor.reduce((sum, x) => sum + (s.by_sensor[x]?.sessions ?? 0), 0)
    const sessions = n === 1 ? "session" : "sessions"
    const [only] = filters.sensor
    return filters.sensor.length === 1 && only
      ? `${formatNumber(n)} ${SENSOR_META[only].label} ${sessions} in the last ${s.window_hours} hours.`
      : `${formatNumber(n)} ${sessions} on ${sensorSetPhrase(filters.sensor)} in the last ${s.window_hours} hours.`
  }
  return `${formatNumber(s.sessions)} sessions from ${formatNumber(s.unique_ips)} addresses in the last ${s.window_hours} hours.`
}

export function AttacksPage() {
  const { masked } = useIpMask()
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
  useEffect(() => {
    if (lastIndex >= rows.length - 10 && hasNextPage && !isFetchingNextPage) {
      void fetchNextPage()
    }
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  return (
    <>
      <PageHeader help="attacks" title="Attacks" description={headline} />

      <FilterBar
        className="mb-4"
        alsoClears={["sensor", FLOOD_PARAM]}
        chips={[
          {
            param: "src_ip",
            label: "IP",
            render: (v) => <span className="font-mono">{masked ? maskIp(v) : v}</span>,
          },
          {
            param: "since",
            label: "Period",
            alsoRemove: ["until"],
            render: (v) => (
              <span>{windowLabel(parseInstant(v), parseInstant(params.get("until")))}</span>
            ),
          },
          ...(params.get("since")
            ? []
            : [
                {
                  param: "until",
                  label: "Period",
                  render: (v: string) => <span>{windowLabel(undefined, parseInstant(v))}</span>,
                },
              ]),
          {
            param: "stage",
            label: "How far",
            render: (v) => {
              const stage = parseStage(v)
              return <span>{stage ? STAGE_META[stage].label : v}</span>
            },
          },
          { param: "tag", label: "Tag", render: (v) => <span className="font-mono">{v}</span> },
          {
            param: "country",
            label: "Country",
            render: (v) => <CountryFlag code={v} showName className="text-fg" />,
          },
          {
            param: "asn",
            label: "Network",
            render: (v) => <span className="font-mono">AS{v}</span>,
          },
          {
            param: "technique",
            label: "Technique",
            render: (v) => <span className="font-mono">{v}</span>,
          },
          {
            param: "campaign_id",
            label: "Campaign",
            render: (v) => <CampaignName id={v} />,
          },
        ]}
      >
        <SensorFilter />
        <FloodFilter />
      </FilterBar>

      <div className="overflow-hidden rounded-lg border bg-surface shadow-sm">
        <div className="hidden grid-cols-[5.5rem_minmax(0,1fr)_auto_6rem] gap-x-4 border-b px-5 py-2.5 text-2xs font-medium tracking-wide text-fg-subtle uppercase md:grid">
          <span>Sensor</span>
          <span>What happened</span>
          <span className="text-right">Tags</span>
          <span className="text-right">Started</span>
        </div>

        {query.isPending ? (
          <SkeletonList rows={10} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title="Could not load sessions"
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
            icon={Crosshair}
            title="No sessions match these filters"
            description="Try another sensor, or clear the filters to see everything."
            action={
              <Button variant="outline" size="sm" onClick={() => setParams({})}>
                Clear filters
              </Button>
            }
          />
        ) : (
          <div
            ref={listRef}
            role="list"
            aria-label="Sessions"
            aria-busy={isFetchingNextPage}
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
                  {session ? <SessionRow session={session} /> : <SkeletonRow />}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {query.isSuccess && rows.length > 0 && !hasNextPage ? (
        <p className="mt-4 text-center text-xs text-fg-subtle">
          End of the list · {plural(connections, "session")}
          {connections === rows.length ? "" : ` in ${plural(rows.length, "row")}`}
        </p>
      ) : null}
    </>
  )
}
