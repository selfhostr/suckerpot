import { useQuery } from "@tanstack/react-query"
import { useMemo, useState } from "react"
import { useIpMask } from "@/app/ip-mask"
import { FilterBar, SensorFilter } from "@/components/filter-bar"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { SegmentedControl } from "@/components/segmented-control"
import { Heatmap } from "@/components/trends/heatmap"
import { NewList } from "@/components/trends/new-list"
import { TagChart } from "@/components/trends/tag-chart"
import { TopList, type TopListItem } from "@/components/top-list"
import { sensorParam, useSensorFilter } from "@/hooks/use-sensor-filter"
import { useUrlParam } from "@/hooks/use-url-param"
import { api, queryKeys, type TopField, type TopResponse } from "@/lib/api"
import { maskIpsInText } from "@/lib/format"
import {
  browserOffsetHours,
  describeHeatmap,
  describeNew,
  describeTags,
  describeTop,
  NEW_FIELDS,
  toLocalGrid,
  type NewField,
} from "@/lib/trends"

const HOUR = 3_600_000
const PERIODS = [7, 30] as const
type Period = (typeof PERIODS)[number]

const NEW_LABEL: Record<NewField, string> = {
  username: "Usernames",
  password: "Passwords",
  command: "Commands",
  url: "URLs",
  asn: "Attacker networks",
  user_agent: "User agents",
}

function useTrendFilters() {
  const [rawDays, setDays] = useUrlParam("days")
  const [sensors] = useSensorFilter()
  const [rawField, setField] = useUrlParam("field")
  const days: Period = rawDays === "30" ? 30 : 7
  const sensor = sensorParam(sensors)
  const field: NewField = NEW_FIELDS.includes(rawField as NewField)
    ? (rawField as NewField)
    : "username"
  // Hour-aligned, so the query keys stay stable between renders.
  const [end] = useState(() => Math.ceil(Date.now() / HOUR) * HOUR)
  const range = {
    since: new Date(end - days * 24 * HOUR).toISOString(),
    until: new Date(end).toISOString(),
    sensor,
  }
  return { days, setDays, sensor, field, setField, range }
}

function toItems(
  top: TopResponse | undefined,
  param: string,
  mask: (s: string) => string,
): TopListItem[] {
  return (top?.items ?? []).map((i) => ({
    key: i.value,
    name: mask(i.value),
    label: <span className="font-mono text-xs">{mask(i.value)}</span>,
    count: i.count,
    share: i.share,
    href: `/attacks?${param}=${encodeURIComponent(i.value)}`,
  }))
}

interface TopCardProps {
  kind: "username" | "password" | "command" | "url"
  eyebrow: string
  field: TopField
  param: string
  days: number
  range: { since: string; until: string; sensor: ReturnType<typeof useTrendFilters>["sensor"] }
  loadingText: string
  empty: string
}

function TopCard({ kind, eyebrow, field, param, days, range, loadingText, empty }: TopCardProps) {
  const { masked } = useIpMask()
  const q = useQuery({
    queryKey: queryKeys.top(field, range),
    queryFn: () => api.top(field, range, 8),
  })
  const f = describeTop(kind, q.data, days)
  const mask = (s: string) => (masked ? maskIpsInText(s) : s)
  return (
    <FindingCard
      className="min-w-0"
      eyebrow={`${eyebrow}, ${days} days`}
      finding={
        q.isPending ? (
          loadingText
        ) : (
          <span className="[overflow-wrap:anywhere]">{mask(f.finding)}</span>
        )
      }
      detail={q.isPending ? undefined : f.detail}
    >
      <TopList items={toItems(q.data, param, mask)} loading={q.isPending} rows={6} empty={empty} />
    </FindingCard>
  )
}

export function TrendsPage() {
  const { days, setDays, field, setField, range } = useTrendFilters()
  const offset = useMemo(() => browserOffsetHours(), [])

  const tags = useQuery({
    queryKey: queryKeys.trendsTags({ since: range.since, until: range.until }),
    queryFn: () => api.trendsTags({ since: range.since, until: range.until }),
  })
  const heat = useQuery({
    queryKey: queryKeys.heatmap(range),
    queryFn: () => api.heatmap(range),
  })
  const fresh = useQuery({
    queryKey: queryKeys.trendsNew(field, days),
    queryFn: () => api.trendsNew(field, days, 50),
  })

  const tagFinding = describeTags(tags.data?.points ?? [], days)
  const heatFinding = describeHeatmap(toLocalGrid(heat.data?.cells ?? [], offset), days)
  const newFinding = describeNew(field, fresh.data?.items ?? [], days)

  return (
    <>
      <PageHeader
        help="patterns"
        title="Trends"
        description={`What attackers try most in the last ${days} days, how it changes over time, and what is new.`}
        actions={
          <SegmentedControl
            label="Period"
            value={String(days)}
            onChange={(v) => setDays(v === "7" ? null : v)}
            options={PERIODS.map((p) => ({ value: String(p), label: `${p} days` }))}
          />
        }
      />

      <FilterBar className="mb-4" chips={[]} alsoClears={["sensor"]}>
        <SensorFilter />
      </FilterBar>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <TopCard
          kind="username"
          eyebrow="Usernames tried"
          field="username"
          param="username"
          days={days}
          range={range}
          loadingText="Counting logins…"
          empty="No login attempts in this period."
        />
        <TopCard
          kind="password"
          eyebrow="Passwords tried"
          field="password"
          param="password"
          days={days}
          range={range}
          loadingText="Counting logins…"
          empty="No login attempts in this period."
        />
        <TopCard
          kind="command"
          eyebrow="Commands run"
          field="command"
          param="command"
          days={days}
          range={range}
          loadingText="Reading shell history…"
          empty="No commands in this period."
        />
        <TopCard
          kind="url"
          eyebrow="URLs requested"
          field="url"
          param="url"
          days={days}
          range={range}
          loadingText="Reading web requests…"
          empty="No web requests in this period."
        />
      </div>

      <FindingCard
        className="mt-4"
        eyebrow={`Tags over time, ${days} days`}
        finding={tags.isPending ? "Reading tags…" : tagFinding.finding}
        detail={tags.isPending ? undefined : tagFinding.detail}
      >
        <TagChart points={tags.data?.points} series={tags.data?.series} loading={tags.isPending} />
      </FindingCard>

      <FindingCard
        className="mt-4"
        eyebrow={`Day and hour, ${days} days`}
        finding={heat.isPending ? "Looking for a rhythm…" : heatFinding.finding}
        detail={heat.isPending ? undefined : heatFinding.detail}
      >
        <Heatmap cells={heat.data?.cells} offsetHours={offset} loading={heat.isPending} />
      </FindingCard>

      <FindingCard
        className="mt-4"
        eyebrow={days === 7 ? "New this week" : `New in the last ${days} days`}
        finding={fresh.isPending ? "Comparing with the last 90 days…" : newFinding.finding}
        detail="Compared with the 90 days before the period. Not affected by the sensor filter."
      >
        <div className="scroll-fade-x -mx-1 mb-3 overflow-x-auto px-1 pb-1">
          <SegmentedControl
            label="Kind of value"
            value={field}
            onChange={(v) => setField(v === "username" ? null : v)}
            options={NEW_FIELDS.map((f) => ({ value: f, label: NEW_LABEL[f] }))}
            className="w-max"
          />
        </div>
        <NewList
          field={field}
          items={fresh.data?.items ?? []}
          loading={fresh.isPending}
          empty="Nothing new: every value in this period was seen before."
        />
      </FindingCard>
    </>
  )
}
