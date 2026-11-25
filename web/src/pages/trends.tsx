import { useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { useIpMask } from "@/app/ip-mask"
import { FilterBar, SensorFilter } from "@/components/filter-bar"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { SegmentedControl } from "@/components/segmented-control"
import { NewList } from "@/components/trends/new-list"
import { TagTable } from "@/components/trends/tag-table"
import { TopList, type TopListItem } from "@/components/top-list"
import { sensorParam, useSensorFilter } from "@/hooks/use-sensor-filter"
import { useUrlParam } from "@/hooks/use-url-param"
import { api, queryKeys, type TopResponse } from "@/lib/api"
import { maskIpsInText } from "@/lib/format"
import {
  describeNew,
  describeTags,
  describeTop,
  NEW_FIELDS,
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

const TOP_KINDS = [
  { value: "username", label: "Usernames", eyebrow: "Usernames tried", loading: "Counting logins…", empty: "No login attempts in this period." },
  { value: "password", label: "Passwords", eyebrow: "Passwords tried", loading: "Counting logins…", empty: "No login attempts in this period." },
  { value: "command", label: "Commands", eyebrow: "Commands run", loading: "Reading shell history…", empty: "No commands in this period." },
  { value: "url", label: "URLs", eyebrow: "URLs requested", loading: "Reading web requests…", empty: "No web requests in this period." },
] as const
type TopKind = (typeof TOP_KINDS)[number]["value"]

/** The four ranked lists as one card: a switch picks which field is ranked. */
function TopValuesCard({
  days,
  range,
}: {
  days: number
  range: { since: string; until: string; sensor: ReturnType<typeof useTrendFilters>["sensor"] }
}) {
  const { masked } = useIpMask()
  const [raw, setRaw] = useUrlParam("top")
  const kind: TopKind = TOP_KINDS.find((k) => k.value === raw)?.value ?? "username"
  const meta = TOP_KINDS.find((k) => k.value === kind) ?? TOP_KINDS[0]
  const q = useQuery({
    queryKey: queryKeys.top(kind, range),
    queryFn: () => api.top(kind, range, 8),
  })
  const f = describeTop(kind, q.data, days)
  const mask = (s: string) => (masked ? maskIpsInText(s) : s)
  return (
    <FindingCard
      className="min-w-0"
      eyebrow={`${meta.eyebrow}, ${days} days`}
      finding={
        q.isPending ? (
          meta.loading
        ) : (
          <span className="[overflow-wrap:anywhere]">{mask(f.finding)}</span>
        )
      }
      detail={q.isPending ? undefined : f.detail}
      action={
        <SegmentedControl
          label="Field"
          value={kind}
          onChange={(v) => setRaw(v === "username" ? null : v)}
          options={TOP_KINDS.map((k) => ({ value: k.value, label: k.label }))}
        />
      }
    >
      <TopList
        items={toItems(q.data, kind, mask)}
        loading={q.isPending}
        rows={8}
        empty={meta.empty}
      />
    </FindingCard>
  )
}

export function TrendsPage() {
  const { days, setDays, field, setField, range } = useTrendFilters()

  const tags = useQuery({
    queryKey: queryKeys.trendsTags({ since: range.since, until: range.until }),
    queryFn: () => api.trendsTags({ since: range.since, until: range.until }),
  })
  const fresh = useQuery({
    queryKey: queryKeys.trendsNew(field, days),
    queryFn: () => api.trendsNew(field, days, 50),
  })

  const tagFinding = describeTags(tags.data?.points ?? [], days)
  const newFinding = describeNew(field, fresh.data?.items ?? [], days)

  return (
    <>
      <PageHeader
        help="patterns"
        title="Patterns"
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

      <div className="grid grid-cols-1 gap-4 2xl:grid-cols-2">
        <TopValuesCard days={days} range={range} />

        <FindingCard
          className="min-w-0"
          eyebrow={`Tags over time, ${days} days`}
          finding={tags.isPending ? "Reading tags…" : tagFinding.finding}
          detail={tags.isPending ? undefined : tagFinding.detail}
        >
          <TagTable points={tags.data?.points} loading={tags.isPending} />
        </FindingCard>
      </div>

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
