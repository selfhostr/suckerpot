import { useQuery } from "@tanstack/react-query"
import { Grid3x3, SearchX } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { FilterBar, SensorFilter } from "@/components/filter-bar"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { SegmentedControl } from "@/components/segmented-control"
import { TechniqueHeatmap } from "@/components/techniques/technique-heatmap"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { useUrlParam } from "@/hooks/use-url-param"
import { api, queryKeys } from "@/lib/api"
import { TECHNIQUE_WINDOWS, describeMatrix, techniqueDays } from "@/lib/campaigns"
import { formatNumber, plural } from "@/lib/format"
import { formatSensors, parseSensors } from "@/lib/sensors"

export function TechniquesPage() {
  const [windowParam, setWindow] = useUrlParam("window")
  const [sensorParam] = useUrlParam("sensor")
  const sensors = parseSensors(sensorParam)
  const sensorKey = formatSensors(sensors) ?? ""
  const days = techniqueDays(windowParam)
  const sensor = sensors.length ? sensors : undefined

  const matrix = useQuery({
    queryKey: queryKeys.attackMatrix(days, sensorKey),
    queryFn: () => api.attackMatrix(days, sensor),
  })
  const catalogue = useQuery({
    queryKey: queryKeys.attackTechniques(days, sensorKey),
    queryFn: () => api.attackTechniques(days, sensor),
  })

  const seen = new Set(matrix.data?.rows.map((r) => r.id))
  const unseen = (catalogue.data?.items ?? []).filter((t) => !seen.has(t.id))
  const total = catalogue.data?.items.length ?? null
  const top = matrix.data
    ? [...matrix.data.rows].sort((a, b) => b.total_sessions - a.total_sessions)[0]
    : undefined

  const headline = matrix.data
    ? describeMatrix(matrix.data, total)
    : "What attackers tried, in the vocabulary security teams use."

  return (
    <>
      <PageHeader help="techniques" title="Techniques" description={headline} />

      <FilterBar className="mb-4" chips={[]} alsoClears={["sensor", "window"]}>
        <SensorFilter />
        <SegmentedControl
          label="Time window"
          value={String(days)}
          onChange={(v) => setWindow(v === "30" ? null : v)}
          options={TECHNIQUE_WINDOWS.map((w) => ({ value: w.value, label: w.label }))}
        />
      </FilterBar>

      <FindingCard
        eyebrow="MITRE ATT&CK techniques by stage"
        finding={
          top
            ? `The most common move: they ${top.plain}, in ${plural(top.total_sessions, "session")}.`
            : matrix.isPending
              ? "Reading the techniques…"
              : "Nothing to show for this window."
        }
        detail="Each row is something attackers did, grouped by the stage of the attack. The stronger a cell, the more sessions that day."
      >
        {matrix.isPending ? (
          <div role="status" aria-label="Loading" className="space-y-3">
            <Skeleton className="h-6 w-40" />
            <Skeleton className="h-64 w-full" />
          </div>
        ) : matrix.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title="Could not load the techniques"
            description={matrix.error.message}
            action={
              <Button variant="outline" size="sm" onClick={() => void matrix.refetch()}>
                Try again
              </Button>
            }
          />
        ) : matrix.data.rows.length === 0 ? (
          <EmptyState
            variant="bare"
            icon={Grid3x3}
            title="No techniques seen"
            description="Techniques are labelled as sessions arrive. Try a longer window or another sensor."
          />
        ) : (
          <TechniqueHeatmap
            matrix={matrix.data}
            linkSuffix={sensorKey ? `&sensor=${encodeURIComponent(sensorKey)}` : ""}
          />
        )}
      </FindingCard>

      {unseen.length > 0 && matrix.isSuccess ? (
        <FindingCard
          className="mt-4"
          eyebrow="Not seen"
          finding={`${plural(unseen.length, "technique")} we watch for did not show up in the last ${days} days.`}
          detail={`${formatNumber(seen.size)} of ${formatNumber(total ?? 0)} appeared.`}
        >
          <ul className="flex flex-wrap gap-1.5" aria-label="Techniques not seen">
            {unseen.map((t) => (
              <li
                key={t.id}
                title={t.name}
                className="inline-flex h-6 items-center gap-1.5 rounded-sm border border-border-strong px-2 text-2xs text-fg-muted"
              >
                <span className="font-mono text-fg-subtle">{t.id}</span>
                {t.name}
              </li>
            ))}
          </ul>
        </FindingCard>
      ) : null}
    </>
  )
}
