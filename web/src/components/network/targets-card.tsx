import { useInfiniteQuery } from "@tanstack/react-query"
import { LoadMore } from "@/components/load-more"
import { BadgeCheck, ListX } from "lucide-react"
import { useMemo } from "react"
import { Link } from "react-router"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { IPChip } from "@/components/ip-chip"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonList } from "@/components/skeletons"
import { TagBadge } from "@/components/tag-badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { useUrlParam } from "@/hooks/use-url-param"
import { plural } from "@/lib/format"
import {
  daysToTakedown,
  defangValue,
  formatDay,
  networkApi,
  networkKeys,
  SENSORS_BUCKET,
  TARGET_KIND_LABEL,
  TARGET_STATE_LABEL,
  targetLabel,
  targetsFinding,
  type NetworkTarget,
} from "@/lib/network"

const STATES = [
  { value: "taken_down", label: "Taken down" },
  { value: "reported", label: "Reported" },
  { value: "confirmed", label: "Confirmed" },
  { value: "all", label: "All" },
] as const

const KINDS = [
  { value: "all", label: "All" },
  { value: "ip", label: "Addresses" },
  { value: "url", label: "Links" },
  { value: "domain", label: "Domains" },
  { value: "sha256", label: "Files" },
  { value: "c2_ip", label: "Command servers" },
] as const

const COLS = "sm:grid-cols-[minmax(0,1.6fr)_7rem_minmax(0,1fr)_9.5rem_8.5rem]"

function TargetValue({ t }: { t: NetworkTarget }) {
  const isIp = (t.kind === "ip" || t.kind === "c2_ip") && t.value
  if (isIp && t.value) {
    // An address this sensor saw opens its attacker page; any other opens just this target.
    return (
      <IPChip
        ip={t.value}
        variant="ghost"
        href={t.mine ? undefined : `/network?target=${t.hub_id}`}
      />
    )
  }
  const text = t.value && t.kind !== "sha256" ? defangValue(t.value) : targetLabel(t)
  return (
    <Link
      to={`/network?target=${t.hub_id}`}
      className="block truncate font-mono text-xs text-fg hover:underline hover:underline-offset-4"
      title={text}
    >
      {text}
    </Link>
  )
}

function Row({ t }: { t: NetworkTarget }) {
  const days = daysToTakedown(t)
  return (
    <li
      className={`grid min-w-0 grid-cols-2 items-center gap-x-4 gap-y-1.5 px-4 py-3 sm:px-5 ${COLS}`}
    >
      <div className="col-span-2 min-w-0 space-y-1 sm:col-span-1">
        <TargetValue t={t} />
        {t.mine ? (
          <span className="flex w-fit items-center gap-1 text-xs font-medium text-fg">
            <BadgeCheck aria-hidden className="size-3.5 text-status-ok" />
            You helped
          </span>
        ) : null}
      </div>
      <span className="text-xs text-fg-muted">{TARGET_KIND_LABEL[t.kind]}</span>
      <span className="flex min-w-0 flex-wrap gap-1.5">
        {t.families.length === 0 ? (
          <span className="text-xs text-fg-subtle">
            <span className="hidden sm:inline">No family</span>
            <span className="sr-only sm:hidden">No family</span>
          </span>
        ) : (
          t.families.map((f) => (
            <TagBadge key={f} tag={f} href={`/attacks?tag=${encodeURIComponent(f)}`} />
          ))
        )}
      </span>
      <span className="text-xs text-fg-muted tabular-nums">
        {t.state === "taken_down" && days !== null ? (
          <>
            <span className="font-medium text-fg">{plural(days, "day")}</span> to takedown
          </>
        ) : (
          <>
            {TARGET_STATE_LABEL[t.state]}
            {t.reported_day ? ` · ${formatDay(t.reported_day)}` : ""}
          </>
        )}
      </span>
      <span className="text-xs text-fg-muted">{SENSORS_BUCKET[t.nodes]}</span>
    </li>
  )
}

/**
 * Targets the network confirmed: addresses, links, domains, files and command servers. Filters
 * (`state`, `kind`, `mine`, `target`) live in the URL. Server-side pagination, "Show more".
 */
export function TargetsCard() {
  const [stateParam, setState] = useUrlParam("state")
  const [kindParam, setKind] = useUrlParam("kind")
  const [mineParam, setMine] = useUrlParam("mine")
  const [target, setTarget] = useUrlParam("target")
  const state: string = STATES.find((s) => s.value === stateParam)?.value ?? "taken_down"
  const kind: string = KINDS.find((k) => k.value === kindParam)?.value ?? "all"
  const mine = mineParam === "1"
  // Looking at one target ignores the other filters, so a shared link always shows it.
  const filters = target
    ? { target }
    : { state: state === "all" ? undefined : state, kind: kind === "all" ? undefined : kind, mine }
  const list = useInfiniteQuery({
    queryKey: networkKeys.targets(filters),
    queryFn: ({ pageParam }) => networkApi.targets(filters, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const items = useMemo(() => (list.data?.pages ?? []).flatMap((p) => p.items), [list.data])

  const controls = target ? (
    <Button variant="outline" size="sm" onClick={() => setTarget(null)}>
      Show all targets
    </Button>
  ) : (
    <div className="flex max-w-full flex-wrap items-center gap-x-4 gap-y-2">
      <div className="max-w-full overflow-x-auto">
        <SegmentedControl
          label="State"
          value={state as (typeof STATES)[number]["value"]}
          onChange={(v) => setState(v === "taken_down" ? null : v)}
          options={STATES}
        />
      </div>
      <label className="inline-flex items-center gap-2 text-xs text-fg-muted">
        <Switch size="sm" checked={mine} onCheckedChange={(v) => setMine(v ? "1" : null)} />
        Only ones I helped confirm
      </label>
    </div>
  )

  return (
    <FindingCard
      eyebrow="Targets"
      finding={target ? "One target of the network." : targetsFinding({ state, kind, mine })}
      detail={
        <span className="text-xs">
          Never a list of who saw what: each target shows only how many sensors, in a range.
        </span>
      }
      bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
    >
      <div className="px-4 pb-3 sm:px-5">{controls}</div>
      {target ? null : (
        <div className="overflow-x-auto px-4 pb-3 sm:px-5">
          <SegmentedControl
            label="Kind of target"
            value={kind as (typeof KINDS)[number]["value"]}
            onChange={(v) => setKind(v === "all" ? null : v)}
            options={KINDS}
          />
        </div>
      )}
      {list.isPending ? (
        <div className="border-t px-4 py-3 sm:px-5">
          <SkeletonList rows={5} />
        </div>
      ) : items.length === 0 ? (
        <div className="border-t p-4 sm:p-5">
          <EmptyState
            variant="bare"
            icon={ListX}
            title="Nothing matches"
            description="No target matches these filters yet. Try another state or kind."
          />
        </div>
      ) : (
        <>
          <div
            aria-hidden
            className={`hidden border-t px-5 py-2 text-xs font-medium text-fg-muted sm:grid ${COLS}`}
          >
            <span>Target</span>
            <span>Kind</span>
            <span>Family</span>
            <span>Outcome</span>
            <span>Seen by</span>
          </div>
          <ul aria-label="Network targets" className="divide-y border-t">
            {items.map((t) => (
              <Row key={t.hub_id} t={t} />
            ))}
          </ul>
          <LoadMore
            hasNextPage={list.hasNextPage}
            isFetchingNextPage={list.isFetchingNextPage}
            fetchNextPage={list.fetchNextPage}
            label="Show more"
            className="border-t"
          />
        </>
      )}
    </FindingCard>
  )
}
