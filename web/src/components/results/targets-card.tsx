import { useInfiniteQuery } from "@tanstack/react-query"
import { LoadMore } from "@/components/load-more"
import { CornerDownRight } from "lucide-react"
import { useMemo } from "react"
import { Link } from "react-router"
import { CountryFlag } from "@/components/country-flag"
import { MetaLine } from "@/components/meta-line"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SegmentedControl } from "@/components/segmented-control"
import { Skeleton } from "@/components/ui/skeleton"
import { useUrlParam } from "@/hooks/use-url-param"
import { cn } from "@/lib/utils"
import { formatNumber } from "@/lib/format"
import {
  CHANNEL_LABEL,
  resultKeys,
  resultsApi,
  ROLE_LABEL,
  type ResultFilters,
  type Target,
  type TargetRole,
  type TargetState,
} from "@/lib/results"
import { defang, shortDelay } from "@/lib/results-sentences"
import { TargetStateBadge } from "./badges"

type RoleFilter = "all" | TargetRole
type StateFilter = "all" | TargetState

const ROLE_OPTIONS = [
  { value: "all", label: "All" },
  { value: "payload_url", label: "URLs" },
  { value: "payload_host", label: "Hosts" },
  { value: "attack_source", label: "Addresses" },
  { value: "c2", label: "C2" },
] as const satisfies readonly { value: RoleFilter; label: string }[]

const STATE_OPTIONS = [
  { value: "all", label: "Any state" },
  { value: "up", label: "Up" },
  { value: "down", label: "Down" },
  { value: "changed", label: "Changed" },
] as const satisfies readonly { value: StateFilter; label: string }[]

const isRole = (v: string | null): v is TargetRole => v !== null && v in ROLE_LABEL
const isState = (v: string | null): v is TargetState =>
  v === "up" || v === "down" || v === "changed" || v === "unknown"

/** Children (a URL on a tracked host) follow their parent; the page order is kept otherwise. */
function groupChildren(items: readonly Target[]): Target[] {
  const ids = new Set(items.map((t) => t.id))
  const kids = new Map<number, Target[]>()
  for (const t of items)
    if (t.parent_id && ids.has(t.parent_id))
      kids.set(t.parent_id, [...(kids.get(t.parent_id) ?? []), t])
  return items
    .filter((t) => !(t.parent_id && ids.has(t.parent_id)))
    .flatMap((t) => [t, ...(kids.get(t.id) ?? [])])
}

const ttdText = (t: Target) =>
  t.ttd_s == null ? "not down yet" : `down within ${shortDelay(t.ttd_s)}`
const channelText = (t: Target) => t.channels.map((c) => CHANNEL_LABEL[c]).join(", ")

/** Below sm a row is two lines instead of six columns. */
function TargetCards({ items, ids }: { items: readonly Target[]; ids: ReadonlySet<number> }) {
  return (
    <ul aria-label="Tracked targets" className="divide-y border-t sm:hidden">
      {items.map((t) => {
        const child = Boolean(t.parent_id && ids.has(t.parent_id))
        return (
          <li key={t.id} className={cn("px-4 py-3", child && "ml-4 border-l pl-3")}>
            <div className="flex items-start justify-between gap-3">
              <Link
                to={`/defend/results/targets/${t.id}`}
                className="min-w-0 font-mono text-xs break-all text-fg underline-offset-4 hover:underline"
              >
                {defang(t.value)}
              </Link>
              <TargetStateBadge state={t.state} role={t.role} />
            </div>
            <MetaLine className="mt-1.5">
              <span>{ROLE_LABEL[t.role]}</span>
              <span className="inline-flex items-center gap-1.5">
                {t.country ? <CountryFlag code={t.country} /> : null}
                {t.provider_name ?? (t.asn ? `AS${t.asn}` : "unknown provider")}
              </span>
              <span>
                reported <RelativeTime iso={t.reported_at} />
              </span>
              <span>{ttdText(t)}</span>
            </MetaLine>
          </li>
        )
      })}
    </ul>
  )
}

/** The tracked targets, newest report first. Values are defanged text; a row opens the target. */
export function TargetsCard({ filters }: { filters: ResultFilters }) {
  const [roleParam, setRole] = useUrlParam("role")
  const [stateParam, setState] = useUrlParam("state")
  const role: RoleFilter = isRole(roleParam) ? roleParam : "all"
  const state: StateFilter = isState(stateParam) ? stateParam : "all"
  const f = {
    ...filters,
    role: role === "all" ? undefined : role,
    state: state === "all" ? undefined : state,
  }
  const q = useInfiniteQuery({
    queryKey: resultKeys.targets(f),
    queryFn: ({ pageParam }) => resultsApi.targets(f, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const items = useMemo(
    () => groupChildren((q.data?.pages ?? []).flatMap((p) => p.items)),
    [q.data],
  )
  const ids = useMemo(() => new Set(items.map((t) => t.id)), [items])
  const down = items.filter((t) => t.state === "down").length
  const finding = q.isPending
    ? "Listing the targets…"
    : items.length === 0
      ? "No tracked target matches these filters."
      : `${formatNumber(items.length)} ${items.length === 1 ? "target" : "targets"} listed; ${formatNumber(down)} ${down === 1 ? "is" : "are"} down.`
  return (
    <FindingCard
      eyebrow="Targets"
      finding={finding}
      detail="Addresses are shown defanged and are never links. A row opens its timeline."
      action={
        <div className="flex flex-wrap gap-2">
          <SegmentedControl
            label="Target type"
            value={role}
            onChange={(v) => setRole(v === "all" ? null : v)}
            options={ROLE_OPTIONS}
            className="scroll-fade-x max-w-full overflow-x-auto"
          />
          <SegmentedControl
            label="Target state"
            value={state}
            onChange={(v) => setState(v === "all" ? null : v)}
            options={STATE_OPTIONS}
            className="scroll-fade-x max-w-full overflow-x-auto"
          />
        </div>
      }
      bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
      className="normal-nums"
    >
      {q.isPending ? (
        <div className="px-4 pb-5 sm:px-5">
          <Skeleton className="h-40 w-full" />
        </div>
      ) : q.isError ? (
        <p role="alert" className="border-t px-4 py-6 text-sm text-fg-muted sm:px-5">
          The targets could not be loaded.
        </p>
      ) : items.length === 0 ? null : (
        <>
          <TargetCards items={items} ids={ids} />
          <div className="relative hidden border-t sm:block">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Tracked targets</caption>
              <thead className="text-xs text-fg-muted [&_th]:sticky [&_th]:top-14 [&_th]:z-10 [&_th]:border-b [&_th]:bg-surface">
                <tr>
                  <th scope="col" className="px-4 py-2 font-medium sm:px-5">
                    Target
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    Provider
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    Reported
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    Channel
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    State
                  </th>
                  <th scope="col" className="px-4 py-2 text-right font-medium sm:px-5">
                    Time to takedown
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {items.map((t) => (
                  <tr key={t.id} className="hover:bg-surface-hover/50">
                    <td className="max-w-[22rem] px-4 py-2 sm:px-5">
                      <div
                        className={cn(t.parent_id && ids.has(t.parent_id) && "ml-1 border-l pl-3")}
                      >
                        <Link
                          to={`/defend/results/targets/${t.id}`}
                          className="block truncate font-mono text-xs text-fg underline-offset-4 hover:underline"
                          title={defang(t.value)}
                        >
                          {t.parent_id && ids.has(t.parent_id) ? (
                            <CornerDownRight
                              aria-hidden
                              className="mr-1 inline size-3 text-fg-subtle"
                            />
                          ) : null}
                          {defang(t.value)}
                        </Link>
                        <span className="text-2xs text-fg-subtle">{ROLE_LABEL[t.role]}</span>
                      </div>
                    </td>
                    <td className="px-2 py-2 whitespace-nowrap">
                      <span className="inline-flex max-w-[16rem] items-center gap-2 text-fg-muted">
                        {t.country ? <CountryFlag code={t.country} /> : null}
                        {t.asn ? (
                          <Link
                            to={`/attackers?asn=${t.asn}`}
                            className="shrink-0 font-mono text-xs hover:text-fg"
                          >
                            AS{t.asn}
                          </Link>
                        ) : null}
                        <span className="truncate text-xs">{t.provider_name ?? "unknown"}</span>
                      </span>
                    </td>
                    <td className="px-2 py-2">
                      <RelativeTime iso={t.reported_at} />
                    </td>
                    <td className="px-2 py-2">
                      <span className="text-xs text-fg-muted">{channelText(t)}</span>
                    </td>
                    <td className="px-2 py-2">
                      <TargetStateBadge state={t.state} role={t.role} />
                    </td>
                    <td className="px-4 py-2 text-right whitespace-nowrap sm:px-5">
                      {t.ttd_s == null ? (
                        <span className="text-fg-subtle">none yet</span>
                      ) : (
                        `within ${shortDelay(t.ttd_s)}`
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      <LoadMore
        hasNextPage={q.hasNextPage}
        isFetchingNextPage={q.isFetchingNextPage}
        fetchNextPage={q.fetchNextPage}
        label="Show more"
        className="border-t"
      />
    </FindingCard>
  )
}
