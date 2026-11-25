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
import { t, tk } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { cn } from "@/lib/utils"
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
  { value: "all", labelKey: tk("common_all") },
  { value: "payload_url", labelKey: tk("results_targets_role_urls") },
  { value: "payload_host", labelKey: tk("results_targets_role_hosts") },
  { value: "attack_source", labelKey: tk("results_targets_role_addresses") },
  { value: "c2", labelKey: tk("results_targets_role_c2") },
] as const satisfies readonly { value: RoleFilter; labelKey: string }[]

const STATE_OPTIONS = [
  { value: "all", labelKey: tk("results_targets_state_any") },
  { value: "up", labelKey: tk("results_targets_state_up") },
  { value: "down", labelKey: tk("results_targets_state_down") },
  { value: "changed", labelKey: tk("results_targets_state_changed") },
] as const satisfies readonly { value: StateFilter; labelKey: string }[]

const isRole = (v: string | null): v is TargetRole => v !== null && v in ROLE_LABEL
const isState = (v: string | null): v is TargetState =>
  v === "up" || v === "down" || v === "changed" || v === "unknown"

/** Children (a URL on a tracked host) follow their parent; the page order is kept otherwise. */
function groupChildren(items: readonly Target[]): Target[] {
  const ids = new Set(items.map((tg) => tg.id))
  const kids = new Map<number, Target[]>()
  for (const tg of items)
    if (tg.parent_id && ids.has(tg.parent_id))
      kids.set(tg.parent_id, [...(kids.get(tg.parent_id) ?? []), tg])
  return items
    .filter((tg) => !(tg.parent_id && ids.has(tg.parent_id)))
    .flatMap((tg) => [tg, ...(kids.get(tg.id) ?? [])])
}

const ttdText = (tg: Target) =>
  tg.ttd_s == null
    ? t("results_targets_not_down_yet")
    : t("results_targets_down_within", { delay: shortDelay(tg.ttd_s) })
const channelText = (tg: Target) => tg.channels.map((c) => CHANNEL_LABEL[c]).join(", ")

/** Below sm a row is two lines instead of six columns. */
function TargetCards({ items, ids }: { items: readonly Target[]; ids: ReadonlySet<number> }) {
  return (
    <ul aria-label={t("results_targets_list_label")} className="divide-y border-t sm:hidden">
      {items.map((tg) => {
        const child = Boolean(tg.parent_id && ids.has(tg.parent_id))
        return (
          <li key={tg.id} className={cn("px-4 py-3", child && "ml-4 border-l pl-3")}>
            <div className="flex items-start justify-between gap-3">
              <Link
                to={`/defend/results/targets/${tg.id}`}
                className="min-w-0 font-mono text-xs break-all text-fg underline-offset-4 hover:underline"
              >
                {defang(tg.value)}
              </Link>
              <TargetStateBadge state={tg.state} role={tg.role} />
            </div>
            <MetaLine className="mt-1.5">
              <span>{ROLE_LABEL[tg.role]}</span>
              <span className="inline-flex items-center gap-1.5">
                {tg.country ? <CountryFlag code={tg.country} /> : null}
                {tg.provider_name ??
                  (tg.asn ? `AS${tg.asn}` : t("results_targets_unknown_provider"))}
              </span>
              <span>
                {tNodes(
                  "results_targets_reported_ago",
                  {},
                  { time: <RelativeTime iso={tg.reported_at} /> },
                )}
              </span>
              <span>{ttdText(tg)}</span>
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
  const ids = useMemo(() => new Set(items.map((tg) => tg.id)), [items])
  const down = items.filter((tg) => tg.state === "down").length
  const finding = q.isPending
    ? t("results_targets_loading")
    : items.length === 0
      ? t("results_targets_none")
      : t("results_targets_finding", { count: items.length, down })
  return (
    <FindingCard
      eyebrow={t("results_targets_eyebrow")}
      finding={finding}
      detail={t("results_targets_detail")}
      action={
        <div className="flex flex-wrap gap-2">
          <SegmentedControl
            label={t("results_targets_filter_type")}
            value={role}
            onChange={(v) => setRole(v === "all" ? null : v)}
            options={ROLE_OPTIONS.map((o) => ({ value: o.value, label: t(o.labelKey) }))}
            className="scroll-fade-x max-w-full overflow-x-auto"
          />
          <SegmentedControl
            label={t("results_targets_filter_state")}
            value={state}
            onChange={(v) => setState(v === "all" ? null : v)}
            options={STATE_OPTIONS.map((o) => ({ value: o.value, label: t(o.labelKey) }))}
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
          {t("results_targets_error")}
        </p>
      ) : items.length === 0 ? null : (
        <>
          <TargetCards items={items} ids={ids} />
          <div className="relative hidden border-t sm:block">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">{t("results_targets_list_label")}</caption>
              <thead className="text-xs text-fg-muted [&_th]:sticky [&_th]:top-14 [&_th]:z-10 [&_th]:border-b [&_th]:bg-surface">
                <tr>
                  <th scope="col" className="px-4 py-2 font-medium sm:px-5">
                    {t("results_targets_col_target")}
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    {t("results_targets_col_provider")}
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    {t("results_targets_col_reported")}
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    {t("results_targets_col_channel")}
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    {t("results_targets_col_state")}
                  </th>
                  <th scope="col" className="px-4 py-2 text-right font-medium sm:px-5">
                    {t("results_targets_col_ttd")}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {items.map((tg) => (
                  <tr key={tg.id} className="hover:bg-surface-hover/50">
                    <td className="max-w-[22rem] px-4 py-2 sm:px-5">
                      <div
                        className={cn(tg.parent_id && ids.has(tg.parent_id) && "ml-1 border-l pl-3")}
                      >
                        <Link
                          to={`/defend/results/targets/${tg.id}`}
                          className="block truncate font-mono text-xs text-fg underline-offset-4 hover:underline"
                          title={defang(tg.value)}
                        >
                          {tg.parent_id && ids.has(tg.parent_id) ? (
                            <CornerDownRight
                              aria-hidden
                              className="mr-1 inline size-3 text-fg-subtle"
                            />
                          ) : null}
                          {defang(tg.value)}
                        </Link>
                        <span className="text-2xs text-fg-subtle">{ROLE_LABEL[tg.role]}</span>
                      </div>
                    </td>
                    <td className="px-2 py-2 whitespace-nowrap">
                      <span className="inline-flex max-w-[16rem] items-center gap-2 text-fg-muted">
                        {tg.country ? <CountryFlag code={tg.country} /> : null}
                        {tg.asn ? (
                          <Link
                            to={`/attackers?asn=${tg.asn}`}
                            className="shrink-0 font-mono text-xs hover:text-fg"
                          >
                            AS{tg.asn}
                          </Link>
                        ) : null}
                        <span className="truncate text-xs">
                          {tg.provider_name ?? t("results_targets_unknown")}
                        </span>
                      </span>
                    </td>
                    <td className="px-2 py-2">
                      <RelativeTime iso={tg.reported_at} />
                    </td>
                    <td className="px-2 py-2">
                      <span className="text-xs text-fg-muted">{channelText(tg)}</span>
                    </td>
                    <td className="px-2 py-2">
                      <TargetStateBadge state={tg.state} role={tg.role} />
                    </td>
                    <td className="px-4 py-2 text-right whitespace-nowrap sm:px-5">
                      {tg.ttd_s == null ? (
                        <span className="text-fg-subtle">{t("results_targets_none_yet")}</span>
                      ) : (
                        t("results_targets_within", { delay: shortDelay(tg.ttd_s) })
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
        label={t("common_show_more")}
        className="border-t"
      />
    </FindingCard>
  )
}
