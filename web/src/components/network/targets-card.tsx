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
import { t, tk } from "@/i18n"
import { tNodes } from "@/i18n/rich"
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
  { value: "taken_down", labelKey: tk("network_targets_state_taken_down") },
  { value: "reported", labelKey: tk("network_targets_state_reported") },
  { value: "confirmed", labelKey: tk("network_targets_state_confirmed") },
  { value: "all", labelKey: tk("common_all") },
] as const

const KINDS = [
  { value: "all", labelKey: tk("common_all") },
  { value: "ip", labelKey: tk("network_targets_kind_ip") },
  { value: "url", labelKey: tk("network_targets_kind_url") },
  { value: "domain", labelKey: tk("network_targets_kind_domain") },
  { value: "sha256", labelKey: tk("network_targets_kind_sha256") },
  { value: "c2_ip", labelKey: tk("network_targets_kind_c2_ip") },
] as const

const COLS = "sm:grid-cols-[minmax(0,1.6fr)_7rem_minmax(0,1fr)_9.5rem_8.5rem]"

function TargetValue({ tg }: { tg: NetworkTarget }) {
  const isIp = (tg.kind === "ip" || tg.kind === "c2_ip") && tg.value
  if (isIp && tg.value) {
    // An address this sensor saw opens its attacker page; any other opens just this target.
    return (
      <IPChip
        ip={tg.value}
        variant="ghost"
        href={tg.mine ? undefined : `/network?target=${tg.hub_id}`}
      />
    )
  }
  const text = tg.value && tg.kind !== "sha256" ? defangValue(tg.value) : targetLabel(tg)
  return (
    <Link
      to={`/network?target=${tg.hub_id}`}
      className="block truncate font-mono text-xs text-fg hover:underline hover:underline-offset-4"
      title={text}
    >
      {text}
    </Link>
  )
}

function Row({ tg }: { tg: NetworkTarget }) {
  const days = daysToTakedown(tg)
  return (
    <li
      className={`grid min-w-0 grid-cols-2 items-center gap-x-4 gap-y-1.5 px-4 py-3 sm:px-5 ${COLS}`}
    >
      <div className="col-span-2 min-w-0 space-y-1 sm:col-span-1">
        <TargetValue tg={tg} />
        {tg.mine ? (
          <span className="flex w-fit items-center gap-1 text-xs font-medium text-fg">
            <BadgeCheck aria-hidden className="size-3.5 text-status-ok" />
            {t("network_targets_you_helped")}
          </span>
        ) : null}
      </div>
      <span className="text-xs text-fg-muted">{TARGET_KIND_LABEL[tg.kind]}</span>
      <span className="flex min-w-0 flex-wrap gap-1.5">
        {tg.families.length === 0 ? (
          <span className="text-xs text-fg-subtle">
            <span className="hidden sm:inline">{t("network_targets_no_family")}</span>
            <span className="sr-only sm:hidden">{t("network_targets_no_family")}</span>
          </span>
        ) : (
          tg.families.map((f) => (
            <TagBadge key={f} tag={f} href={`/attacks?tag=${encodeURIComponent(f)}`} />
          ))
        )}
      </span>
      <span className="text-xs text-fg-muted tabular-nums">
        {tg.state === "taken_down" && days !== null ? (
          <>
            {tNodes(
              "network_targets_days_to_takedown",
              {},
              {
                days: (
                  <span className="font-medium text-fg">
                    {t("network_targets_days", { count: days })}
                  </span>
                ),
              },
            )}
          </>
        ) : (
          <>
            {TARGET_STATE_LABEL[tg.state]}
            {tg.reported_day ? ` · ${formatDay(tg.reported_day)}` : ""}
          </>
        )}
      </span>
      <span className="text-xs text-fg-muted">{SENSORS_BUCKET[tg.nodes]}</span>
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
      {t("network_targets_show_all")}
    </Button>
  ) : (
    <div className="flex max-w-full flex-wrap items-center gap-x-4 gap-y-2">
      <div className="max-w-full overflow-x-auto">
        <SegmentedControl
          label={t("network_targets_filter_state")}
          value={state as (typeof STATES)[number]["value"]}
          onChange={(v) => setState(v === "taken_down" ? null : v)}
          options={STATES.map((s) => ({ value: s.value, label: t(s.labelKey) }))}
        />
      </div>
      <label className="inline-flex items-center gap-2 text-xs text-fg-muted">
        <Switch size="sm" checked={mine} onCheckedChange={(v) => setMine(v ? "1" : null)} />
        {t("network_targets_only_mine")}
      </label>
    </div>
  )

  return (
    <FindingCard
      eyebrow={t("network_targets_eyebrow")}
      help="targets"
      finding={target ? t("network_targets_one") : targetsFinding({ state, kind, mine })}
      detail={
        <span className="text-xs">
          {t("network_targets_privacy_note")}
        </span>
      }
      bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
    >
      <div className="px-4 pb-3 sm:px-5">{controls}</div>
      {target ? null : (
        <div className="overflow-x-auto px-4 pb-3 sm:px-5">
          <SegmentedControl
            label={t("network_targets_filter_kind")}
            value={kind as (typeof KINDS)[number]["value"]}
            onChange={(v) => setKind(v === "all" ? null : v)}
            options={KINDS.map((k) => ({ value: k.value, label: t(k.labelKey) }))}
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
            title={t("network_targets_empty_title")}
            description={t("network_targets_empty_description")}
          />
        </div>
      ) : (
        <>
          <div
            aria-hidden
            className={`hidden border-t px-5 py-2 text-xs font-medium text-fg-muted sm:grid ${COLS}`}
          >
            <span className="truncate">{t("network_targets_col_target")}</span>
            <span className="truncate">{t("network_targets_col_kind")}</span>
            <span className="truncate">{t("network_targets_col_family")}</span>
            <span className="truncate">{t("network_targets_col_outcome")}</span>
            <span className="truncate">{t("network_targets_col_seen_by")}</span>
          </div>
          <ul aria-label={t("network_targets_list_label")} className="divide-y border-t">
            {items.map((tg) => (
              <Row key={tg.hub_id} tg={tg} />
            ))}
          </ul>
          <LoadMore
            hasNextPage={list.hasNextPage}
            isFetchingNextPage={list.isFetchingNextPage}
            fetchNextPage={list.fetchNextPage}
            label={t("common_show_more")}
            className="border-t"
          />
        </>
      )}
    </FindingCard>
  )
}
