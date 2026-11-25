import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react"
import { useMemo } from "react"
import { Link } from "react-router"
import { CountryFlag } from "@/components/country-flag"
import { MetaLine } from "@/components/meta-line"
import { FindingCard } from "@/components/finding-card"
import { SegmentedControl } from "@/components/segmented-control"
import { Skeleton } from "@/components/ui/skeleton"
import { useUrlParam } from "@/hooks/use-url-param"
import { t } from "@/i18n"
import { KIND_LABEL } from "@/lib/abuse"
import { formatNumber, formatPercent } from "@/lib/format"
import type { Outcome } from "@/lib/replies"
import {
  ANSWER_ROWS,
  GROUP_OPTIONS,
  type OutcomeGroup,
  type OutcomeGroupRow,
  type ProviderRow,
} from "@/lib/results"
import {
  describeProviderAnswers,
  describeTakedownProviders,
  shortDelay,
} from "@/lib/results-sentences"
import { cn } from "@/lib/utils"
import { OutcomeBadge } from "./badges"

type SortKey = "sent" | "answered" | "reply" | "name" | "targets" | "down" | "ttd" | "up"

interface Row {
  key: string
  label: string
  group: OutcomeGroup
  country: string | null
  sent: number
  answeredPct: number | null
  replyS: number | null
  best: Outcome
  td: ProviderRow | null
}

/** The best thing that happened to a provider's reports (resolved beats a ticket beats a reply). */
function bestOutcome(g: OutcomeGroupRow): Outcome {
  return ANSWER_ROWS.find((o) => (g.by_outcome[o] ?? 0) > 0) ?? "none"
}

function toRows(
  groups: readonly OutcomeGroupRow[],
  group: OutcomeGroup,
  takedown: ReadonlyMap<string, ProviderRow>,
): Row[] {
  return groups.map((g) => {
    const td = group === "asn" ? (takedown.get(`as${g.key}`) ?? null) : null
    return {
      key: g.key,
      label: g.label,
      group,
      country: group === "country" ? g.key : (td?.country ?? null),
      sent: g.sent,
      answeredPct: g.eligible > 0 ? g.answered / g.eligible : null,
      replyS: g.first_reply_p50_s,
      best: bestOutcome(g),
      td,
    }
  })
}

const VALUE: Record<SortKey, (r: Row) => number | string | null> = {
  name: (r) => r.label.toLowerCase(),
  sent: (r) => r.sent,
  answered: (r) => r.answeredPct,
  reply: (r) => r.replyS,
  targets: (r) => r.td?.targets ?? null,
  down: (r) => (r.td && r.td.eligible_48h > 0 ? r.td.down_48h / r.td.eligible_48h : null),
  ttd: (r) => r.td?.ttd_p50_s ?? null,
  up: (r) => r.td?.still_up ?? null,
}

function compare(a: Row, b: Row, key: SortKey, dir: 1 | -1): number {
  const x = VALUE[key](a)
  const y = VALUE[key](b)
  if (x === null && y === null) return 0
  if (x === null) return 1
  if (y === null) return -1
  return (x < y ? -1 : x > y ? 1 : 0) * dir
}

function ProviderName({ r }: { r: Row }) {
  if (r.group === "asn")
    return (
      <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
        <Link
          to={`/attackers?asn=${r.key}`}
          className="inline-flex h-(--chip) items-center rounded-sm border px-2 font-mono text-2xs text-fg-muted transition-colors hover:border-fg-subtle hover:text-fg"
        >
          AS{r.key}
        </Link>
        <span className="text-fg">{r.label}</span>
      </span>
    )
  if (r.group === "country")
    return (
      <Link
        to={`/attacks?country=${r.key}`}
        className="inline-flex items-center gap-2 text-fg hover:underline"
      >
        <CountryFlag code={r.key} decorative />
        {r.label}
      </Link>
    )
  if (r.group === "recipient")
    return (
      <Link
        to={`/defend/abuse?status=sent&recipient=${r.key}`}
        className="text-fg underline-offset-4 hover:underline"
      >
        {r.label}
      </Link>
    )
  return (
    <span className="text-fg">
      {(KIND_LABEL as Record<string, string | undefined>)[r.key] ?? r.label}
    </span>
  )
}

function Th({
  label,
  k,
  sort,
  dir,
  onSort,
  align = "right",
}: {
  label: string
  k: SortKey
  sort: SortKey
  dir: 1 | -1
  onSort: (k: SortKey) => void
  align?: "left" | "right"
}) {
  const active = sort === k
  const Icon = !active ? ChevronsUpDown : dir === 1 ? ArrowUp : ArrowDown
  return (
    <th
      scope="col"
      aria-sort={active ? (dir === 1 ? "ascending" : "descending") : "none"}
      className={cn("px-2 py-2 font-medium whitespace-nowrap", align === "right" && "text-right")}
    >
      <button
        type="button"
        onClick={() => onSort(k)}
        className={cn(
          "inline-flex items-center gap-1 rounded-sm outline-none hover:text-fg focus-visible:ring-2 focus-visible:ring-ring",
          active && "text-fg",
        )}
      >
        {label}
        <Icon aria-hidden className="size-3" />
      </button>
    </th>
  )
}

interface ProvidersCardProps {
  groups: readonly OutcomeGroupRow[] | undefined
  group: OutcomeGroup
  takedown: readonly ProviderRow[] | undefined
}

/** The providers table: who got reports, who answered, and (with tracking) who took things down. */
export function ProvidersCard({ groups, group, takedown }: ProvidersCardProps) {
  const [, setGroup] = useUrlParam("group")
  const [sortParam, setSortParam] = useUrlParam("sort")
  const [dirParam, setDirParam] = useUrlParam("dir")
  const td = useMemo(() => new Map((takedown ?? []).map((p) => [p.provider_key, p])), [takedown])
  const showTd = group === "asn" && td.size > 0
  const sort = (sortParam && sortParam in VALUE ? sortParam : "sent") as SortKey
  const dir: 1 | -1 = dirParam === "asc" ? 1 : -1
  const rows = useMemo(
    () => toRows(groups ?? [], group, td).sort((a, b) => compare(a, b, sort, dir)),
    [groups, group, td, sort, dir],
  )
  const onSort = (k: SortKey) => {
    if (k === sort) setDirParam(dir === 1 ? null : "asc")
    else {
      setSortParam(k === "sent" ? null : k)
      setDirParam(k === "name" ? "asc" : null)
    }
  }
  const finding = !groups
    ? t("results_providers_loading")
    : showTd
      ? describeTakedownProviders(takedown ?? [])
      : describeProviderAnswers(groups)
  const th = { sort, dir, onSort }
  return (
    <FindingCard
      eyebrow={t("results_providers_eyebrow")}
      finding={finding}
      action={
        <SegmentedControl
          label={t("results_providers_group_by")}
          value={group}
          onChange={(v) => setGroup(v === "asn" ? null : v)}
          options={GROUP_OPTIONS}
          className="scroll-fade-x max-w-full overflow-x-auto"
        />
      }
      bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
      className="normal-nums"
    >
      {!groups ? (
        <div className="px-4 pb-5 sm:px-5">
          <Skeleton className="h-40 w-full" />
        </div>
      ) : rows.length === 0 ? (
        <p className="border-t px-4 py-6 text-sm text-fg-muted sm:px-5">
          {t("results_providers_empty")}
        </p>
      ) : (
        <>
          <ul
            aria-label={t("results_providers_list_label")}
            className="divide-y border-t sm:hidden"
          >
            {rows.map((r) => (
              <li key={r.key} className="px-4 py-3">
                <span className="flex flex-wrap items-center gap-2">
                  {r.group === "asn" && r.country ? <CountryFlag code={r.country} /> : null}
                  <ProviderName r={r} />
                </span>
                <MetaLine className="mt-1.5">
                  <span>{t("results_providers_sent", { count: r.sent })}</span>
                  <span>
                    {r.answeredPct == null
                      ? t("results_providers_too_recent")
                      : t("results_providers_answered", { percent: formatPercent(r.answeredPct) })}
                  </span>
                  {showTd && r.td && r.td.eligible_48h > 0 ? (
                    <span>
                      {t("results_providers_down_48h", {
                        down: r.td.down_48h,
                        eligible: r.td.eligible_48h,
                      })}
                    </span>
                  ) : null}
                  {showTd && r.td?.ttd_p50_s != null ? (
                    <span>
                      {t("results_providers_median", { delay: shortDelay(r.td.ttd_p50_s) })}
                    </span>
                  ) : null}
                  <OutcomeBadge outcome={r.best} noAnswer />
                </MetaLine>
              </li>
            ))}
          </ul>
          <div className="relative hidden overflow-x-auto border-t sm:block">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">{t("results_providers_list_label")}</caption>
              <thead className="text-xs text-fg-muted">
                <tr className="border-b">
                  <Th label={t("results_providers_col_provider")} k="name" align="left" {...th} />
                  <Th label={t("results_providers_col_sent")} k="sent" {...th} />
                  <Th label={t("results_providers_col_answered")} k="answered" {...th} />
                  <Th label={t("results_providers_col_reply")} k="reply" {...th} />
                  <th scope="col" className="px-2 py-2 font-medium whitespace-nowrap">
                    {t("results_providers_col_best")}
                  </th>
                  {showTd ? (
                    <>
                      <Th label={t("results_providers_col_targets")} k="targets" {...th} />
                      <Th label={t("results_providers_col_down")} k="down" {...th} />
                      <Th label={t("results_providers_col_ttd")} k="ttd" {...th} />
                      <Th label={t("results_providers_col_up")} k="up" {...th} />
                    </>
                  ) : null}
                </tr>
              </thead>
              <tbody className="divide-y">
                {rows.map((r) => (
                  <tr key={r.key} className="hover:bg-surface-hover/50">
                    <td className="px-4 py-2 sm:px-5">
                      <span className="flex items-center gap-2">
                        {r.group === "asn" && r.country ? <CountryFlag code={r.country} /> : null}
                        <ProviderName r={r} />
                      </span>
                    </td>
                    <td className="px-2 py-2 text-right">{formatNumber(r.sent)}</td>
                    <td className="px-2 py-2 text-right">
                      {r.answeredPct == null
                        ? t("results_providers_too_recent")
                        : formatPercent(r.answeredPct)}
                    </td>
                    <td className="px-2 py-2 text-right whitespace-nowrap">
                      {r.replyS == null ? (
                        <span className="text-fg-subtle">—</span>
                      ) : (
                        shortDelay(r.replyS)
                      )}
                    </td>
                    <td className="px-2 py-2">
                      <OutcomeBadge outcome={r.best} noAnswer />
                    </td>
                    {showTd ? (
                      <>
                        <td className="px-2 py-2 text-right">
                          {r.td ? (
                            formatNumber(r.td.targets)
                          ) : (
                            <span className="text-fg-subtle">—</span>
                          )}
                        </td>
                        <td className="px-2 py-2 text-right whitespace-nowrap">
                          {r.td && r.td.eligible_48h > 0 ? (
                            t("results_providers_down_of", {
                              down: r.td.down_48h,
                              eligible: r.td.eligible_48h,
                            })
                          ) : (
                            <span className="text-fg-subtle">—</span>
                          )}
                        </td>
                        <td className="px-2 py-2 text-right whitespace-nowrap">
                          {r.td?.ttd_p50_s == null ? (
                            <span className="text-fg-subtle">—</span>
                          ) : (
                            shortDelay(r.td.ttd_p50_s)
                          )}
                        </td>
                        <td className="px-4 py-2 text-right sm:px-5">
                          {r.td ? (
                            formatNumber(r.td.still_up)
                          ) : (
                            <span className="text-fg-subtle">—</span>
                          )}
                        </td>
                      </>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </FindingCard>
  )
}
