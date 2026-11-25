import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowLeft, CircleCheck, CircleDot, FileSearch, Mail } from "lucide-react"
import { Fragment, useState } from "react"
import { Link, useParams } from "react-router"
import { useAuth } from "@/app/auth"
import { TargetStateBadge } from "@/components/results/badges"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { ReadOnlyBadge } from "@/components/read-only-badge"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonCard } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { ApiError } from "@/lib/api"
import { intlLocale, t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { formatAbsolute, formatClock } from "@/lib/format"
import {
  CHANNEL_LABEL,
  DOWN_RESULTS,
  METHOD_LABEL,
  resultKeys,
  resultsApi,
  resultWord,
  ROLE_LABEL,
  type Channel,
  type TargetCheck,
  type TargetDetail,
} from "@/lib/results"
import { defang, describeBounds, describeTarget, shortDelay } from "@/lib/results-sentences"
import { cn } from "@/lib/utils"

const back = () => (
  <Link
    to="/defend/results"
    className="inline-flex items-center gap-1.5 text-fg-muted transition-colors hover:text-fg"
  >
    <ArrowLeft aria-hidden className="size-3.5" />
    {t("results_title")}
  </Link>
)

type Step =
  { kind: "report"; at: string; id: string } | { kind: "check"; at: string; check: TargetCheck }

/** Newest first: every check, and the reports that started the tracking. */
function steps(d: TargetDetail): Step[] {
  const out: Step[] = [
    ...d.links.reports.map((id): Step => ({
      kind: "report",
      at: d.target.reported_at,
      id,
    })),
    ...d.checks.map((c): Step => ({ kind: "check", at: c.checked_at, check: c })),
  ]
  return out.sort((a, b) => b.at.localeCompare(a.at))
}

/** "email, web form, ThreatFox": where the report went, in the active language. */
function channelList(channels: readonly Channel[]): string {
  const names = channels.map((c) =>
    c === "mail"
      ? t("results_target_channel_email")
      : c === "form"
        ? t("results_target_channel_form")
        : CHANNEL_LABEL[c],
  )
  return new Intl.ListFormat(intlLocale(), { style: "long", type: "unit" }).format(names)
}

function StepRow({ s, last }: { s: Step; last: boolean }) {
  const down = s.kind === "check" && DOWN_RESULTS.includes(s.check.outcome)
  const changed = s.kind === "check" && s.check.outcome === "changed"
  const Icon = s.kind === "report" ? Mail : down ? CircleCheck : CircleDot
  return (
    <li className="relative grid grid-cols-[2rem_minmax(0,1fr)] gap-x-3">
      {!last ? (
        <span
          aria-hidden
          className="absolute top-8 bottom-[-1rem] left-4 w-px -translate-x-1/2 bg-border-strong"
        />
      ) : null}
      <span
        aria-hidden
        className="relative z-10 flex size-8 items-center justify-center rounded-full border bg-surface-raised text-fg-muted shadow-sm"
      >
        <Icon className={cn("size-4", down && "text-status-ok", changed && "text-sev-severe")} />
      </span>
      <div className="min-w-0 space-y-0.5 pt-1">
        {s.kind === "report" ? (
          <p className="text-sm text-fg">
            {tNodes(
              "results_target_report_sent",
              {},
              {
                id: (
                  <Link
                    to={`/defend/abuse/${s.id}`}
                    className="font-mono text-xs underline underline-offset-4"
                  >
                    {s.id.slice(0, 8)}
                  </Link>
                ),
              },
            )}
          </p>
        ) : (
          <>
            <p className="text-sm text-fg">
              {resultWord(s.check.outcome)}
              {s.check.http_status ? (
                <span className="ml-2 font-mono text-xs text-fg-muted">
                  HTTP {s.check.http_status}
                </span>
              ) : null}
            </p>
            <p className="text-xs text-fg-muted">
              {METHOD_LABEL[s.check.method]}
              {s.check.sha256 && s.check.outcome === "changed" ? (
                <>
                  {" · "}
                  <Link
                    to={`/malware/samples/${s.check.sha256}`}
                    className="underline underline-offset-4"
                  >
                    {t("results_target_new_sample")}
                  </Link>
                </>
              ) : null}
            </p>
          </>
        )}
        <RelativeTime iso={s.at} className="text-xs" />
      </div>
    </li>
  )
}

const sameCheck = (a: Step, b: Step) =>
  a.kind === "check" &&
  b.kind === "check" &&
  a.check.outcome === b.check.outcome &&
  a.check.method === b.check.method &&
  a.check.http_status === b.check.http_status &&
  a.check.sha256 === b.check.sha256

interface Row {
  step: Step
  folded: Step[]
}

/** Runs of three or more identical checks show the newest one and fold the rest away. */
function fold(list: readonly Step[]): Row[] {
  const rows: Row[] = []
  let i = 0
  while (i < list.length) {
    const first = list.at(i)
    if (!first) break
    let j = i + 1
    while (j < list.length) {
      const next = list.at(j)
      if (!next || !sameCheck(first, next)) break
      j++
    }
    if (first.kind === "check" && j - i >= 3) {
      rows.push({ step: first, folded: list.slice(i + 1, j) })
      i = j
    } else {
      rows.push({ step: first, folded: [] })
      i++
    }
  }
  return rows
}

const dayFmt = () => new Intl.DateTimeFormat(intlLocale(), { month: "short", day: "numeric" })

function Body({ d }: { d: TargetDetail }) {
  const tg = d.target
  const { canWrite } = useAuth()
  const qc = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const done = () => void qc.invalidateQueries({ queryKey: resultKeys.target(tg.id) })
  const fail = (e: unknown) =>
    setError(
      e instanceof ApiError && e.status === 429
        ? t("results_target_recheck_limit")
        : t("results_target_failed"),
    )
  const recheck = useMutation({
    mutationFn: () => resultsApi.recheck(tg.id),
    onSuccess: () => {
      setError(null)
      done()
    },
    onError: fail,
  })
  const stop = useMutation({
    mutationFn: () => resultsApi.stop(tg.id),
    onSuccess: () => {
      setError(null)
      done()
    },
    onError: fail,
  })
  const bounds = describeBounds(d.ttd, formatClock)
  const list = steps(d)
  const rows = fold(list)
  const since = d.checks.filter((c) => c.checked_at >= tg.reported_at).length
  const isUrlTarget = tg.role === "payload_url" || tg.role === "payload_host"
  return (
    <div className="space-y-4 normal-nums">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-xs text-fg-muted">
        <TargetStateBadge state={tg.state} role={tg.role} />
        {/* Role and provider name are in the header line; this row adds what it does not say. */}
        {tg.asn ? (
          <Link to={`/attackers?asn=${tg.asn}`} className="font-mono hover:text-fg">
            AS{tg.asn}
          </Link>
        ) : null}
        <span>
          {tg.channels.length > 0
            ? tNodes(
                "results_target_reported_via",
                { channels: channelList(tg.channels) },
                { time: <RelativeTime iso={tg.reported_at} /> },
              )
            : tNodes(
                "results_target_reported",
                {},
                { time: <RelativeTime iso={tg.reported_at} /> },
              )}
        </span>
        {!tg.tracking ? <span>{t("results_target_tracking_stopped")}</span> : null}
      </div>

      <FindingCard
        eyebrow={t("results_target_what_we_see")}
        finding={describeTarget(d)}
        detail={
          bounds
            ? t("results_target_bounds_detail", {
                bounds: `${bounds.charAt(0).toLocaleUpperCase(intlLocale())}${bounds.slice(1)}`,
              })
            : isUrlTarget
              ? t("results_target_recheck_note")
              : undefined
        }
        action={
          canWrite ? (
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={recheck.isPending || !tg.tracking || tg.role === "c2"}
                onClick={() => recheck.mutate()}
              >
                {t("results_target_check_now")}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                disabled={stop.isPending || !tg.tracking}
                onClick={() => stop.mutate()}
              >
                {t("results_target_stop")}
              </Button>
            </div>
          ) : undefined
        }
      >
        <p role="alert" className="text-sm text-fg empty:hidden">
          {error}
        </p>
        {tg.first_down_at ? (
          <p className="text-sm text-fg-muted">
            {t("results_target_first_down", {
              date: formatAbsolute(tg.first_down_at),
              hasDelay: tg.ttd_s != null ? "yes" : "no",
              delay: tg.ttd_s != null ? shortDelay(tg.ttd_s) : "",
            })}
          </p>
        ) : null}
      </FindingCard>

      <FindingCard
        eyebrow={t("results_target_timeline")}
        finding={t("results_target_timeline_finding", { count: since })}
      >
        <ol className="space-y-4" aria-label={t("results_target_timeline_label")}>
          {rows.map((r, i) => (
            <Fragment key={`${r.step.kind}-${r.step.at}-${i}`}>
              <StepRow s={r.step} last={i === rows.length - 1 && r.folded.length === 0} />
              {r.folded.length > 0 ? (
                <li className="ml-11">
                  <details className="text-sm text-fg-muted">
                    <summary className="cursor-pointer rounded-sm hover:text-fg focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
                      {t("results_target_folded", {
                        count: r.folded.length,
                        from: dayFmt().format(
                          new Date(r.folded[r.folded.length - 1]?.at ?? r.step.at),
                        ),
                        to: dayFmt().format(new Date(r.folded[0]?.at ?? r.step.at)),
                      })}
                    </summary>
                    <ol className="mt-3 space-y-4">
                      {r.folded.map((f, k) => (
                        <StepRow key={`${f.at}-${k}`} s={f} last={k === r.folded.length - 1} />
                      ))}
                    </ol>
                  </details>
                </li>
              ) : null}
            </Fragment>
          ))}
        </ol>
      </FindingCard>

      {d.children.length > 0 ? (
        <FindingCard
          eyebrow={t("results_target_children")}
          finding={t("results_target_children_finding", { count: d.children.length })}
          bodyClassName="px-0 sm:px-0 pb-1 sm:pb-1"
        >
          <ul className="divide-y border-t">
            {d.children.map((c) => (
              <li key={c.id}>
                <Link
                  to={`/defend/results/targets/${c.id}`}
                  className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 hover:bg-surface-hover sm:px-5"
                >
                  <span className="min-w-0 truncate font-mono text-xs text-fg">
                    {defang(c.value)}
                  </span>
                  <TargetStateBadge state={c.state} role={c.role} />
                </Link>
              </li>
            ))}
          </ul>
        </FindingCard>
      ) : null}
    </div>
  )
}

export function ResultsTargetPage() {
  const { id = "" } = useParams()
  const n = Number(id)
  const q = useQuery({
    queryKey: resultKeys.target(n),
    queryFn: () => resultsApi.target(n),
    enabled: Number.isInteger(n) && n > 0,
    retry: false,
  })
  if (q.isError || !Number.isInteger(n)) {
    const gone = !(q.error instanceof ApiError) || q.error.status === 404
    return (
      <>
        <PageHeader title={t("results_target_title")} eyebrow={back()} />
        <EmptyState
          icon={FileSearch}
          title={gone ? t("results_target_gone") : t("results_target_load_error")}
          description={gone ? t("results_target_gone_description") : undefined}
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/defend/results">{t("results_target_back")}</Link>
            </Button>
          }
        />
      </>
    )
  }
  if (!q.data) {
    return (
      <>
        <PageHeader title={t("results_target_title")} eyebrow={back()} />
        <div className="space-y-4" aria-busy>
          <SkeletonCard />
          <SkeletonCard />
        </div>
      </>
    )
  }
  return (
    <>
      <PageHeader
        help="abuse-target"
        eyebrow={back()}
        title={<span className="font-mono text-lg break-all">{defang(q.data.target.value)}</span>}
        description={
          <span className="normal-nums">
            {ROLE_LABEL[q.data.target.role]}
            {q.data.target.provider_name ? ` · ${q.data.target.provider_name}` : ""}
          </span>
        }
        actions={<ReadOnlyBadge />}
      />
      <Body d={q.data} />
    </>
  )
}
