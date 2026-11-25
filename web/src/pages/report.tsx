import { useQuery } from "@tanstack/react-query"
import { ArrowLeft, FileText, Printer, ShieldCheck } from "lucide-react"
import { Link, useParams } from "react-router"
import { ALERTS_SETTINGS } from "@/app/nav"
import { CountryFlag } from "@/components/country-flag"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { SkeletonText } from "@/components/skeletons"
import { StatTile } from "@/components/stat-tile"
import { TagBadge } from "@/components/tag-badge"
import { TopList, type TopListItem } from "@/components/top-list"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { alertKeys, alertsApi, reportHtmlUrl, weekLabel, type ReportSummary } from "@/lib/alerts"
import { ApiError } from "@/lib/api"
import { t } from "@/i18n"
import { countryName, formatAbsolute, formatNumber } from "@/lib/format"
import { sensorMeta } from "@/lib/sensors"

const WEEK = /^\d{4}-\d{2}-\d{2}$/

/** Rows of one summary list as TopList items; the share is against the week's sessions. */
function items<T>(
  rows: readonly T[] | undefined,
  total: number,
  pick: (row: T) => Omit<TopListItem, "share">,
): TopListItem[] {
  return (rows ?? []).map((r) => {
    const item = pick(r)
    return { ...item, share: total > 0 ? item.count / total : 0 }
  })
}

function SensorLabel({ sensor }: { sensor: string }) {
  const meta = sensorMeta(sensor)
  const Icon = meta?.icon
  return (
    <span className="inline-flex items-center gap-2">
      {Icon ? <Icon aria-hidden className={`size-3.5 ${meta.text}`} strokeWidth={2} /> : null}
      {meta?.label ?? sensor}
    </span>
  )
}

/** The plain-text list a report section turns into, with a one-line finding first. */
function Section({
  eyebrow,
  finding,
  list,
  empty,
}: {
  eyebrow: string
  finding: string
  list: TopListItem[]
  empty: string
}) {
  return (
    <FindingCard eyebrow={eyebrow} finding={list.length ? finding : empty}>
      {list.length ? <TopList items={list} rows={list.length} /> : null}
    </FindingCard>
  )
}

/** A weekly report, drawn with the design system from its stored summary (text only). */
function ReportBody({ summary: s, createdAt }: { summary: ReportSummary; createdAt: string }) {
  const tot = s.totals ?? {}
  const total = tot.sessions ?? 0
  const change = tot.change_pct ?? null
  const actions = s.actions ?? []

  const sensors = items(s.by_sensor, total, (r) => ({
    key: r.sensor,
    name: sensorMeta(r.sensor)?.label ?? r.sensor,
    label: <SensorLabel sensor={r.sensor} />,
    count: r.sessions,
    href: `/attacks?sensor=${encodeURIComponent(r.sensor)}`,
  }))
  const countries = items(s.countries, total, (r) => ({
    key: r.country,
    name: countryName(r.country) ?? r.country,
    label: <CountryFlag code={r.country} showName className="text-fg" />,
    count: r.sessions,
    href: `/attacks?country=${encodeURIComponent(r.country)}`,
  }))
  const tags = items(s.tags, total, (r) => ({
    key: r.tag,
    name: r.tag,
    label: <TagBadge tag={r.tag} href={null} />,
    count: r.sessions,
    href: `/attacks?tag=${encodeURIComponent(r.tag)}`,
  }))
  // Shares within the list: a CVE or a campaign is a small slice of all sessions, so "0%" would say nothing.
  const sum = (rows: readonly { sessions: number }[] | undefined) =>
    (rows ?? []).reduce((n, r) => n + r.sessions, 0)
  const cves = items(s.watched_cves, sum(s.watched_cves), (r) => ({
    key: r.cve_id,
    name: r.cve_id,
    label: <span className="font-mono text-xs">{r.cve_id}</span>,
    count: r.sessions,
    href: `/cves?q=${encodeURIComponent(r.cve_id)}`,
  }))
  const campaigns = items(s.campaigns, sum(s.campaigns), (r) => ({
    key: String(r.id),
    name: r.name,
    label: (
      <span>
        {r.name}
        <span className="text-fg-muted"> · {t("report_campaign_sources", { count: r.sources })}</span>
      </span>
    ),
    count: r.sessions,
    href: `/campaigns/${encodeURIComponent(String(r.id))}`,
  }))
  // Defanged indicators stay plain text: never a link, never something to click by mistake.
  const hosts = items(s.download_hosts, 0, (r) => ({
    key: r.host,
    name: r.host,
    label: <span className="font-mono text-xs break-all">{r.host}</span>,
    count: r.sightings,
  }))

  const top = (list: TopListItem[], say: (first: TopListItem) => string) =>
    list[0] ? say(list[0]) : ""

  return (
    <div className="space-y-4 sm:space-y-6">
      <section aria-label={t("report_key_figures")} className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <StatTile
          label={t("report_tile_sessions")}
          value={total}
          delta={change === null ? null : change / 100}
          deltaLabel={t("report_tile_delta")}
          hint={t("report_tile_sessions_hint")}
        />
        <StatTile
          label={t("report_tile_addresses")}
          value={tot.sources ?? 0}
          hint={t("report_tile_addresses_hint")}
        />
        <StatTile
          label={t("report_tile_commands")}
          value={tot.with_commands ?? 0}
          hint={t("report_tile_commands_hint")}
        />
        <StatTile
          label={t("report_tile_malware")}
          value={tot.malware ?? 0}
          hint={t("report_tile_malware_hint")}
        />
      </section>

      <FindingCard
        eyebrow={t("report_actions_eyebrow")}
        finding={t("report_actions_finding", { count: actions.length })}
      >
        <ol className="space-y-2.5">
          {actions.map((a, i) => (
            <li key={i} className="flex animate-slide-in gap-3 text-sm text-fg">
              <span
                aria-hidden
                className="mt-px grid size-5 shrink-0 place-items-center rounded-full border text-2xs font-medium text-fg-muted"
              >
                {i + 1}
              </span>
              <span className="min-w-0 text-pretty">{a}</span>
            </li>
          ))}
        </ol>
      </FindingCard>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Section
          eyebrow={t("report_services_eyebrow")}
          finding={top(
            sensors,
            (f) =>
              t("report_services_finding", { name: f.name, percent: Math.round(f.share * 100) }),
          )}
          list={sensors}
          empty={t("report_services_empty")}
        />
        <Section
          eyebrow={t("report_countries_eyebrow")}
          finding={top(countries, (f) => t("report_countries_finding", { name: f.name }))}
          list={countries}
          empty={t("report_countries_empty")}
        />
        <Section
          eyebrow={t("report_tags_eyebrow")}
          finding={top(
            tags,
            (f) => t("report_tags_finding", { name: f.name, count: f.count }),
          )}
          list={tags}
          empty={t("report_tags_empty")}
        />
        <Section
          eyebrow={t("report_cves_eyebrow")}
          finding={t("report_cves_finding", { count: cves.length })}
          list={cves}
          empty={t("report_cves_empty")}
        />
        <Section
          eyebrow={t("report_campaigns_eyebrow")}
          finding={t("report_campaigns_finding", { count: campaigns.length })}
          list={campaigns}
          empty={t("report_campaigns_empty")}
        />
        <FindingCard
          eyebrow={t("report_hosts_eyebrow")}
          finding={
            hosts.length
              ? t("report_hosts_finding", { count: hosts.length })
              : t("report_hosts_empty")
          }
          detail={hosts.length ? t("report_hosts_detail") : undefined}
        >
          {hosts.length ? (
            <ul className="divide-y">
              {hosts.map((h) => (
                <li key={h.key} className="flex items-baseline gap-3 py-2 first:pt-0 last:pb-0">
                  <span className="min-w-0 flex-1 text-fg">{h.label}</span>
                  <span className="shrink-0 text-sm text-fg">
                    {formatNumber(h.count)}
                    <span className="sr-only"> {t("report_hosts_times_seen")}</span>
                  </span>
                </li>
              ))}
            </ul>
          ) : null}
        </FindingCard>
      </div>

      <p className="flex items-start gap-2 text-xs text-fg-subtle">
        <ShieldCheck aria-hidden className="mt-px size-3.5 shrink-0" />
        <span>
          {t("report_footer", {
            timezone: s.timezone ?? "UTC",
            date: formatAbsolute(createdAt),
          })}
        </span>
      </p>
    </div>
  )
}

function ReportSkeleton() {
  return (
    <div className="space-y-4 sm:space-y-6" aria-busy>
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-[104px] rounded-lg" />
        ))}
      </div>
      <div className="rounded-lg border p-5">
        <SkeletonText lines={4} />
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Skeleton className="h-64 rounded-lg" />
        <Skeleton className="h-64 rounded-lg" />
      </div>
    </div>
  )
}

/**
 * One weekly report. The page draws the stored summary with the design system (every value is
 * text); the printable version is the plain HTML page written by the server, opened on its own
 * so the browser can print it or save it as a PDF.
 */
export function ReportPage() {
  const { week = "" } = useParams()
  const valid = WEEK.test(week)
  const q = useQuery({
    queryKey: alertKeys.report(week),
    queryFn: () => alertsApi.report(week),
    enabled: valid,
    retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 2,
  })
  const back = (
    <Link to={ALERTS_SETTINGS} className="inline-flex items-center gap-1 hover:text-fg">
      <ArrowLeft aria-hidden className="size-3.5" />
      {t("report_back")}
    </Link>
  )
  if (!valid || (q.isError && q.error instanceof ApiError && q.error.status === 404)) {
    return (
      <>
        <PageHeader help="report" title={t("report_title")} eyebrow={back} />
        <EmptyState
          icon={FileText}
          title={t("report_missing_title")}
          description={t("report_missing_description")}
          action={
            <Button variant="outline" asChild>
              <Link to={ALERTS_SETTINGS}>{t("report_missing_back")}</Link>
            </Button>
          }
        />
      </>
    )
  }
  const headline = q.data?.summary.headline
  return (
    <>
      <PageHeader
        help="report"
        title={t("report_week_of", { week: weekLabel(week, q.data?.summary.week_end ?? null) })}
        eyebrow={back}
        description={headline ?? (q.isError ? undefined : t("report_loading"))}
        actions={
          <Button variant="outline" size="sm" asChild>
            <a href={reportHtmlUrl(week)} target="_blank" rel="noopener noreferrer">
              <Printer aria-hidden />
              {t("report_print")}
            </a>
          </Button>
        }
      />
      {q.isPending ? (
        <ReportSkeleton />
      ) : q.isError ? (
        <EmptyState
          icon={FileText}
          title={t("report_error_title")}
          description={t("report_error_description")}
        />
      ) : (
        <ReportBody summary={q.data.summary} createdAt={q.data.created_at} />
      )}
    </>
  )
}
