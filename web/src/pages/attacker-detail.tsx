import { useQuery } from "@tanstack/react-query"
import { ArrowLeft, SearchX } from "lucide-react"
import { Link, useParams } from "react-router"
import { intlLocale, t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { useIpMask } from "@/app/ip-mask"
import { subjectProps } from "@/app/view-transitions"
import { Term } from "@/components/term"
import { DayBars } from "@/components/charts/day-bars"
import { CountryFlag } from "@/components/country-flag"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { SessionRow } from "@/components/session-row"
import { SkeletonCard } from "@/components/skeletons"
import { TagBadge } from "@/components/tag-badge"
import { TopList, type TopListItem } from "@/components/top-list"
import { Button } from "@/components/ui/button"
import {
  api,
  ApiError,
  queryKeys,
  type Attacker,
  type CountItem,
  type SessionFilters,
} from "@/lib/api"
import { attackerOrigin, describeAttacker } from "@/lib/describe-attacker"
import { describeTimeline } from "@/lib/findings"
import { LATEST_ROWS } from "@/lib/latest"
import { floodSentence, isFlood, totalConnections } from "@/lib/floods"
import { formatNumber, maskIp, maskIpsInText } from "@/lib/format"

const formatDay = (d: string) =>
  new Intl.DateTimeFormat(intlLocale(), { month: "short", day: "numeric", timeZone: "UTC" }).format(
    new Date(`${d}T00:00:00Z`),
  )

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 space-y-1">
      <dt className="text-xs text-fg-subtle">{label}</dt>
      <dd className="text-sm text-fg">{children}</dd>
    </div>
  )
}

function Reputation({ a }: { a: Attacker }) {
  if (a.abuse_score === null && a.known_scanner === null) {
    return <span className="text-fg-muted">{t("attacker_not_checked")}</span>
  }
  return (
    <span className="flex flex-wrap items-center gap-x-2">
      {a.abuse_score !== null ? (
        <span>
          <Term id="abuse-score">{t("session_abuse_score")}</Term>{" "}
          <span className="tabular-nums">{a.abuse_score}</span> / 100
        </span>
      ) : null}
      {a.known_scanner !== null ? (
        <span className="text-fg-muted">
          {a.known_scanner ? (
            <Term id="known-scanner">{t("session_known_scanner")}</Term>
          ) : (
            t("attacker_not_known_scanner")
          )}
        </span>
      ) : null}
    </span>
  )
}

function countItems(items: readonly CountItem[], param: string, mask: boolean): TopListItem[] {
  const total = items.reduce((n, i) => n + i.count, 0) || 1
  return items.map((i) => {
    const value = mask ? maskIpsInText(i.value) : i.value
    return {
      key: i.value,
      name: value,
      label: <span className="font-mono text-xs">{value}</span>,
      count: i.count,
      share: i.count / total,
      href: `/trends?${param}=${encodeURIComponent(value)}`,
    }
  })
}

export function AttackerDetailPage() {
  const { ip = "" } = useParams()
  const { masked } = useIpMask()
  const q = useQuery({
    queryKey: queryKeys.attacker(ip),
    queryFn: () => api.attacker(ip),
    retry: (n, err) => !(err instanceof ApiError && err.status === 404) && n < 2,
  })

  // How much of it came in floods: the flood groups of this address, summed. One request; more
  // than one page of groups reads "at least".
  const floodFilters: SessionFilters = { src_ip: ip, kind: "burst" }
  const floods = useQuery({
    queryKey: queryKeys.sessions(floodFilters),
    queryFn: () => api.sessions(floodFilters, null, 200),
    enabled: q.isSuccess,
  })
  const floodConnections = floods.data ? totalConnections(floods.data.items) : 0

  const shownIp = masked ? maskIp(ip) : ip
  const back = (
    <Link
      to="/attackers"
      className="inline-flex items-center gap-1 rounded-sm text-fg-muted transition-colors hover:text-fg"
    >
      <ArrowLeft aria-hidden className="size-3.5" /> {t("attacker_all")}
    </Link>
  )

  if (q.isError) {
    const missing = q.error instanceof ApiError && q.error.status === 404
    return (
      <>
        <PageHeader help="attacker" title={shownIp} eyebrow={back} />
        <EmptyState
          icon={SearchX}
          title={missing ? t("attacker_missing_title") : t("attacker_error_title")}
          description={missing ? t("attacker_missing_description") : q.error.message}
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/attackers">{t("attacker_back")}</Link>
            </Button>
          }
        />
      </>
    )
  }

  const d = q.data
  const latest = d?.recent_sessions.slice(0, LATEST_ROWS) ?? []
  const a = d?.attacker
  const origin = a ? attackerOrigin(a) : null
  const story = a
    ? t("attacker_story", {
        hasOrigin: origin ? "yes" : "no",
        origin: origin ?? "",
        description: describeAttacker(a),
      })
    : undefined
  const timeline = d ? describeTimeline(d.timeline, formatDay) : null
  const firstCommand = d?.top_commands[0]?.value
  const sessionsHref = `/attacks?src_ip=${encodeURIComponent(ip)}`

  return (
    <>
      <PageHeader
        help="attacker"
        eyebrow={back}
        title={
          <span {...subjectProps(`attacker:${ip}`)} className="inline-block">
            {shownIp}
          </span>
        }
        description={story ? (masked ? maskIpsInText(story) : story) : t("attacker_loading")}
        actions={
          <Button asChild variant="outline" size="sm">
            <Link to={sessionsHref}>{t("attacker_all_sessions")}</Link>
          </Button>
        }
      />

      {!a ? (
        <div className="space-y-4" role="status" aria-label={t("common_loading")}>
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : (
        <div className="space-y-4">
          <FindingCard
            eyebrow={t("attacker_profile")}
            finding={
              // The flood clause follows the sessions it counts, never the events.
              tNodes(
                "attacker_profile_finding",
                {
                  sessions: a.sessions,
                  events: a.events,
                  hasFloods: floodConnections > 0 ? "yes" : "no",
                },
                {
                  floods: (
                    <Link
                      to={`${sessionsHref}&kind=burst`}
                      className="underline decoration-border-strong underline-offset-4 transition-colors hover:decoration-fg"
                    >
                      {floodSentence(floodConnections, floods.data?.next_cursor != null)}
                    </Link>
                  ),
                },
              )
            }
          >
            <dl className="grid grid-cols-2 gap-x-6 gap-y-5 md:grid-cols-4">
              <Fact label={t("attacker_first_seen")}>
                <RelativeTime iso={a.first_seen} className="text-sm text-fg" />
              </Fact>
              <Fact label={t("attacker_last_seen")}>
                <RelativeTime iso={a.last_seen} className="text-sm text-fg" />
              </Fact>
              <Fact label={t("attacker_sensors")}>
                <span className="flex flex-wrap gap-1.5">
                  {a.sensors.map((s) => (
                    <Link
                      key={s}
                      to={`/attacks?sensor=${s}&src_ip=${encodeURIComponent(a.ip)}`}
                      className="rounded-sm"
                    >
                      <SensorBadge sensor={s} />
                    </Link>
                  ))}
                </span>
              </Fact>
              <Fact label={t("attacker_origin")}>
                <span className="flex flex-wrap items-center gap-2">
                  {a.country ? (
                    <Link
                      to={`/attackers?country=${encodeURIComponent(a.country)}`}
                      className="rounded-sm hover:underline hover:underline-offset-4"
                    >
                      <CountryFlag code={a.country} showName className="text-fg" />
                    </Link>
                  ) : (
                    <span className="text-fg-muted">{t("common_unknown")}</span>
                  )}
                  {a.city ? <span className="text-fg-muted">{a.city}</span> : null}
                </span>
              </Fact>
              <Fact label={t("attacker_network")}>
                {a.asn !== null ? (
                  <Link
                    to={`/attackers?asn=${a.asn}`}
                    className="rounded-sm hover:underline hover:underline-offset-4"
                  >
                    <span className="font-mono text-xs text-fg-muted">AS{a.asn}</span> {a.org}
                  </Link>
                ) : (
                  <span className="text-fg-muted">{t("common_unknown")}</span>
                )}
              </Fact>
              <Fact label={t("attacker_reputation")}>
                <Reputation a={a} />
              </Fact>
              <Fact label={t("attacker_logins")}>
                <span className="tabular-nums">{formatNumber(a.login_attempts)}</span>
                <span className="text-fg-muted">
                  {" "}
                  ·{" "}
                  {t("attacker_logins_succeeded", { count: a.login_success })}
                </span>
              </Fact>
              <Fact label={t("attacker_cmds_downloads")}>
                <span className="text-fg-muted">
                  {tNodes(
                    "attacker_cmds_files",
                    { commandsCount: a.commands, filesCount: a.downloads },
                    {
                      commands: <span className="text-fg tabular-nums">{formatNumber(a.commands)}</span>,
                      files: <span className="text-fg tabular-nums">{formatNumber(a.downloads)}</span>,
                    },
                  )}
                </span>
              </Fact>
              {a.tags.length ? (
                <div className="col-span-2 space-y-1 md:col-span-4">
                  <dt className="text-xs text-fg-subtle">{t("attacker_tags")}</dt>
                  <dd className="flex flex-wrap gap-1.5">
                    {a.tags.map((tag) => (
                      <TagBadge
                        key={tag}
                        tag={tag}
                        href={`/attackers?tag=${encodeURIComponent(tag)}`}
                      />
                    ))}
                  </dd>
                </div>
              ) : null}
            </dl>
          </FindingCard>

          <FindingCard eyebrow={t("attacker_activity")} finding={timeline?.finding ?? ""}>
            <DayBars points={d.timeline} />
          </FindingCard>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <FindingCard
              eyebrow={t("creds_usernames_label")}
              finding={
                d.top_usernames[0]
                  ? t("attacker_favourite_username", { value: d.top_usernames[0].value })
                  : t("attacker_no_username")
              }
            >
              <TopList
                items={countItems(d.top_usernames, "username", masked)}
                empty={t("attacker_no_logins")}
              />
            </FindingCard>
            <FindingCard
              eyebrow={t("attacker_commands_eyebrow")}
              finding={
                firstCommand
                  ? t("attacker_top_command", {
                      value: masked ? maskIpsInText(firstCommand) : firstCommand,
                    })
                  : t("attacker_no_shell")
              }
            >
              <TopList
                items={countItems(d.top_commands, "command", masked)}
                empty={t("attacker_no_commands")}
              />
            </FindingCard>
          </div>

          <FindingCard
            eyebrow={t("attacker_recent")}
            finding={
              latest.length === 1
                ? latest.some(isFlood)
                  ? t("attacker_recent_only_flood")
                  : t("attacker_recent_only")
                : latest.some(isFlood)
                  ? t("attacker_recent_last_with_floods", { count: latest.length })
                  : t("attacker_recent_last", { count: latest.length })
            }
            action={
              <Button asChild variant="ghost" size="sm">
                <Link to={sessionsHref}>{t("attacker_see_all")}</Link>
              </Button>
            }
            bodyClassName="p-0 sm:p-0 pt-4 sm:pt-4"
          >
            <ul aria-label={t("attacker_recent")} className="border-t">
              {latest.map((s, i) => (
                <li key={s.session_id} className={i > 0 ? "border-t" : undefined}>
                  <SessionRow session={s} showSource={false} />
                </li>
              ))}
            </ul>
          </FindingCard>
        </div>
      )}
    </>
  )
}
