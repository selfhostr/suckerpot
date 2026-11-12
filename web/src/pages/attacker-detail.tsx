import { useQuery } from "@tanstack/react-query"
import { ArrowLeft, SearchX } from "lucide-react"
import { Link, useParams } from "react-router"
import { useIpMask } from "@/app/ip-mask"
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
import { floodSentence, isFlood, totalConnections } from "@/lib/floods"
import { formatNumber, maskIp, maskIpsInText } from "@/lib/format"

const dayFmt = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" })
const formatDay = (d: string) => dayFmt.format(new Date(`${d}T00:00:00Z`))

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
    return <span className="text-fg-muted">Not checked yet</span>
  }
  return (
    <span className="flex flex-wrap items-center gap-x-2">
      {a.abuse_score !== null ? (
        <span>
          <Term id="abuse-score">Abuse score</Term>{" "}
          <span className="tabular-nums">{a.abuse_score}</span> / 100
        </span>
      ) : null}
      {a.known_scanner !== null ? (
        <span className="text-fg-muted">
          {a.known_scanner ? <Term id="known-scanner">Known scanner</Term> : "Not a known scanner"}
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
      <ArrowLeft aria-hidden className="size-3.5" /> All attackers
    </Link>
  )

  if (q.isError) {
    const missing = q.error instanceof ApiError && q.error.status === 404
    return (
      <>
        <PageHeader help="attacker" title={shownIp} eyebrow={back} />
        <EmptyState
          icon={SearchX}
          title={missing ? "No sensor has seen this address" : "Could not load this attacker"}
          description={
            missing
              ? "It may be older than the retention window, or the address is mistyped."
              : q.error.message
          }
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/attackers">Back to attackers</Link>
            </Button>
          }
        />
      </>
    )
  }

  const d = q.data
  const a = d?.attacker
  const origin = a ? attackerOrigin(a) : null
  const story = a ? `${origin ? `${origin} — ` : ""}${describeAttacker(a)}.` : undefined
  const timeline = d ? describeTimeline(d.timeline, formatDay) : null
  const firstCommand = d?.top_commands[0]?.value
  const sessionsHref = `/attacks?src_ip=${encodeURIComponent(ip)}`

  return (
    <>
      <PageHeader
        help="attacker"
        eyebrow={back}
        title={shownIp}
        description={story ? (masked ? maskIpsInText(story) : story) : "Loading the profile…"}
        actions={
          <Button asChild variant="outline" size="sm">
            <Link to={sessionsHref}>All sessions</Link>
          </Button>
        }
      />

      {!a ? (
        <div className="space-y-4" role="status" aria-label="Loading">
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : (
        <div className="space-y-4">
          <FindingCard
            eyebrow="Profile"
            finding={
              // The flood clause follows the sessions it counts, never the events.
              <>
                {`${formatNumber(a.sessions)} ${a.sessions === 1 ? "session" : "sessions"}`}
                {floodConnections > 0 ? (
                  <>
                    {", "}
                    <Link
                      to={`${sessionsHref}&kind=burst`}
                      className="underline decoration-border-strong underline-offset-4 transition-colors hover:decoration-fg"
                    >
                      {floodSentence(floodConnections, floods.data?.next_cursor != null)}
                    </Link>
                    {","}
                  </>
                ) : null}
                {` and ${formatNumber(a.events)} events recorded.`}
              </>
            }
          >
            <dl className="grid grid-cols-2 gap-x-6 gap-y-5 md:grid-cols-4">
              <Fact label="First seen">
                <RelativeTime iso={a.first_seen} className="text-sm text-fg" />
              </Fact>
              <Fact label="Last seen">
                <RelativeTime iso={a.last_seen} className="text-sm text-fg" />
              </Fact>
              <Fact label="Sensors targeted">
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
              <Fact label="Origin">
                <span className="flex flex-wrap items-center gap-2">
                  {a.country ? (
                    <Link
                      to={`/attackers?country=${encodeURIComponent(a.country)}`}
                      className="rounded-sm hover:underline hover:underline-offset-4"
                    >
                      <CountryFlag code={a.country} showName className="text-fg" />
                    </Link>
                  ) : (
                    <span className="text-fg-muted">Unknown</span>
                  )}
                  {a.city ? <span className="text-fg-muted">{a.city}</span> : null}
                </span>
              </Fact>
              <Fact label="Network">
                {a.asn !== null ? (
                  <Link
                    to={`/attackers?asn=${a.asn}`}
                    className="rounded-sm hover:underline hover:underline-offset-4"
                  >
                    <span className="font-mono text-xs text-fg-muted">AS{a.asn}</span> {a.org}
                  </Link>
                ) : (
                  <span className="text-fg-muted">Unknown</span>
                )}
              </Fact>
              <Fact label="Reputation">
                <Reputation a={a} />
              </Fact>
              <Fact label="Login attempts">
                <span className="tabular-nums">{formatNumber(a.login_attempts)}</span>
                <span className="text-fg-muted">
                  {" "}
                  ·{" "}
                  {a.login_success > 0
                    ? `${formatNumber(a.login_success)} succeeded`
                    : "none succeeded"}
                </span>
              </Fact>
              <Fact label="Commands and downloads">
                <span className="tabular-nums">{formatNumber(a.commands)}</span>
                <span className="text-fg-muted"> commands · </span>
                <span className="tabular-nums">{formatNumber(a.downloads)}</span>
                <span className="text-fg-muted"> files</span>
              </Fact>
              {a.tags.length ? (
                <div className="col-span-2 space-y-1 md:col-span-4">
                  <dt className="text-xs text-fg-subtle">Tags</dt>
                  <dd className="flex flex-wrap gap-1.5">
                    {a.tags.map((t) => (
                      <TagBadge key={t} tag={t} href={`/attackers?tag=${encodeURIComponent(t)}`} />
                    ))}
                  </dd>
                </div>
              ) : null}
            </dl>
          </FindingCard>

          <FindingCard eyebrow="Activity, last 30 days" finding={timeline?.finding ?? ""}>
            <DayBars points={d.timeline} />
          </FindingCard>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <FindingCard
              eyebrow="Usernames tried"
              finding={
                d.top_usernames[0]
                  ? `"${d.top_usernames[0].value}" was its favourite username.`
                  : "It never tried a username."
              }
            >
              <TopList
                items={countItems(d.top_usernames, "username", masked)}
                empty="No login attempts."
              />
            </FindingCard>
            <FindingCard
              eyebrow="Commands run"
              finding={
                firstCommand
                  ? `Its most common command was "${masked ? maskIpsInText(firstCommand) : firstCommand}".`
                  : "It never got a shell, so it ran no commands."
              }
            >
              <TopList items={countItems(d.top_commands, "command", masked)} empty="No commands." />
            </FindingCard>
          </div>

          <FindingCard
            eyebrow="Recent sessions"
            finding={
              d.recent_sessions.length === 1
                ? d.recent_sessions.some(isFlood)
                  ? "Its only flood group so far."
                  : "Its only session so far."
                : d.recent_sessions.some(isFlood)
                  ? `Its last ${d.recent_sessions.length} sessions and flood groups, newest first.`
                  : `Its last ${d.recent_sessions.length} sessions, newest first.`
            }
            action={
              <Button asChild variant="ghost" size="sm">
                <Link to={sessionsHref}>View all</Link>
              </Button>
            }
            bodyClassName="p-0 sm:p-0 pt-4 sm:pt-4"
          >
            <ul aria-label="Recent sessions" className="border-t">
              {d.recent_sessions.map((s, i) => (
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
