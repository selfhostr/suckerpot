import { PageHelp } from "@/components/page-help"
import { useQuery } from "@tanstack/react-query"
import { ArrowLeft, FileQuestion, TerminalSquare } from "lucide-react"
import { lazy, Suspense, useMemo, useState } from "react"
import { Link, useParams, useSearchParams } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { Term } from "@/components/term"
import { CountryFlag } from "@/components/country-flag"
import { CampaignChip } from "@/components/campaigns/campaign-chip"
import { CredentialsCard } from "@/components/credentials-card"
import { EmptyState } from "@/components/empty-state"
import { EventTimeline } from "@/components/event-timeline"
import { FindingCard } from "@/components/finding-card"
import { FloodBadge } from "@/components/flood-badge"
import { IPChip } from "@/components/ip-chip"
import { SensorBadge } from "@/components/sensor-badge"
import { SessionStory } from "@/components/session-story"
import { SiblingGroupsCard } from "@/components/sibling-groups-card"
import { SeverityBadge } from "@/components/severity-badge"
import { SkeletonList, SkeletonText } from "@/components/skeletons"
import { TagBadge } from "@/components/tag-badge"
import { replayFromEvents, type ReplaySource } from "@/components/replay/frames"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError, api, queryKeys, type SensorEvent, type Session } from "@/lib/api"
import { connectionsOf, floodFinding, floodSpanLong, isFlood, parseAt } from "@/lib/floods"
import { formatAbsolute, formatDuration, formatNumber, plural } from "@/lib/format"
import { sessionSeverity } from "@/lib/severity"
import { cn } from "@/lib/utils"

// xterm.js is heavy and only this page needs it: load it on demand.
const TerminalReplay = lazy(() =>
  import("@/components/replay/terminal-replay").then((m) => ({ default: m.TerminalReplay })),
)

/** The API pages events 200 at a time; the replay needs the last one (disconnect), so read them all. */
const EVENT_PAGE = 200
const MAX_EVENT_PAGES = 50

async function fetchAllEvents(sessionId: string): Promise<SensorEvent[]> {
  const items: SensorEvent[] = []
  let cursor: string | null = null
  for (let page = 0; page < MAX_EVENT_PAGES; page++) {
    const res = await api.sessionEvents(sessionId, cursor, EVENT_PAGE)
    items.push(...res.items)
    if (!res.next_cursor) break
    cursor = res.next_cursor
  }
  return items
}

/** A flood group can stand for thousands of events: the page shows the first ones only. */
async function fetchFirstEvents(sessionId: string): Promise<SensorEvent[]> {
  return (await api.sessionEvents(sessionId, null, EVENT_PAGE)).items
}

const REPLAY_SENSORS = new Set(["ssh", "telnet"])

function replayFinding(source: ReplaySource, commands: number): string {
  const seconds = source.frames.reduce((n, f) => n + f[0], 0)
  const span = formatDuration(seconds)
  if (source.reconstructed) {
    return `${plural(commands, "command")} rebuilt from the session log, about ${span} of activity.`
  }
  return commands
    ? `${plural(commands, "command")} typed over ${span}, replayed here at real speed.`
    : `${span} of terminal output, replayed here at real speed.`
}

function durationOf(s: Session): string {
  const end = s.ended_at ?? s.last_event_at
  return formatDuration((Date.parse(end) - Date.parse(s.started_at)) / 1000)
}

function timelineFinding(s: Session): string {
  const parts: string[] = []
  if (s.login_attempts) parts.push(plural(s.login_attempts, "login attempt"))
  if (s.commands) parts.push(plural(s.commands, "command"))
  if (s.downloads) parts.push(plural(s.downloads, "download attempt"))
  if (s.http_requests) parts.push(plural(s.http_requests, "HTTP request"))
  const what = parts.length ? parts.join(", ") : plural(s.event_count, "event")
  return `${what} in ${durationOf(s)}.`
}

/** A flood group loads its first 200 events; the timeline opens on the first few of them. */
const FLOOD_EVENTS_SHOWN = 40

function floodTimelineFinding(shown: number, total: number): string {
  return shown >= total
    ? `All ${formatNumber(total)} events of the group, in time order.`
    : `The first ${formatNumber(shown)} of ${formatNumber(total)} events of the group, in time order.`
}

function Meta({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="min-w-0 space-y-1">
      <dt className="text-xs text-fg-muted">{label}</dt>
      <dd className="text-sm font-medium break-words text-fg">{children}</dd>
    </div>
  )
}

export function SessionDetailPage() {
  const { sessionId = "" } = useParams()
  // A link from an event carries its time: a connection that was folded into a flood group has no
  // page of its own, and the API answers with the group that holds it.
  const [searchParams] = useSearchParams()
  const at = parseAt(searchParams.get("at"))
  const [showAllEvents, setShowAllEvents] = useState(false)
  const session = useQuery({
    queryKey: queryKeys.session(sessionId, at),
    queryFn: () => api.session(sessionId, at),
    retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 2,
  })
  const s = session.data
  const flood = s ? isFlood(s) : false
  // Everything below reads the row the API returned, which is the group for a folded connection.
  const rowId = s?.session_id ?? sessionId
  const events = useQuery({
    queryKey: queryKeys.sessionEvents(rowId),
    queryFn: () => (flood ? fetchFirstEvents(rowId) : fetchAllEvents(rowId)),
    enabled: session.isSuccess,
  })
  const { masked } = useIpMask()
  const eventList = events.data
  const replay = useMemo(
    () => (eventList && !flood ? replayFromEvents(eventList) : null),
    [eventList, flood],
  )
  const commandCount = eventList?.filter((e) => e.type === "command").length ?? 0

  const back = (
    <Link
      to="/attacks"
      className="inline-flex items-center gap-1.5 text-xs text-fg-muted transition-colors hover:text-fg"
    >
      <ArrowLeft aria-hidden className="size-3.5" /> Attacks
    </Link>
  )

  if (session.isError) {
    const notFound = session.error instanceof ApiError && session.error.status === 404
    return (
      <>
        <div className="pb-6">{back}</div>
        <EmptyState
          icon={FileQuestion}
          title={notFound ? "Session not found" : "Could not load this session"}
          description={
            notFound ? "It may have been removed by the retention job." : session.error.message
          }
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/attacks">Back to attacks</Link>
            </Button>
          }
        />
      </>
    )
  }

  const clientTool =
    s?.sensor === "rdp" && s.client_tool && s.client_tool !== "unknown" ? s.client_tool : null
  return (
    <>
      <header className="space-y-4 pb-6">
        {back}
        {s ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <SensorBadge sensor={s.sensor} />
              {flood ? <FloodBadge connections={connectionsOf(s)} /> : null}
              <SeverityBadge severity={sessionSeverity(s)} />
              {s.tags.map((t) => (
                <TagBadge key={t} tag={t} />
              ))}
            </div>
            {s.campaign_id ? <CampaignChip id={s.campaign_id} /> : null}
            <div className="flex items-start gap-1.5">
              <h1 className="min-w-0 text-lg font-medium text-pretty sm:text-xl">
                <span className="sr-only">
                  {flood ? "Flood group" : "Session"} {s.session_id}:{" "}
                </span>
                <SessionStory session={s} layout="block" />
              </h1>
              <PageHelp id="session" className="mt-0.5" />
            </div>
            {flood ? (
              <p className="max-w-3xl text-sm text-pretty text-fg-muted">
                {floodFinding(s)}
                {s.folded_from ? (
                  <>
                    {" "}
                    The connection you opened (<span className="font-mono">{s.folded_from}</span>)
                    is one of them.
                  </>
                ) : null}
              </p>
            ) : null}
          </>
        ) : (
          <SkeletonText lines={2} className="max-w-xl" />
        )}
      </header>

      {s && flood ? (
        // A group has no single start, port or id worth reading: its figures are the window it
        // covers and the totals of the connections it stands for. The source port is always 0.
        <dl className="mb-6 grid grid-cols-2 gap-x-6 gap-y-4 rounded-lg border bg-surface p-4 shadow-sm sm:grid-cols-3 sm:p-5 lg:grid-cols-[minmax(0,1.5fr)_repeat(4,minmax(0,1fr))]">
          {/* The value names the time zone, so the label does not repeat it. */}
          <Meta label="Window">{floodSpanLong(s)}</Meta>
          <Meta label="Connections">{formatNumber(connectionsOf(s))}</Meta>
          <Meta label="Logins tried">{formatNumber(s.login_attempts)}</Meta>
          <Meta label="Events">{formatNumber(s.event_count)}</Meta>
          <Meta label="Port">
            <span className="font-mono text-xs">{s.dst_port}</span>
          </Meta>
        </dl>
      ) : s ? (
        <dl
          className={cn(
            "mb-6 grid grid-cols-2 gap-x-6 gap-y-4 rounded-lg border bg-surface p-4 shadow-sm sm:grid-cols-3 sm:p-5",
            // Six cells: "Started" (a full date and time zone) gets more room so it stays on one line.
            clientTool
              ? "lg:grid-cols-[minmax(0,1.5fr)_repeat(5,minmax(0,1fr))]"
              : "lg:grid-cols-5",
          )}
        >
          <Meta label="Started">{formatAbsolute(s.started_at)}</Meta>
          <Meta label="Duration">{s.ended_at ? durationOf(s) : "Still connected"}</Meta>
          <Meta label="Events">{formatNumber(s.event_count)}</Meta>
          {clientTool ? <Meta label="Client">{clientTool}</Meta> : null}
          <Meta label="Ports">
            <span className="font-mono text-xs">
              {s.src_port} → {s.dst_port}
            </span>
          </Meta>
          <Meta label="Session ID">
            <span className="font-mono text-xs">{s.session_id}</span>
          </Meta>
        </dl>
      ) : null}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          {s && flood && s.login_attempts > 0 ? <CredentialsCard sessionId={s.session_id} /> : null}

          {s && !flood && REPLAY_SENSORS.has(s.sensor) ? (
            <FindingCard
              eyebrow="Terminal replay"
              finding={
                events.isPending
                  ? "Loading the recording…"
                  : replay
                    ? replayFinding(replay, commandCount)
                    : "No commands were run, so there is nothing to replay."
              }
            >
              {events.isPending ? (
                <Skeleton className="h-64 w-full sm:h-80" />
              ) : events.isError ? (
                <p className="text-sm text-fg-muted">Could not load the recording.</p>
              ) : replay ? (
                <Suspense fallback={<Skeleton className="h-64 w-full sm:h-80" />}>
                  <TerminalReplay source={replay} masked={masked} />
                </Suspense>
              ) : (
                <EmptyState
                  variant="bare"
                  icon={TerminalSquare}
                  title="Nothing was typed"
                  description="The client connected but never ran a command."
                  className="py-8"
                />
              )}
            </FindingCard>
          ) : null}

          <FindingCard
            eyebrow={flood ? "First events" : "Timeline"}
            finding={
              !s
                ? "Loading the timeline…"
                : flood
                  ? events.data
                    ? floodTimelineFinding(events.data.length, s.event_count)
                    : "Loading the first events…"
                  : timelineFinding(s)
            }
            bodyClassName="px-0 sm:px-0 pt-3 pb-2 sm:pb-2"
            footer={
              flood && events.data && events.data.length > FLOOD_EVENTS_SHOWN ? (
                <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
                  <span>
                    {showAllEvents
                      ? `All ${formatNumber(events.data.length)} loaded events are shown.`
                      : `Showing the first ${FLOOD_EVENTS_SHOWN} of ${formatNumber(events.data.length)} loaded events.`}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    aria-expanded={showAllEvents}
                    onClick={() => setShowAllEvents((open) => !open)}
                  >
                    {showAllEvents ? "Show fewer" : `Show all ${formatNumber(events.data.length)}`}
                  </Button>
                </div>
              ) : undefined
            }
          >
            {events.isPending ? (
              <SkeletonList rows={6} />
            ) : events.isError ? (
              <p className="px-5 py-6 text-sm text-fg-muted">Could not load events.</p>
            ) : (
              <EventTimeline
                events={
                  flood && !showAllEvents ? events.data.slice(0, FLOOD_EVENTS_SHOWN) : events.data
                }
              />
            )}
          </FindingCard>
        </div>

        <div className="space-y-4 self-start">
          <FindingCard
            eyebrow="Source"
            finding={
              s ? (
                <span className="inline-flex flex-wrap items-center gap-2">
                  <IPChip ip={s.src_ip} />
                  {s.country ? <CountryFlag code={s.country} showName /> : null}
                </span>
              ) : (
                "…"
              )
            }
            detail={s?.org ? `${s.org}${s.asn ? ` · AS${s.asn}` : ""}` : "Not enriched yet"}
          >
            <dl className="grid grid-cols-2 gap-4">
              <Meta label={<Term id="abuse-score">Abuse score</Term>}>
                {s?.abuse_score != null ? `${s.abuse_score} / 100` : "–"}
              </Meta>
              <Meta label={<Term id="known-scanner">Known scanner</Term>}>
                {s?.known_scanner == null ? "–" : s.known_scanner ? "Yes" : "No"}
              </Meta>
            </dl>
            {s ? (
              <div className="mt-4 flex flex-col gap-2">
                <Button asChild variant="outline" size="sm" className="w-full">
                  <Link to={`/attackers/${encodeURIComponent(s.src_ip)}`}>Attacker profile</Link>
                </Button>
                <Button asChild variant="ghost" size="sm" className="w-full">
                  <Link to={`/attacks?src_ip=${encodeURIComponent(s.src_ip)}`}>
                    All sessions from this address
                  </Link>
                </Button>
              </div>
            ) : null}
          </FindingCard>
          {s && flood ? <SiblingGroupsCard group={s} /> : null}
        </div>
      </div>
    </>
  )
}
