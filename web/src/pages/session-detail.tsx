import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { PageHelp } from "@/components/page-help"
import { useQuery } from "@tanstack/react-query"
import { ArrowLeft, FileQuestion, TerminalSquare } from "lucide-react"
import { lazy, Suspense, useMemo, useState } from "react"
import { Link, useParams, useSearchParams } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { subjectProps } from "@/app/view-transitions"
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
import { formatAbsolute, formatDuration, formatNumber } from "@/lib/format"
import { listPlain } from "@/lib/sensors"
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
  if (source.reconstructed) return t("session_replay_rebuilt", { count: commands, span })
  return commands
    ? t("session_replay_typed", { count: commands, span })
    : t("session_replay_output", { span })
}

function durationOf(s: Session): string {
  const end = s.ended_at ?? s.last_event_at
  return formatDuration((Date.parse(end) - Date.parse(s.started_at)) / 1000)
}

function timelineFinding(s: Session): string {
  const parts: string[] = []
  if (s.login_attempts) parts.push(t("session_timeline_logins", { count: s.login_attempts }))
  if (s.commands) parts.push(t("session_timeline_commands", { count: s.commands }))
  if (s.downloads) parts.push(t("session_timeline_downloads", { count: s.downloads }))
  if (s.http_requests) parts.push(t("session_timeline_http", { count: s.http_requests }))
  const what = parts.length
    ? listPlain(parts)
    : t("session_timeline_events", { count: s.event_count })
  return t("session_timeline_finding", { what, duration: durationOf(s) })
}

/** A flood group loads its first 200 events; the timeline opens on the first few of them. */
const FLOOD_EVENTS_SHOWN = 40

function floodTimelineFinding(shown: number, total: number): string {
  return shown >= total
    ? t("session_flood_events_all", { total })
    : t("session_flood_events_first", { shown, total })
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
      <ArrowLeft aria-hidden className="size-3.5" /> {t("attacks_title")}
    </Link>
  )

  if (session.isError) {
    const notFound = session.error instanceof ApiError && session.error.status === 404
    return (
      <>
        <div className="pb-6">{back}</div>
        <EmptyState
          icon={FileQuestion}
          title={notFound ? t("session_not_found") : t("session_load_error")}
          description={notFound ? t("session_removed") : session.error.message}
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/attacks">{t("session_back_to_attacks")}</Link>
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
              <span {...subjectProps(`session:${sessionId}`)} className="inline-flex">
                <SensorBadge sensor={s.sensor} />
              </span>
              {flood ? <FloodBadge connections={connectionsOf(s)} /> : null}
              <SeverityBadge severity={sessionSeverity(s)} />
              {s.tags.map((tag) => (
                <TagBadge key={tag} tag={tag} />
              ))}
            </div>
            {s.campaign_id ? <CampaignChip id={s.campaign_id} /> : null}
            <div className="flex items-start gap-1.5">
              <h1 className="min-w-0 type-section-title text-pretty sm:type-page-title">
                <span className="sr-only">
                  {t("session_sr_title", { flood: flood ? "yes" : "no", id: s.session_id })}{" "}
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
                    {tNodes(
                      "session_folded_from",
                      {},
                      { id: <span className="font-mono">{s.folded_from}</span> },
                    )}
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
          <Meta label={t("session_meta_window")}>{floodSpanLong(s)}</Meta>
          <Meta label={t("session_meta_connections")}>{formatNumber(connectionsOf(s))}</Meta>
          <Meta label={t("session_meta_logins")}>{formatNumber(s.login_attempts)}</Meta>
          <Meta label={t("session_meta_events")}>{formatNumber(s.event_count)}</Meta>
          <Meta label={t("session_meta_port")}>
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
          <Meta label={t("session_meta_started")}>{formatAbsolute(s.started_at)}</Meta>
          <Meta label={t("session_meta_duration")}>
            {s.ended_at ? durationOf(s) : t("session_still_connected")}
          </Meta>
          <Meta label={t("session_meta_events")}>{formatNumber(s.event_count)}</Meta>
          {clientTool ? <Meta label={t("session_meta_client")}>{clientTool}</Meta> : null}
          <Meta label={t("session_meta_ports")}>
            <span className="font-mono text-xs">
              {s.src_port} → {s.dst_port}
            </span>
          </Meta>
          <Meta label={t("session_meta_id")}>
            <span className="font-mono text-xs">{s.session_id}</span>
          </Meta>
        </dl>
      ) : null}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          {s && flood && s.login_attempts > 0 ? <CredentialsCard sessionId={s.session_id} /> : null}

          {s && !flood && REPLAY_SENSORS.has(s.sensor) ? (
            <FindingCard
              eyebrow={t("session_replay_eyebrow")}
              finding={
                events.isPending
                  ? t("session_replay_loading")
                  : replay
                    ? replayFinding(replay, commandCount)
                    : t("session_replay_none")
              }
            >
              {events.isPending ? (
                <Skeleton className="h-64 w-full sm:h-80" />
              ) : events.isError ? (
                <p className="text-sm text-fg-muted">{t("session_replay_error")}</p>
              ) : replay ? (
                <Suspense fallback={<Skeleton className="h-64 w-full sm:h-80" />}>
                  <TerminalReplay source={replay} masked={masked} />
                </Suspense>
              ) : (
                <EmptyState
                  variant="bare"
                  icon={TerminalSquare}
                  title={t("session_replay_empty_title")}
                  description={t("session_replay_empty_description")}
                  className="py-8"
                />
              )}
            </FindingCard>
          ) : null}

          <FindingCard
            eyebrow={flood ? t("session_first_events") : t("session_timeline")}
            finding={
              !s
                ? t("session_timeline_loading")
                : flood
                  ? events.data
                    ? floodTimelineFinding(events.data.length, s.event_count)
                    : t("session_first_events_loading")
                  : timelineFinding(s)
            }
            bodyClassName="px-0 sm:px-0 pt-3 pb-2 sm:pb-2"
            footer={
              flood && events.data && events.data.length > FLOOD_EVENTS_SHOWN ? (
                <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
                  <span>
                    {showAllEvents
                      ? t("session_loaded_all", { total: events.data.length })
                      : t("session_loaded_first", {
                          shown: FLOOD_EVENTS_SHOWN,
                          total: events.data.length,
                        })}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    aria-expanded={showAllEvents}
                    onClick={() => setShowAllEvents((open) => !open)}
                  >
                    {showAllEvents
                      ? t("session_show_fewer")
                      : t("session_show_all", { total: events.data.length })}
                  </Button>
                </div>
              ) : undefined
            }
          >
            {events.isPending ? (
              <SkeletonList rows={6} />
            ) : events.isError ? (
              <p className="px-5 py-6 text-sm text-fg-muted">{t("session_events_error")}</p>
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
            eyebrow={t("session_source")}
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
            detail={s?.org ? `${s.org}${s.asn ? ` · AS${s.asn}` : ""}` : t("session_not_enriched")}
          >
            <dl className="grid grid-cols-2 gap-4">
              <Meta label={<Term id="abuse-score">{t("session_abuse_score")}</Term>}>
                {s?.abuse_score != null ? `${s.abuse_score} / 100` : "–"}
              </Meta>
              <Meta label={<Term id="known-scanner">{t("session_known_scanner")}</Term>}>
                {s?.known_scanner == null
                  ? "–"
                  : s.known_scanner
                    ? t("common_yes")
                    : t("common_no")}
              </Meta>
            </dl>
            {s ? (
              <div className="mt-4 flex flex-col gap-2">
                <Button asChild variant="outline" size="sm" className="w-full">
                  <Link to={`/attackers/${encodeURIComponent(s.src_ip)}`}>
                    {t("session_attacker_profile")}
                  </Link>
                </Button>
                <Button asChild variant="ghost" size="sm" className="w-full">
                  <Link to={`/attacks?src_ip=${encodeURIComponent(s.src_ip)}`}>
                    {t("session_all_from_address")}
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
