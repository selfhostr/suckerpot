import { useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { ArrowLeft, FileCode2, Lightbulb } from "lucide-react"
import { Link, useParams } from "react-router"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { RelativeTime } from "@/components/relative-time"
import { ExplainedLines } from "@/components/scripts/explained-lines"
import { SensorBadge } from "@/components/sensor-badge"
import { SessionRow } from "@/components/session-row"
import { SeverityBadge } from "@/components/severity-badge"
import { SkeletonCard, SkeletonList } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { ApiError } from "@/lib/api"
import { formatNumber, plural } from "@/lib/format"
import { describeScript, nextStep, scriptKeys, scriptsApi } from "@/lib/scripts"

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <dt className="text-2xs font-medium tracking-wide text-fg-subtle uppercase">{label}</dt>
      <dd className="text-sm text-fg tabular-nums">{children}</dd>
    </div>
  )
}

function SessionsCard({ id }: { id: number }) {
  const query = useInfiniteQuery({
    queryKey: scriptKeys.sessions(id),
    queryFn: ({ pageParam }) => scriptsApi.sessions(id, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const rows = query.data?.pages.flatMap((p) => p.items) ?? []
  return (
    <FindingCard
      eyebrow="Sessions"
      finding={
        query.isPending
          ? "Loading the sessions that ran this script."
          : rows.length === 0
            ? "The sessions that ran this script are no longer stored."
            : `Most recent ${plural(rows.length, "session")} that ran it${query.hasNextPage ? " (more below)" : ""}.`
      }
      bodyClassName="px-0 pt-3 sm:px-0 pb-0 sm:pb-0"
    >
      {query.isPending ? (
        <SkeletonList rows={3} />
      ) : (
        <div role="list" aria-label="Sessions that ran this script" className="divide-y border-t">
          {rows.map((s) => (
            <div key={s.session_id} role="listitem">
              <SessionRow session={s} />
            </div>
          ))}
        </div>
      )}
      {query.hasNextPage ? (
        <div className="border-t p-3 text-center">
          <Button
            variant="outline"
            size="sm"
            disabled={query.isFetchingNextPage}
            onClick={() => void query.fetchNextPage()}
          >
            Show more sessions
          </Button>
        </div>
      ) : null}
    </FindingCard>
  )
}

export function ScriptDetailPage() {
  const { id: raw } = useParams()
  const id = Number(raw)
  const valid = Number.isInteger(id) && id > 0
  const query = useQuery({
    queryKey: scriptKeys.detail(id),
    queryFn: () => scriptsApi.detail(id),
    enabled: valid,
    retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 2,
  })
  const back = (
    <Link to="/scripts" className="inline-flex items-center gap-1 hover:text-fg">
      <ArrowLeft aria-hidden className="size-3.5" />
      All scripts
    </Link>
  )

  if (!valid || (query.isError && query.error instanceof ApiError && query.error.status === 404)) {
    return (
      <>
        <PageHeader help="script" title="Script" eyebrow={back} />
        <EmptyState
          icon={FileCode2}
          title="This script is not in the library"
          description="It may have been removed by the retention job, or the link is wrong."
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/scripts">Back to the library</Link>
            </Button>
          }
        />
      </>
    )
  }
  if (query.isPending) {
    return (
      <>
        <PageHeader help="script" title="Script" eyebrow={back} />
        <div className="space-y-4" aria-busy>
          <SkeletonCard />
          <SkeletonCard />
        </div>
      </>
    )
  }
  if (query.isError) {
    return (
      <>
        <PageHeader help="script" title="Script" eyebrow={back} />
        <EmptyState
          icon={FileCode2}
          title="Could not load this script"
          description={query.error.message}
          action={
            <Button variant="outline" size="sm" onClick={() => void query.refetch()}>
              Try again
            </Button>
          }
        />
      </>
    )
  }

  const d = query.data
  const item = d.item
  return (
    <>
      <PageHeader
        help="script"
        title={`Script ${item.id}`}
        eyebrow={back}
        description={<span className="normal-nums">{describeScript(item, item.summary)}</span>}
      />

      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-xs text-fg-muted">
          {item.risk ? <SeverityBadge severity={item.risk} /> : null}
          {item.sensors.map((s) => (
            <Link
              key={s}
              to={`/scripts?sensor=${encodeURIComponent(s)}`}
              className="rounded-sm hover:opacity-80"
            >
              <SensorBadge sensor={s} />
            </Link>
          ))}
          {d.campaign ? (
            <Link
              to={`/campaigns/${d.campaign.id}`}
              className="rounded-sm border border-border-strong px-2 py-1 text-fg-muted normal-nums transition-colors hover:border-fg-subtle hover:text-fg"
            >
              Campaign: {d.campaign.name}
            </Link>
          ) : null}
        </div>

        <FindingCard
          eyebrow="Line by line"
          className="normal-nums"
          finding={
            d.lines.length === 0
              ? "No explanation is stored for this script yet."
              : "What each command does, in plain words."
          }
          detail={
            d.unexplained > 0
              ? `${plural(d.unexplained, "line")} not in the built-in explanation base yet.`
              : undefined
          }
        >
          {d.lines.length > 0 ? (
            <>
              <ExplainedLines lines={d.lines} />
              <p className="mt-4 flex items-start gap-2 rounded-md bg-surface-hover/50 px-3 py-2.5 text-sm text-fg-muted">
                <Lightbulb aria-hidden className="mt-0.5 size-4 shrink-0" />
                <span>
                  <span className="font-medium text-fg">What to do: </span>
                  {nextStep(d.lines)}
                </span>
              </p>
            </>
          ) : null}
        </FindingCard>

        {d.techniques_detail.length > 0 ? (
          <FindingCard
            eyebrow="Techniques"
            className="normal-nums"
            finding={`It uses ${plural(d.techniques_detail.length, "known attacker technique")}.`}
            detail="Names from the MITRE ATT&CK catalogue. Select one to find other scripts that use it."
          >
            <ul className="flex flex-wrap gap-2" aria-label="Techniques">
              {d.techniques_detail.map((t) => (
                <li key={t.id}>
                  <Link
                    to={`/scripts?technique=${encodeURIComponent(t.id)}`}
                    className="inline-flex items-center gap-1.5 rounded-sm border border-border-strong px-2 py-1 text-xs text-fg-muted transition-colors hover:border-fg-subtle hover:text-fg"
                  >
                    <span className="font-mono">{t.id}</span>
                    {t.name}
                  </Link>
                </li>
              ))}
            </ul>
          </FindingCard>
        ) : null}

        <FindingCard eyebrow="Facts" finding="When and how often it was seen.">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-4">
            <Fact label="First seen">
              <RelativeTime iso={item.first_seen} className="text-sm text-fg" />
            </Fact>
            <Fact label="Last seen">
              <RelativeTime iso={item.last_seen} className="text-sm text-fg" />
            </Fact>
            <Fact label="Sessions">{formatNumber(item.sessions)}</Fact>
            <Fact label="Addresses">{formatNumber(item.sources)}</Fact>
            <Fact label="Fingerprint">
              <span className="font-mono text-xs" title={item.fingerprint}>
                {item.fingerprint.slice(0, 12)}
              </span>
            </Fact>
          </dl>
        </FindingCard>

        <SessionsCard id={item.id} />
      </div>
    </>
  )
}
