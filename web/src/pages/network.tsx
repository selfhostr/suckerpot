import { useQuery } from "@tanstack/react-query"
import { Hourglass } from "lucide-react"
import { useAuth } from "@/app/auth"
import { SharedExplainer } from "@/components/network/explainer"
import { JoinCard } from "@/components/network/join-card"
import { NodeCard } from "@/components/network/node-card"
import { TargetsCard } from "@/components/network/targets-card"
import { useNetworkStatus } from "@/components/network/use-network"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { ReadOnlyBadge } from "@/components/read-only-badge"
import { SkeletonCard } from "@/components/skeletons"
import { StatTile } from "@/components/stat-tile"
import {
  bootstrapSentence,
  describeStatus,
  formatDay,
  isMember,
  type NetworkStatus,
  networkApi,
  networkKeys,
  weeklyFinding,
} from "@/lib/network"

/** The summary of the network is fetched by this node once a day; wait for the first one. */
function WaitingForFigures() {
  return (
    <EmptyState
      icon={Hourglass}
      title="The first figures are on their way"
      description="The network publishes its figures once a day. They show up here after the next count."
    />
  )
}

function MemberOverview({ status }: { status: NetworkStatus }) {
  const summary = useQuery({ queryKey: networkKeys.summary, queryFn: networkApi.summary })
  const impact = useQuery({ queryKey: networkKeys.impact, queryFn: networkApi.impact })
  const s = summary.data
  const t = s?.totals
  const boot = t ? bootstrapSentence(t) : null
  return (
    <div className="grid grid-cols-1 gap-4">
      <p className="max-w-3xl type-lede text-pretty text-fg">
        {impact.data ? describeStatus(status, impact.data) : "Counting what the network did…"}
      </p>
      {boot ? (
        <p
          role="status"
          className="rounded-md border border-dashed px-4 py-3 text-sm text-fg-muted"
        >
          {boot}
        </p>
      ) : null}

      <section aria-label="Network figures" className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatTile
          label="Active members this week"
          value={t?.active_7d}
          loading={summary.isPending}
          hint={t ? `of ${t.members} members` : undefined}
          href="/network/members"
        />
        <StatTile
          label="Confirmed, 30 days"
          value={t?.confirmed_30d}
          loading={summary.isPending}
          hint="by 5 or more sensors"
          href="/network?state=all"
        />
        <StatTile
          label="Reported, 30 days"
          value={t?.reported_30d}
          loading={summary.isPending}
          hint="one report per target"
          href="/network?state=reported"
        />
        <StatTile
          label="Taken down, 30 days"
          value={t?.taken_down_30d}
          loading={summary.isPending}
          hint="no longer answering"
          href="/network?state=taken_down"
        />
        {t?.median_days_to_takedown === null ? null : (
          <StatTile
            label="Median time to takedown"
            value={t?.median_days_to_takedown}
            loading={summary.isPending}
            unit="days"
            className="col-span-2 lg:col-span-1"
            hint="from first sighting"
          />
        )}
      </section>

      {summary.isPending ? (
        <SkeletonCard />
      ) : !s ? (
        <WaitingForFigures />
      ) : (
        <p className="text-sm text-fg-muted">
          {weeklyFinding(s.weekly)}{" "}
          <span className="text-fg-subtle">Figures of {formatDay(s.generated_day, true)}.</span>
        </p>
      )}

      <TargetsCard />

      <NodeCard status={status} />
    </div>
  )
}

function OutsideOverview() {
  return (
    <div className="grid grid-cols-1 gap-4">
      <JoinCard />
      <FindingCard
        eyebrow="How it works"
        finding="Many sensors see the same attackers. Together they can get one of them removed."
        detail="Here is exactly what is shared if you join, and what never is."
      >
        <SharedExplainer />
      </FindingCard>
    </div>
  )
}

export function NetworkPage() {
  const { canWrite } = useAuth()
  const q = useNetworkStatus()
  const member = isMember(q.data)
  return (
    <>
      <PageHeader
        help="network"
        title="SuckerPot network"
        description="SuckerPot installations pooling what their sensors see, to get attackers removed."
        actions={canWrite ? null : <ReadOnlyBadge />}
      />
      {q.isPending ? (
        <SkeletonCard />
      ) : member && q.data ? (
        <MemberOverview status={q.data} />
      ) : (
        <OutsideOverview />
      )}
    </>
  )
}
