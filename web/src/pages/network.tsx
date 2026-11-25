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
import { t } from "@/i18n"

/** The summary of the network is fetched by this node once a day; wait for the first one. */
function WaitingForFigures() {
  return (
    <EmptyState
      icon={Hourglass}
      title={t("network_overview_waiting_title")}
      description={t("network_overview_waiting_description")}
    />
  )
}

function MemberOverview({ status }: { status: NetworkStatus }) {
  const summary = useQuery({ queryKey: networkKeys.summary, queryFn: networkApi.summary })
  const impact = useQuery({ queryKey: networkKeys.impact, queryFn: networkApi.impact })
  const s = summary.data
  const tot = s?.totals
  const boot = tot ? bootstrapSentence(tot) : null
  return (
    <div className="grid grid-cols-1 gap-4">
      <p className="max-w-3xl type-lede text-pretty text-fg">
        {impact.data ? describeStatus(status, impact.data) : t("network_overview_counting")}
      </p>
      {boot ? (
        <p
          role="status"
          className="rounded-md border border-dashed px-4 py-3 text-sm text-fg-muted"
        >
          {boot}
        </p>
      ) : null}

      <section aria-label={t("network_overview_figures_label")} className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatTile
          label={t("network_overview_active_members")}
          value={tot?.active_7d}
          loading={summary.isPending}
          hint={tot ? t("network_overview_of_members", { count: tot.members }) : undefined}
          href="/network/members"
        />
        <StatTile
          label={t("network_overview_confirmed")}
          value={tot?.confirmed_30d}
          loading={summary.isPending}
          hint={t("network_overview_confirmed_hint")}
          href="/network?state=all"
        />
        <StatTile
          label={t("network_overview_reported")}
          value={tot?.reported_30d}
          loading={summary.isPending}
          hint={t("network_overview_reported_hint")}
          href="/network?state=reported"
        />
        <StatTile
          label={t("network_overview_taken_down")}
          value={tot?.taken_down_30d}
          loading={summary.isPending}
          hint={t("network_overview_taken_down_hint")}
          href="/network?state=taken_down"
        />
        {tot?.median_days_to_takedown === null ? null : (
          <StatTile
            label={t("network_overview_median")}
            value={tot?.median_days_to_takedown}
            loading={summary.isPending}
            unit={t("network_overview_unit_days")}
            className="col-span-2 lg:col-span-1"
            hint={t("network_overview_median_hint")}
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
          <span className="text-fg-subtle">
            {t("network_overview_figures_of", { date: formatDay(s.generated_day, true) })}
          </span>
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
        eyebrow={t("network_overview_how_eyebrow")}
        finding={t("network_overview_how_finding")}
        detail={t("network_overview_how_detail")}
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
        title={t("network_page_title")}
        description={t("network_page_description")}
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
