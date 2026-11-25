import { CircleCheck, ListChecks, Rss, TriangleAlert } from "lucide-react"
import { useState } from "react"
import { useAuth } from "@/app/auth"
import { EmptyState } from "@/components/empty-state"
import { SkeletonCard, SkeletonText } from "@/components/skeletons"
import { Term } from "@/components/term"
import { Button } from "@/components/ui/button"
import { formatAbsolute } from "@/lib/format"
import {
  feedSentence,
  feedStatusLine,
  isEmptyForNow,
  LIST_META,
  type FeedList,
} from "@/lib/network-feed"
import { EntriesCard } from "./entries-card"
import { FeedOff } from "./feed-off"
import { HowToDrawer } from "./how-to-drawer"
import { ListCard } from "./list-card"
import { useFeedStatus } from "./use-feed"
import { WhyJoinCard } from "./why-join-card"

/** The recommended list ("Start here") first, then the API order. */
function byRecommendation(lists: FeedList[]): FeedList[] {
  return [...lists].sort(
    (a, b) => Number(LIST_META[b.id].startHere) - Number(LIST_META[a.id].startHere),
  )
}

/**
 * Blocklists, tab "Network": the free community lists built from network consensus. Everything
 * here is optional; a firewall can use the lists without this dashboard and without joining.
 */
export function NetworkFeedTab() {
  const { canWrite } = useAuth()
  const q = useFeedStatus()
  const [howTo, setHowTo] = useState(false)
  const s = q.data

  if (q.isPending) {
    return (
      <div className="space-y-4" aria-busy>
        <SkeletonText lines={2} className="max-w-xl" />
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      </div>
    )
  }
  if (!s) {
    return (
      <EmptyState
        icon={TriangleAlert}
        title="The community lists are not available"
        description={q.error.message}
        action={
          <Button variant="outline" size="sm" onClick={() => void q.refetch()}>
            Try again
          </Button>
        }
      />
    )
  }

  const drawer = <HowToDrawer open={howTo} onOpenChange={setHowTo} status={s} />
  if (!s.enabled_env || !s.configured || s.state === "disabled") {
    return (
      <>
        <FeedOff status={s} onHowTo={() => setHowTo(true)} />
        {drawer}
      </>
    )
  }

  const line = feedStatusLine(s, formatAbsolute)
  const StatusIcon = line.tone === "ok" ? CircleCheck : TriangleAlert
  const empty = isEmptyForNow(s)

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="max-w-2xl space-y-2">
          <p className="type-lede text-pretty text-fg">{feedSentence(s)}</p>
          <p
            role="status"
            className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-fg-muted"
          >
            <span className="inline-flex items-center gap-1.5 font-medium text-fg">
              <StatusIcon
                aria-hidden
                className={line.tone === "warning" ? "size-4 text-sev-warning" : "size-4"}
              />
              {line.label}
            </span>
            {line.detail ? <span>{line.detail}</span> : null}
          </p>
          <p className="text-sm text-fg-muted">
            Built only from network consensus: an entry needs at least 5 independent sensors (its{" "}
            <Term id="k-support">k-support</Term>). The <Term id="high-tier">high tier</Term> is the
            safest part to block automatically. Using these lists is optional and needs no account;
            an <Term id="outbound-list">outbound list</Term> is the best place to start.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setHowTo(true)}>
          <ListChecks aria-hidden />
          How to use
        </Button>
      </div>

      {empty ? (
        <EmptyState
          className="mt-6"
          icon={Rss}
          title="Nothing to block yet"
          description="The lists grow as more members join the network. You can already add an address below to your firewall: it picks up new entries on its own as they appear."
        />
      ) : null}

      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        {byRecommendation(s.lists).map((l) => (
          <ListCard key={l.id} list={l} mirrorLink={canWrite && s.local_mirror.feeds_enabled} />
        ))}
      </div>

      {empty ? null : (
        <div className="mt-10">
          <EntriesCard />
        </div>
      )}

      <div className="mt-10">
        <WhyJoinCard status={s} />
      </div>
      {drawer}
    </>
  )
}
