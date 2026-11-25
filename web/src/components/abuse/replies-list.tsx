import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { CircleAlert, CircleCheck, Inbox, Link2 } from "lucide-react"
import { useMemo, useState } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { OutcomeBadge } from "@/components/results/badges"
import { EmptyState } from "@/components/empty-state"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonList } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { abuseApi, abuseKeys } from "@/lib/abuse"
import {
  describeRepliesError,
  matchLabel,
  repliesApi,
  repliesKeys,
  ruleLabel,
  type Reply,
} from "@/lib/replies"
import { cn } from "@/lib/utils"

/** Verified or not, as icon plus word. */
export function VerifiedMark({ verified }: { verified: boolean }) {
  return verified ? (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-fg-muted">
      <CircleCheck aria-hidden className="size-3.5 text-status-ok" />
      Verified
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-fg">
      <CircleAlert aria-hidden className="size-3.5 text-sev-warning" />
      Check it
    </span>
  )
}

/**
 * One reply. The sender and the excerpt come from outside and are shown as plain text in a
 * monospace block: never HTML, never a link. Administrators see the address and the excerpt.
 */
export function ReplyView({ r, actions }: { r: Reply; actions?: React.ReactNode }) {
  return (
    <li className="space-y-2 px-4 py-3 sm:px-5">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <OutcomeBadge outcome={r.classification} />
        <VerifiedMark verified={r.verified} />
        <span className="font-mono text-xs text-fg-muted">
          {r.from_address ?? r.from_domain ?? "unknown sender"}
        </span>
        <RelativeTime iso={r.received_at} className="ml-auto text-xs" />
      </div>
      <p className="text-xs text-fg-muted" title={r.rule_id ?? undefined}>
        {r.classification_source === "manual"
          ? "Classified by you."
          : r.rule_id
            ? `${ruleLabel(r.rule_id)}.`
            : "No rule matched."}
        {matchLabel(r.match_method)
          ? ` Linked by: ${matchLabel(r.match_method)?.toLowerCase()}.`
          : ""}
        {r.ticket_id ? ` Ticket ${r.ticket_id}.` : ""}
      </p>
      {r.excerpt_purged ? (
        <p className="text-xs text-fg-subtle">The text was deleted after its retention period.</p>
      ) : r.excerpt ? (
        <div className="overflow-hidden rounded-md border bg-bg">
          <pre className="scroll-fade-y max-h-40 overflow-auto px-3 py-2 font-mono text-xs break-words whitespace-pre-wrap text-fg-muted">
            {r.excerpt}
          </pre>
        </div>
      ) : null}
      {actions}
    </li>
  )
}

/** The replies of one report. */
export function RepliesList({ replies }: { replies: readonly Reply[] }) {
  if (replies.length === 0)
    return (
      <p className="border-t px-4 py-4 text-sm text-fg-muted sm:px-5">
        No reply stored for this report yet.
      </p>
    )
  return (
    <ul className="divide-y border-t" aria-label="Replies">
      {replies.map((r) => (
        <ReplyView key={r.id} r={r} />
      ))}
    </ul>
  )
}

function LinkMenu({ reply, onLinked }: { reply: Reply; onLinked: (msg: string) => void }) {
  const qc = useQueryClient()
  const sent = useQuery({
    queryKey: abuseKeys.list({ status: "sent" }),
    queryFn: () => abuseApi.list({ status: "sent" }),
  })
  const link = useMutation({
    mutationFn: (report: string) => repliesApi.patch(reply.id, { report, verified: true }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["abuse"] })
      onLinked("Linked to the report.")
    },
    onError: (e) => onLinked(describeRepliesError(e)),
  })
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" disabled={link.isPending}>
          <Link2 aria-hidden /> Link to report
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="max-h-72 w-72 overflow-y-auto">
        {(sent.data?.items ?? []).length === 0 ? (
          <p className="px-2 py-1.5 text-xs text-fg-muted">No sent report to link to.</p>
        ) : (
          (sent.data?.items ?? []).map((rep) => (
            <DropdownMenuItem key={rep.public_id} onSelect={() => link.mutate(rep.public_id)}>
              <span className="truncate">{rep.recipient.name}</span>
              <span className="ml-auto font-mono text-2xs text-fg-subtle">
                {rep.public_id.slice(0, 8)}
              </span>
            </DropdownMenuItem>
          ))
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** Replies that are unmatched or unverified. Nothing counts for an outcome until it is verified. */
export function RepliesToCheck() {
  const { canWrite } = useAuth()
  const qc = useQueryClient()
  const [notice, setNotice] = useState<string | null>(null)
  const filters = { needs_review: true } as const
  const q = useInfiniteQuery({
    queryKey: repliesKeys.list(filters),
    queryFn: ({ pageParam }) => repliesApi.replies(filters, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const items = useMemo(() => (q.data?.pages ?? []).flatMap((p) => p.items), [q.data])
  const patch = useMutation({
    mutationFn: (v: { id: number; trust: boolean }) =>
      repliesApi.patch(v.id, v.trust ? { verified: true, trust_domain: true } : { verified: true }),
    onSuccess: () => {
      setNotice(null)
      void qc.invalidateQueries({ queryKey: ["abuse"] })
    },
    onError: (e) => setNotice(describeRepliesError(e)),
  })
  if (q.isPending) return <SkeletonList rows={3} />
  if (items.length === 0)
    return (
      <EmptyState
        icon={Inbox}
        title="Nothing to check"
        description="Every reply is linked to a report and verified."
      />
    )
  return (
    <section
      aria-label="Replies to check"
      className="overflow-hidden rounded-lg border bg-surface shadow-sm"
    >
      <ul className="divide-y">
        {items.map((r) => (
          <ReplyView
            key={r.id}
            r={r}
            actions={
              canWrite ? (
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  {r.report ? (
                    <Button variant="ghost" size="sm" asChild>
                      <Link to={`/defend/abuse/${r.report}`}>Open the report</Link>
                    </Button>
                  ) : (
                    <LinkMenu reply={r} onLinked={setNotice} />
                  )}
                  {r.report && !r.verified ? (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={patch.isPending}
                        onClick={() => patch.mutate({ id: r.id, trust: false })}
                      >
                        Confirm
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={patch.isPending}
                        onClick={() => patch.mutate({ id: r.id, trust: true })}
                      >
                        Trust this sender
                      </Button>
                    </>
                  ) : null}
                </div>
              ) : null
            }
          />
        ))}
      </ul>
      <p
        role="status"
        className={cn("border-t px-4 py-2 text-sm text-fg-muted sm:px-5", !notice && "hidden")}
      >
        {notice}
      </p>
    </section>
  )
}
