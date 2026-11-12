import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Mailbox, MailWarning, Settings2 } from "lucide-react"
import { useId, useMemo, useState } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { BlockedDraftsNotice } from "@/components/abuse/blocked-drafts"
import { RepliesToCheck } from "@/components/abuse/replies-list"
import { ReportRow } from "@/components/abuse/report-row"
import { SendQueue } from "@/components/abuse/send-queue"
import { useSendQueue } from "@/components/abuse/send-hooks"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { PageHeader } from "@/components/page-header"
import { ReadOnlyBadge } from "@/components/read-only-badge"
import { SkeletonList } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useUrlParam } from "@/hooks/use-url-param"
import {
  abuseApi,
  abuseKeys,
  blockedReason,
  describeAbuseError,
  describeReports,
  LIST_STATUSES,
  TAB_LABEL,
  type ListStatus,
  type ReportItem,
  type WaitingRecipient,
} from "@/lib/abuse"
import { plural } from "@/lib/format"
import { describeRepliesToCheck } from "@/lib/results-sentences"

interface Group {
  id: number
  name: string
  mailbox: string | null
  asns: { asn: number; name: string | null }[]
  reports: ReportItem[]
}

/** Reports of one provider belong together: one desk reads them all. */
function groupByProvider(items: ReportItem[]): Group[] {
  const groups = new Map<number, Group>()
  for (const r of items) {
    let g = groups.get(r.recipient.id)
    if (!g) {
      g = {
        id: r.recipient.id,
        name: r.recipient.name,
        mailbox: r.recipient.mailbox,
        asns: [],
        reports: [],
      }
      groups.set(r.recipient.id, g)
    }
    for (const a of r.asns) if (!g.asns.some((x) => x.asn === a.asn)) g.asns.push(a)
    g.reports.push(r)
  }
  return [...groups.values()]
}

function ProviderGroup({ g }: { g: Group }) {
  return (
    <section
      aria-labelledby={`prov-${g.id}`}
      className="overflow-hidden rounded-lg border bg-surface shadow-sm"
    >
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-4 pt-4 pb-3 sm:px-5">
        <h2 id={`prov-${g.id}`} className="text-base font-medium text-fg">
          {g.name}
        </h2>
        <span className="font-mono text-xs text-fg-muted">{g.mailbox ?? "no mailbox yet"}</span>
        <span className="flex flex-wrap gap-1.5">
          {g.asns.map((a) => (
            <Link
              key={a.asn}
              to={`/attackers?asn=${a.asn}`}
              className="inline-flex h-6 items-center gap-1.5 rounded-sm border px-2 font-mono text-2xs text-fg-muted transition-colors hover:border-fg-subtle hover:text-fg"
            >
              AS{a.asn}
              {a.name ? <span className="font-sans">{a.name}</span> : null}
            </Link>
          ))}
        </span>
      </header>
      <ul className="divide-y border-t">
        {g.reports.map((r) => (
          <ReportRow key={r.public_id} r={r} />
        ))}
      </ul>
    </section>
  )
}

function MailboxForm({ w, onDone }: { w: WaitingRecipient; onDone: () => void }) {
  const id = useId()
  const [value, setValue] = useState("")
  const [error, setError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => abuseApi.setMailbox(w.id, value.trim()),
    onSuccess: onDone,
    onError: (e) => setError(describeAbuseError(e)),
  })
  return (
    <form
      className="flex flex-wrap items-center gap-2"
      onSubmit={(e) => {
        e.preventDefault()
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value.trim())) {
          setError("Enter a full mailbox such as abuse@example.net.")
          return
        }
        setError(null)
        save.mutate()
      }}
    >
      <label htmlFor={id} className="sr-only">
        Abuse mailbox for {w.name}
      </label>
      <Input
        id={id}
        type="email"
        value={value}
        placeholder="abuse@provider.tld"
        onChange={(e) => setValue(e.target.value)}
        className="h-8 w-56 font-mono text-xs placeholder:text-fg-subtle"
      />
      <Button type="submit" size="sm" variant="outline" disabled={save.isPending}>
        Add mailbox
      </Button>
      <p role="alert" className="w-full text-xs text-fg empty:hidden">
        {error}
      </p>
    </form>
  )
}

function NoContact() {
  const { canWrite } = useAuth()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: abuseKeys.waiting, queryFn: abuseApi.waiting })
  const list = q.data ?? []
  if (list.length === 0) return null
  const total = list.reduce((n, w) => n + w.subject_count, 0)
  return (
    <FindingCard
      eyebrow="No contact found"
      finding={`${plural(total, "address", "addresses")} in ${plural(list.length, "network")} cannot be reported yet: no abuse mailbox was found.`}
      detail={
        canWrite ? "Add a mailbox by hand and the draft is written on the next run." : undefined
      }
      bodyClassName="px-0 sm:px-0 pb-1 sm:pb-1"
    >
      <ul className="divide-y border-t">
        {list.map((w) => (
          <li
            key={w.id}
            className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-5"
          >
            <span className="min-w-0 space-y-0.5">
              <span className="block text-sm font-medium text-fg">{w.name}</span>
              <span className="block text-xs text-fg-muted">
                {w.asns.map((a) => `AS${a.asn}`).join(", ")} ·{" "}
                {plural(w.subject_count, "address", "addresses")}
              </span>
            </span>
            {canWrite ? (
              <MailboxForm
                w={w}
                onDone={() => void qc.invalidateQueries({ queryKey: abuseKeys.all })}
              />
            ) : null}
          </li>
        ))}
      </ul>
    </FindingCard>
  )
}

export function AbusePage() {
  const { canWrite } = useAuth()
  const [param, setParam] = useUrlParam("status")
  const queueView = canWrite && param === "queue"
  const repliesView = canWrite && param === "replies"
  const [recipientParam] = useUrlParam("recipient")
  const recipient =
    recipientParam && /^\d+$/.test(recipientParam) ? Number(recipientParam) : undefined
  const status: ListStatus = LIST_STATUSES.find((s) => s === param) ?? "draft"
  const queue = useSendQueue()
  const st = useQuery({ queryKey: abuseKeys.status, queryFn: abuseApi.status })
  const filters = recipient === undefined ? { status } : { status, recipient }
  const list = useInfiniteQuery({
    enabled: !queueView && !repliesView,
    queryKey: abuseKeys.list(filters),
    queryFn: ({ pageParam }) => abuseApi.list(filters, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const items = useMemo(() => (list.data?.pages ?? []).flatMap((p) => p.items), [list.data])
  const groups = useMemo(() => groupByProvider(items), [items])
  const blocked = blockedReason(st.data)
  const counts = st.data?.counts
  const repliesToCheck = st.data?.replies
    ? Math.max(st.data.replies.unmatched, st.data.replies.needs_review)
    : 0

  return (
    <>
      <PageHeader
        help="abuse"
        title="Abuse reports"
        description={
          <span className="normal-nums">
            {describeReports(st.data, {
              toSend: queue.data?.items.length,
              replies: canWrite ? repliesToCheck : 0,
            })}
          </span>
        }
        actions={
          <>
            <ReadOnlyBadge />
            {canWrite ? (
              <Button variant="outline" size="sm" asChild>
                <Link to="/settings?tab=reporting">
                  <Settings2 aria-hidden /> Reporting settings
                </Link>
              </Button>
            ) : null}
          </>
        }
      />

      {blocked ? (
        <EmptyState
          icon={MailWarning}
          title="Reports are not available yet"
          description={blocked}
          action={
            canWrite ? (
              <Button asChild variant="outline" size="sm">
                <Link to="/settings?tab=reporting">Open Settings</Link>
              </Button>
            ) : undefined
          }
          className="mb-6"
        />
      ) : null}

      {canWrite && !repliesView && repliesToCheck > 0 ? (
        <p
          role="status"
          className="mb-4 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border border-border-strong bg-surface-raised px-3 py-2 text-sm text-fg"
        >
          <Mailbox aria-hidden className="size-4 text-fg-muted" />
          {describeRepliesToCheck(repliesToCheck)}
          <Link
            to="/defend/abuse?status=replies"
            className="font-medium underline underline-offset-4"
          >
            Check the replies
          </Link>
        </p>
      ) : null}

      <Tabs
        value={queueView ? "queue" : repliesView ? "replies" : status}
        onValueChange={(v) => setParam(v === "draft" ? null : v)}
      >
        <TabsList
          variant="line"
          aria-label="Report status"
          className="scroll-fade-x mb-4 max-w-full justify-start overflow-x-auto"
        >
          {canWrite ? (
            <TabsTrigger value="queue" className="flex-none px-3">
              To send
              {queue.data ? (
                <span className="ml-1.5 text-xs text-fg-subtle tabular-nums">
                  {queue.data.items.length}
                </span>
              ) : null}
            </TabsTrigger>
          ) : null}
          {canWrite && repliesToCheck > 0 ? (
            <TabsTrigger value="replies" className="flex-none px-3">
              Replies to check
              <span className="ml-1.5 text-xs text-fg-subtle tabular-nums">{repliesToCheck}</span>
            </TabsTrigger>
          ) : null}
          {LIST_STATUSES.map((s) => (
            <TabsTrigger key={s} value={s} className="flex-none px-3">
              {TAB_LABEL[s]}
              {counts ? (
                <span className="ml-1.5 text-xs text-fg-subtle tabular-nums">{counts[s]}</span>
              ) : null}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      {repliesView ? (
        <RepliesToCheck />
      ) : queueView ? (
        <SendQueue />
      ) : (
        <div className="space-y-4 normal-nums">
          {status === "draft" && st.data?.blocked_drafts ? (
            <BlockedDraftsNotice blocked={st.data.blocked_drafts} />
          ) : null}
          {list.isPending ? (
            <SkeletonList rows={4} />
          ) : list.isError ? (
            <EmptyState
              icon={MailWarning}
              title="Could not load the reports"
              description={describeAbuseError(list.error)}
              action={
                <Button variant="outline" size="sm" onClick={() => void list.refetch()}>
                  Try again
                </Button>
              }
            />
          ) : groups.length === 0 ? (
            blocked ? null : (
              <EmptyState
                icon={MailWarning}
                title={`No ${TAB_LABEL[status].toLowerCase()} reports`}
                description={
                  status === "draft"
                    ? "A draft appears when a source crosses the thresholds and a mailbox is found."
                    : "Nothing here yet."
                }
              />
            )
          ) : (
            groups.map((g) => <ProviderGroup key={g.id} g={g} />)
          )}
          {list.hasNextPage ? (
            <Button
              variant="outline"
              size="sm"
              disabled={list.isFetchingNextPage}
              onClick={() => void list.fetchNextPage()}
            >
              {list.isFetchingNextPage ? "Loading…" : "Show more"}
            </Button>
          ) : null}
          {status === "draft" ? <NoContact /> : null}
        </div>
      )}
    </>
  )
}
