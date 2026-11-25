import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Plus } from "lucide-react"
import { useId, useState } from "react"
import { useAuth } from "@/app/auth"
import { RepliesList } from "@/components/abuse/replies-list"
import { ReplyImportDialog } from "@/components/abuse/reply-import-dialog"
import { Field } from "@/components/form-parts"
import { FindingCard } from "@/components/finding-card"
import { OutcomeBadge } from "@/components/results/badges"
import { RelativeTime } from "@/components/relative-time"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { abuseKeys, type ReportDetail } from "@/lib/abuse"
import { plural } from "@/lib/format"
import {
  describeRepliesError,
  MANUAL_OUTCOMES,
  NO_ANSWER_DAYS,
  OUTCOME_LABEL,
  repliesApi,
  type Outcome,
} from "@/lib/replies"
import { describeOutcome } from "@/lib/results-sentences"

/** `datetime-local` wants "YYYY-MM-DDTHH:mm" in the browser's own time zone. */
function localInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

function SetOutcomeDialog({
  report,
  open,
  onOpenChange,
}: {
  report: ReportDetail
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const id = useId()
  const qc = useQueryClient()
  const [now] = useState(() => new Date())
  const [outcome, setOutcome] = useState<Outcome>(report.outcome?.manual ?? "human_reply")
  const [at, setAt] = useState(localInput(now))
  const [note, setNote] = useState(report.outcome?.note ?? "")
  const [error, setError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => {
      const when = new Date(at)
      if (Number.isNaN(when.getTime()) || when.getTime() > Date.now() + 60_000)
        throw new Error("time")
      if (report.sent_at && when.getTime() < Date.parse(report.sent_at)) throw new Error("early")
      return repliesApi.setOutcome(report.public_id, {
        outcome,
        at: when.toISOString(),
        ...(note.trim() ? { note: note.trim() } : {}),
      })
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: abuseKeys.all })
      onOpenChange(false)
    },
    onError: (e) =>
      setError(
        e instanceof Error && e.message === "time"
          ? "Pick a time that is now or earlier."
          : e instanceof Error && e.message === "early"
            ? "That is before the report was sent."
            : describeRepliesError(e),
      ),
  })
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form
          className="flex flex-col gap-4"
          noValidate
          onSubmit={(e) => {
            e.preventDefault()
            setError(null)
            save.mutate()
          }}
        >
          <DialogHeader className="text-left">
            <DialogTitle>Set the outcome</DialogTitle>
            <DialogDescription>
              Use this when the answer reached you some other way. It replaces the automatic outcome
              until you go back to automatic.
            </DialogDescription>
          </DialogHeader>
          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium text-fg">What happened</legend>
            {MANUAL_OUTCOMES.map((o) => (
              <label key={o} className="flex items-center gap-2.5 text-sm text-fg">
                <input
                  type="radio"
                  name={`${id}-outcome`}
                  value={o}
                  checked={outcome === o}
                  onChange={() => setOutcome(o)}
                  className="size-4 accent-current"
                />
                {o === "none" ? "No answer" : OUTCOME_LABEL[o]}
              </label>
            ))}
          </fieldset>
          <Field
            id={`${id}-at`}
            label="When"
            hint="Your local time. Not before the report was sent."
          >
            <Input
              id={`${id}-at`}
              type="datetime-local"
              value={at}
              max={localInput(now)}
              onChange={(e) => setAt(e.target.value)}
            />
          </Field>
          <Field id={`${id}-note`} label="Note" optional>
            <Textarea
              id={`${id}-note`}
              rows={3}
              maxLength={1000}
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </Field>
          <p role="alert" className="text-sm text-fg empty:hidden">
            {error}
          </p>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving…" : "Save outcome"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** The outcome of a sent or closed report: a sentence, the verdict, and the replies behind it. */
export function OutcomeCard({ r }: { r: ReportDetail }) {
  const { canWrite } = useAuth()
  const qc = useQueryClient()
  const [setting, setSetting] = useState(false)
  const [importing, setImporting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const clear = useMutation({
    mutationFn: () => repliesApi.clearOutcome(r.public_id),
    onSuccess: () => {
      setError(null)
      void qc.invalidateQueries({ queryKey: abuseKeys.all })
    },
    onError: (e) => setError(describeRepliesError(e)),
  })
  const o = r.outcome ?? null
  const replies = r.replies ?? []
  const effective = o?.effective ?? "none"
  const [now] = useState(() => Date.now())
  const old = r.sent_at !== null && now - Date.parse(r.sent_at) >= NO_ANSWER_DAYS * 86_400_000
  return (
    <FindingCard
      eyebrow="Outcome"
      finding={describeOutcome(o, r.sent_at)}
      detail={
        canWrite && r.reply_token
          ? `Replies are matched with the code ${r.reply_token} that the report carries.`
          : undefined
      }
      action={
        canWrite ? (
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={() => setSetting(true)}>
              Set outcome
            </Button>
            {o?.manual ? (
              <Button
                variant="ghost"
                size="sm"
                disabled={clear.isPending}
                onClick={() => clear.mutate()}
              >
                Back to automatic
              </Button>
            ) : null}
          </div>
        ) : undefined
      }
      bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
      className="normal-nums"
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 pb-4 sm:px-5">
        <OutcomeBadge outcome={effective} noAnswer={old} />
        {o?.manual ? (
          <span className="text-xs text-fg-muted">
            Set by you
            {o.manual_at ? (
              <>
                {" "}
                <RelativeTime iso={o.manual_at} />
              </>
            ) : null}
            {o.note ? `: ${o.note}` : "."}
          </span>
        ) : o && o.reply_count > 0 ? (
          <span className="text-xs text-fg-muted">
            Worked out from {plural(o.reply_count, "reply", "replies")}.
          </span>
        ) : null}
        {o?.needs_review ? (
          <span className="text-xs text-fg-muted">Some replies need a look before they count.</span>
        ) : null}
      </div>
      <p role="alert" className="px-4 pb-3 text-sm text-fg empty:hidden sm:px-5">
        {error}
      </p>
      <div className="flex items-center justify-between gap-3 border-t px-4 py-3 sm:px-5">
        <h4 className="type-subtitle text-fg">
          Replies <span className="text-fg-subtle tabular-nums">{replies.length}</span>
        </h4>
        {canWrite ? (
          <Button variant="outline" size="sm" onClick={() => setImporting(true)}>
            <Plus aria-hidden /> Add a reply
          </Button>
        ) : null}
      </div>
      <RepliesList replies={replies} />
      {canWrite ? (
        <>
          {setting ? (
            <SetOutcomeDialog report={r} open={setting} onOpenChange={setSetting} />
          ) : null}
          <ReplyImportDialog open={importing} onOpenChange={setImporting} report={r.public_id} />
        </>
      ) : null}
    </FindingCard>
  )
}
