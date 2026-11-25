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
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
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
          ? t("outcome_error_time")
          : e instanceof Error && e.message === "early"
            ? t("outcome_error_early")
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
            <DialogTitle>{t("outcome_dialog_title")}</DialogTitle>
            <DialogDescription>
              {t("outcome_dialog_description")}
            </DialogDescription>
          </DialogHeader>
          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium text-fg">{t("outcome_what_happened")}</legend>
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
                {o === "none" ? t("outcome_no_answer") : OUTCOME_LABEL[o]}
              </label>
            ))}
          </fieldset>
          <Field
            id={`${id}-at`}
            label={t("outcome_when")}
            hint={t("outcome_when_hint")}
          >
            <Input
              id={`${id}-at`}
              type="datetime-local"
              value={at}
              max={localInput(now)}
              onChange={(e) => setAt(e.target.value)}
            />
          </Field>
          <Field id={`${id}-note`} label={t("outcome_note")} optional>
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
              {t("common_cancel")}
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? t("outcome_saving") : t("outcome_save")}
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
      eyebrow={t("outcome_eyebrow")}
      finding={describeOutcome(o, r.sent_at)}
      detail={
        canWrite && r.reply_token
          ? t("outcome_token_detail", { token: r.reply_token })
          : undefined
      }
      action={
        canWrite ? (
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={() => setSetting(true)}>
              {t("outcome_set")}
            </Button>
            {o?.manual ? (
              <Button
                variant="ghost"
                size="sm"
                disabled={clear.isPending}
                onClick={() => clear.mutate()}
              >
                {t("outcome_back_to_automatic")}
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
            {tNodes(
              "outcome_set_by_you",
              { hasTime: o.manual_at ? "yes" : "no", hasNote: o.note ? "yes" : "no", note: o.note },
              o.manual_at ? { time: <RelativeTime iso={o.manual_at} /> } : {},
            )}
          </span>
        ) : o && o.reply_count > 0 ? (
          <span className="text-xs text-fg-muted">
            {t("outcome_worked_out", { count: o.reply_count })}
          </span>
        ) : null}
        {o?.needs_review ? (
          <span className="text-xs text-fg-muted">{t("outcome_needs_review")}</span>
        ) : null}
      </div>
      <p role="alert" className="px-4 pb-3 text-sm text-fg empty:hidden sm:px-5">
        {error}
      </p>
      <div className="flex items-center justify-between gap-3 border-t px-4 py-3 sm:px-5">
        <h4 className="type-subtitle text-fg">
          {tNodes(
            "outcome_replies_heading",
            {},
            { count: <span className="text-fg-subtle tabular-nums">{replies.length}</span> },
          )}
        </h4>
        {canWrite ? (
          <Button variant="outline" size="sm" onClick={() => setImporting(true)}>
            <Plus aria-hidden /> {t("outcome_add_reply")}
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
