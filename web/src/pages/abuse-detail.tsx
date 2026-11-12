import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  ArrowLeft,
  CircleCheck,
  FileSearch,
  FlaskConical,
  Info,
  TriangleAlert,
  RefreshCw,
} from "lucide-react"
import { useId, useState } from "react"
import { Link, useParams } from "react-router"
import { useAuth } from "@/app/auth"
import { SettingsCause } from "@/components/abuse/blocked-drafts"
import { CopyField } from "@/components/abuse/copy-field"
import { ExportMenu } from "@/components/abuse/export-menu"
import { OutcomeCard } from "@/components/abuse/outcome-card"
import { StatusStepper } from "@/components/abuse/status-stepper"
import { SendControl } from "@/components/abuse/send-control"
import { useSendMode } from "@/components/abuse/send-hooks"
import { inFlight } from "@/lib/abuse-send"
import { ConfirmDialog, MarkSentDialog } from "@/components/abuse/status-dialogs"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { IPChip } from "@/components/ip-chip"
import { PageHeader } from "@/components/page-header"
import { ReadOnlyBadge } from "@/components/read-only-badge"
import { RelativeTime } from "@/components/relative-time"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonCard } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { ApiError } from "@/lib/api"
import {
  abuseApi,
  abuseKeys,
  describeAbuseError,
  describeGuard,
  describeReport,
  downloadFile,
  FORMAT_OPTIONS,
  guardAdvice,
  guardReason,
  guardReasonsOf,
  missingSettingsOf,
  isStale,
  KIND_LABEL,
  nextActions,
  reviewBlocker,
  STATUS_LABEL,
  type FileFormat,
  type MessageFormat,
  type ReportDetail,
  type ReportOptions,
  type ReportStatus,
} from "@/lib/abuse"
import { MetaLine } from "@/components/meta-line"
import { formatAbsolute, formatNumber, plural } from "@/lib/format"
import { saveBlob } from "@/lib/samples"

const back = (
  <Link
    to="/defend/abuse"
    className="inline-flex items-center gap-1.5 text-fg-muted transition-colors hover:text-fg"
  >
    <ArrowLeft aria-hidden className="size-3.5" />
    Abuse reports
  </Link>
)

/* --- Identity check ------------------------------------------------------------------------ */

function IdentityCard({ r }: { r: ReportDetail }) {
  const ok = r.guard.ok
  return (
    <FindingCard
      eyebrow="Identity check"
      finding={describeGuard(r.guard, r.redaction)}
      detail={
        ok
          ? "Runs on every view and download. It looks for anything that could point back to you."
          : undefined
      }
      className={ok ? "normal-nums" : "border-sev-warning/40 normal-nums"}
    >
      <div className="flex items-start gap-2.5 text-sm">
        {ok ? (
          <>
            <CircleCheck aria-hidden className="mt-0.5 size-4 shrink-0 text-status-ok" />
            <span className="font-medium text-fg">Checked</span>
          </>
        ) : (
          <>
            <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-sev-warning" />
            <div className="space-y-2">
              <span className="font-medium text-fg">Blocked</span>
              <ul className="list-disc space-y-1.5 pl-5">
                {(r.guard.codes.length > 0 ? r.guard.codes : ["unknown"]).map((c) => {
                  const { why, fix } = guardAdvice(c)
                  return (
                    <li key={c}>
                      <span className="text-fg">{why}</span>{" "}
                      <span className="text-fg-muted">{fix}</span>
                    </li>
                  )
                })}
              </ul>
              <SettingsCause />
              <p className="text-fg-muted">
                Nothing is sent while a draft is blocked. The words the check looks for are listed
                in{" "}
                <Link
                  to="/settings?tab=reporting#reporting-never"
                  className="font-medium text-fg underline underline-offset-4"
                >
                  Settings, Reporting, Never in a report
                </Link>
                .
              </p>
            </div>
          </>
        )}
      </div>
    </FindingCard>
  )
}

/* --- Message ------------------------------------------------------------------------------- */

function MessageCard({ r }: { r: ReportDetail }) {
  const [format, setFormat] = useState<MessageFormat>("text")
  const [fileError, setFileError] = useState<string | null>(null)
  const q = useQuery({
    queryKey: abuseKeys.render(r.public_id, format, r.revision),
    queryFn: () => abuseApi.render(r.public_id, format),
    retry: false,
    enabled: r.guard.ok,
  })
  const reasons = guardReasonsOf(q.error)
  const apiError = q.error instanceof ApiError ? q.error : null
  const missing = missingSettingsOf(q.error)

  async function save(f: FileFormat, fallback: string) {
    setFileError(null)
    try {
      const { blob, filename } = await downloadFile(r.public_id, f)
      saveBlob(blob, filename ?? fallback)
    } catch (e) {
      const why = guardReasonsOf(e)
      setFileError(why ? why.map(guardReason).join(" ") : describeAbuseError(e))
    }
  }

  const short = r.public_id.slice(0, 8)
  const m = q.data
  return (
    <FindingCard
      eyebrow="Message"
      finding={
        r.guard.ok
          ? `Ready to copy into your own mailbox, addressed to ${r.recipient.mailbox ?? "no one yet"}.`
          : "This message is held back until the identity check passes."
      }
      action={
        <SegmentedControl
          label="Message format"
          value={format}
          onChange={setFormat}
          options={FORMAT_OPTIONS}
        />
      }
    >
      {!r.guard.ok ? (
        <p className="text-sm text-fg-muted">See the identity check above.</p>
      ) : q.isPending ? (
        <div aria-busy className="space-y-3">
          <SkeletonCard />
        </div>
      ) : q.isError ? (
        <div role="alert" className="space-y-2 text-sm text-fg-muted">
          <p className="font-medium text-fg">
            {reasons ? "Blocked by the identity check." : "This format is not available."}
          </p>
          <p>
            {reasons
              ? reasons.map(guardReason).join(" ")
              : apiError?.code === "settings_incomplete"
                ? "Set a reply contact in the Reporting settings before a message can be written. The texts around the facts are optional."
                : describeAbuseError(q.error)}
          </p>
          {apiError?.code === "settings_incomplete" ? (
            <Link
              to={`/settings?tab=reporting${missing.length ? `&missing=${missing.join(",")}` : ""}`}
              className="font-medium text-fg underline underline-offset-4"
            >
              Set a reply contact in Settings
            </Link>
          ) : null}
        </div>
      ) : m ? (
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <CopyField label="To" value={m.to} />
            <CopyField label="Subject" value={m.subject} />
          </div>
          <CopyField label="Body" value={m.body} multiline />
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-fg-muted">Attach to your message:</span>
            <Button variant="outline" size="xs" onClick={() => void save("txt", `report.txt`)}>
              report.txt
            </Button>
            <Button
              variant="outline"
              size="xs"
              onClick={() => void save("evidence_csv", "evidence.csv")}
            >
              evidence.csv
            </Button>
            {format === "eml" ? (
              <Button
                variant="outline"
                size="xs"
                onClick={() => void save("eml", `abuse-${short}.eml`)}
              >
                abuse-{short}.eml
              </Button>
            ) : null}
            {format === "xarf" ? (
              <Button
                variant="outline"
                size="xs"
                onClick={() => void save("xarf_yaml", "report.yaml")}
              >
                report.yaml
              </Button>
            ) : null}
          </div>
          <p role="status" className="text-xs text-fg-muted empty:hidden">
            {fileError}
          </p>
        </div>
      ) : null}
    </FindingCard>
  )
}

/* --- Subjects ------------------------------------------------------------------------------ */

function SubjectsCard({ r }: { r: ReportDetail }) {
  return (
    <FindingCard
      eyebrow="In this report"
      finding={`${r.kind === "attack_source" ? plural(r.subjects.length, "address", "addresses") : plural(r.subjects.length, "host")} in this report.`}
      detail="These links open the dashboard and exist only here: they are never part of the message."
      className="normal-nums"
      bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
    >
      <ul aria-label="Addresses and hosts in this report" className="divide-y border-t sm:hidden">
        {r.subjects.map((s) => (
          <li key={`${s.subject_type}:${s.value}`} className="px-4 py-3">
            {s.subject_type === "ip" ? (
              <IPChip ip={s.value} href={s.link} />
            ) : (
              <Link
                to={s.link}
                className="font-mono text-xs break-all text-fg underline-offset-4 hover:underline"
              >
                {s.value}
              </Link>
            )}
            <MetaLine className="mt-1.5">
              {s.asn || s.network ? (
                <span>
                  {s.asn ? `AS${s.asn}` : null}
                  {s.asn && s.network ? " " : null}
                  {s.network}
                </span>
              ) : null}
              <span>{plural(s.sessions, "session")}</span>
              <span>
                last <RelativeTime iso={s.last_ts} />
              </span>
            </MetaLine>
          </li>
        ))}
      </ul>
      <div className="overflow-x-auto sm:border-t">
        <table className="hidden w-full text-left text-sm sm:table">
          <caption className="sr-only">Addresses and hosts in this report</caption>
          <thead className="text-xs text-fg-muted">
            <tr className="border-b">
              <th scope="col" className="px-4 py-2 font-medium sm:px-5">
                {r.kind === "attack_source" ? "Address" : "Host"}
              </th>
              <th scope="col" className="px-2 py-2 font-medium">
                Network
              </th>
              <th scope="col" className="px-2 py-2 text-right font-medium">
                Sessions
              </th>
              <th scope="col" className="px-4 py-2 font-medium sm:px-5">
                Last seen
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {r.subjects.map((s) => (
              <tr key={`${s.subject_type}:${s.value}`}>
                <td className="px-4 py-2 sm:px-5">
                  {s.subject_type === "ip" ? (
                    <IPChip ip={s.value} href={s.link} />
                  ) : (
                    <Link
                      to={s.link}
                      className="font-mono text-xs text-fg underline-offset-4 hover:underline"
                    >
                      {s.value}
                    </Link>
                  )}
                </td>
                <td className="px-2 py-2 text-fg-muted">
                  {s.asn ? (
                    <Link
                      to={`/attackers?asn=${s.asn}`}
                      className="font-mono text-xs text-fg-muted hover:text-fg"
                    >
                      AS{s.asn}
                    </Link>
                  ) : null}
                  {s.network ? <span className="ml-1.5">{s.network}</span> : null}
                </td>
                <td className="px-2 py-2 text-right tabular-nums">{formatNumber(s.sessions)}</td>
                <td className="px-4 py-2 sm:px-5">
                  <RelativeTime iso={s.last_ts} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </FindingCard>
  )
}

/* --- Notes and options --------------------------------------------------------------------- */

const OPTION_LABEL: { key: keyof ReportOptions; label: string; hint: string }[] = [
  {
    key: "defang",
    label: "Defang URLs and addresses",
    hint: "hxxp://203.0.113[.]9 instead of a live link.",
  },
  { key: "include_usernames", label: "Include the usernames tried", hint: "Never the passwords." },
  {
    key: "show_redaction_counts",
    label: "Add the redaction counter line",
    hint: "How many values were masked and lines left out. Off by default.",
  },
  {
    key: "include_reply_contact",
    label: "Include the reply contact",
    hint: "So the abuse desk can answer.",
  },
]

function NotesCard({ r, onSaved }: { r: ReportDetail; onSaved: (d: ReportDetail) => void }) {
  const { canWrite } = useAuth()
  const id = useId()
  const editable = canWrite && (r.status === "draft" || r.status === "reviewed")
  const [notes, setNotes] = useState(r.notes ?? "")
  const [error, setError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: (body: Parameters<typeof abuseApi.patch>[1]) => abuseApi.patch(r.public_id, body),
    onSuccess: (d) => {
      setError(null)
      onSaved(d)
    },
    onError: (e) => setError(describeAbuseError(e)),
  })
  const minute = r.options.time_precision === "minute"
  return (
    <FindingCard
      eyebrow="Notes and options"
      finding="Notes stay here. Options change what the message says."
    >
      <div className="grid gap-6 md:grid-cols-2">
        <div className="space-y-2">
          <label htmlFor={id} className="text-sm font-medium text-fg">
            Your notes
          </label>
          {editable ? (
            <>
              <Textarea
                id={id}
                value={notes}
                maxLength={4000}
                rows={4}
                onChange={(e) => setNotes(e.target.value)}
              />
              <Button
                size="sm"
                variant="outline"
                disabled={save.isPending || notes === (r.notes ?? "")}
                onClick={() => save.mutate({ notes: notes.trim() === "" ? null : notes })}
              >
                Save notes
              </Button>
            </>
          ) : (
            <p id={id} className="text-sm whitespace-pre-wrap text-fg-muted">
              {r.notes ?? "No notes."}
            </p>
          )}
        </div>
        <fieldset className="space-y-3" disabled={!editable}>
          <legend className="text-sm font-medium text-fg">Options</legend>
          <div className="flex items-start gap-3">
            <Switch
              id={`${id}-minute`}
              checked={minute}
              disabled={!editable}
              onCheckedChange={(on) =>
                save.mutate({ options: { time_precision: on ? "minute" : "second" } })
              }
              className="mt-0.5"
            />
            <label htmlFor={`${id}-minute`} className="text-sm text-fg">
              Round times to the minute
              <span className="block text-xs text-fg-muted">
                Exact seconds make it easier to match flow logs, and so to recognise you.
              </span>
            </label>
          </div>
          {OPTION_LABEL.map((o) => (
            <div key={o.key} className="flex items-start gap-3">
              <Switch
                id={`${id}-${o.key}`}
                checked={Boolean(r.options[o.key])}
                disabled={!editable}
                onCheckedChange={(on) => save.mutate({ options: { [o.key]: on } })}
                className="mt-0.5"
              />
              <label htmlFor={`${id}-${o.key}`} className="text-sm text-fg">
                {o.label}
                <span className="block text-xs text-fg-muted">{o.hint}</span>
              </label>
            </div>
          ))}
        </fieldset>
      </div>
      <p role="alert" className="mt-3 text-sm text-fg empty:hidden">
        {error}
      </p>
    </FindingCard>
  )
}

/* --- History ------------------------------------------------------------------------------- */

function HistoryCard({ r }: { r: ReportDetail }) {
  return (
    <FindingCard
      eyebrow="History"
      finding={`Last change: ${STATUS_LABEL[r.status].toLowerCase()}.`}
      bodyClassName="px-0 sm:px-0 pb-1 sm:pb-1"
    >
      <ol className="divide-y border-t">
        {[...r.history].reverse().map((h, i) => (
          <li
            key={i}
            className="flex flex-wrap items-center gap-x-3 gap-y-0.5 px-4 py-2 text-sm sm:px-5"
          >
            <span className="font-medium text-fg">
              {h.from
                ? `${STATUS_LABEL[h.from]} to ${STATUS_LABEL[h.to]}`
                : `${STATUS_LABEL[h.to]} written`}
            </span>
            <span className="text-fg-muted">
              {h.actor === "ingest" ? "automatically" : `by ${h.actor}`}
            </span>
            <RelativeTime iso={h.ts} className="ml-auto" />
          </li>
        ))}
      </ol>
    </FindingCard>
  )
}

/* --- Actions ------------------------------------------------------------------------------- */

function Actions({
  r,
  onChanged,
}: {
  r: ReportDetail
  onChanged: (d: ReportDetail | null, message?: string) => void
}) {
  const { canWrite } = useAuth()
  const mode = useSendMode()
  const [sentOpen, setSentOpen] = useState(false)
  const [confirm, setConfirm] = useState<"discarded" | "draft" | "regenerate" | null>(null)
  const [error, setError] = useState<string | null>(null)
  if (!canWrite) return null
  const next = nextActions(r.status)
  const blocker = reviewBlocker(r)

  async function step(to: ReportStatus, sentAt?: string) {
    try {
      const d = await abuseApi.setStatus(r.public_id, {
        to,
        revision: r.revision,
        ...(sentAt ? { sent_at: sentAt } : {}),
      })
      setError(null)
      onChanged(d)
    } catch (e) {
      if (isStale(e)) onChanged(null, describeAbuseError(e))
      setError(describeAbuseError(e))
      throw e
    }
  }
  const go = (to: ReportStatus) => void step(to).catch(() => undefined)

  const canRegenerate = r.status === "draft" || r.status === "reviewed"
  if (next.length === 0 && !canRegenerate) return null
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {next.includes("reviewed") ? (
          <Button size="sm" disabled={blocker !== null} onClick={() => go("reviewed")}>
            Mark reviewed
          </Button>
        ) : null}
        {next.includes("sent") && !r.demo ? (
          <Button
            size="sm"
            variant={mode === "click" ? "outline" : "default"}
            onClick={() => setSentOpen(true)}
          >
            Mark sent
          </Button>
        ) : null}
        {next.includes("closed") ? (
          <Button size="sm" onClick={() => go("closed")}>
            Mark as closed
          </Button>
        ) : null}
        {next.includes("draft") ? (
          <Button size="sm" variant="outline" onClick={() => setConfirm("draft")}>
            Reopen as draft
          </Button>
        ) : null}
        {canRegenerate ? (
          <Button size="sm" variant="outline" onClick={() => setConfirm("regenerate")}>
            <RefreshCw aria-hidden /> Regenerate
          </Button>
        ) : null}
        {next.includes("discarded") ? (
          <Button size="sm" variant="ghost" onClick={() => setConfirm("discarded")}>
            Discard
          </Button>
        ) : null}
      </div>
      {r.status === "draft" || r.status === "reviewed" ? (
        <SendControl
          reportId={r.public_id}
          recipient={r.recipient.mailbox ?? r.recipient.name}
          // A draft is read first: "Send now" appears once it is marked reviewed, so each state
          // has one obvious next step.
          ready={
            r.status === "reviewed" &&
            !r.demo &&
            r.guard.ok &&
            Boolean(r.recipient.mailbox) &&
            r.missing.length === 0
          }
          scheduledAt={r.send_state?.scheduled_at ?? null}
          lastRequest={r.send_state?.last_request ?? null}
          revision={r.revision}
          primary={r.status !== "draft"}
        />
      ) : null}
      {r.status === "draft" && blocker ? (
        <p className="flex items-start gap-2 text-sm text-fg-muted">
          <Info aria-hidden className="mt-0.5 size-4 shrink-0" />
          <span>
            {blocker}{" "}
            {r.missing.length > 0 ? (
              <Link
                to="/settings?tab=reporting"
                className="font-medium text-fg underline underline-offset-4"
              >
                Open Settings
              </Link>
            ) : null}
          </span>
        </p>
      ) : null}
      {r.demo ? (
        <p className="text-sm text-fg-muted">Demo reports cannot be marked as sent.</p>
      ) : null}
      <p role="alert" className="text-sm text-fg empty:hidden">
        {error}
      </p>
      <MarkSentDialog
        open={sentOpen}
        onOpenChange={setSentOpen}
        describe={describeAbuseError}
        run={(at) => step("sent", at)}
      />
      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={
          confirm === "discarded"
            ? "Discard this report?"
            : confirm === "draft"
              ? "Reopen this report as a draft?"
              : "Rebuild this draft?"
        }
        description={
          confirm === "discarded"
            ? "It will not be sent. These addresses are reported again only if they attack again."
            : confirm === "draft"
              ? "The review is cleared, so you read the message again before it can be marked sent."
              : "The draft is rebuilt from the latest data. A reviewed report goes back to draft."
        }
        confirmLabel={
          confirm === "discarded" ? "Discard" : confirm === "draft" ? "Reopen" : "Regenerate"
        }
        describe={describeAbuseError}
        run={async () => {
          if (confirm === "regenerate") {
            await abuseApi.regenerate(r.public_id)
            onChanged(null)
          } else if (confirm) await step(confirm)
        }}
      />
    </div>
  )
}

/* --- Page ---------------------------------------------------------------------------------- */

export function AbuseDetailPage() {
  const { publicId = "" } = useParams()
  const { canWrite } = useAuth()
  const qc = useQueryClient()
  const q = useQuery({
    queryKey: abuseKeys.report(publicId),
    queryFn: () => abuseApi.report(publicId),
    retry: false,
    // While a send is waiting or on its way the report changes by itself.
    refetchInterval: (query) => {
      const s = query.state.data?.send_state
      return s?.scheduled_at || inFlight(s?.last_request?.status) ? 4000 : false
    },
  })
  const [notice, setNotice] = useState<string | null>(null)
  const refresh = (d: ReportDetail | null, message?: string) => {
    setNotice(message ?? null)
    if (d) qc.setQueryData(abuseKeys.report(publicId), d)
    void qc.invalidateQueries({ queryKey: abuseKeys.all })
  }

  if (q.isError) {
    const gone = q.error instanceof ApiError && q.error.status === 404
    return (
      <>
        <PageHeader help="abuse-report" title="Abuse report" eyebrow={back} />
        <EmptyState
          icon={FileSearch}
          title={gone ? "This report does not exist" : "Could not load this report"}
          description={
            gone
              ? "It may have been replaced by a newer draft, or the link is wrong."
              : q.error.message
          }
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/defend/abuse">Back to the reports</Link>
            </Button>
          }
        />
      </>
    )
  }
  if (!q.data) {
    return (
      <>
        <PageHeader help="abuse-report" title="Abuse report" eyebrow={back} />
        <div className="space-y-4" aria-busy>
          <SkeletonCard />
          <SkeletonCard />
        </div>
      </>
    )
  }
  const r = q.data
  return (
    <>
      <PageHeader
        help="abuse-report"
        eyebrow={back}
        title={r.recipient.name}
        description={<span className="normal-nums">{describeReport(r)}</span>}
        actions={
          <>
            <ReadOnlyBadge />
            <ExportMenu
              scope={{ report: r.public_id }}
              blockedReason={
                r.guard.ok
                  ? undefined
                  : "The identity check blocked this report, so it cannot be exported."
              }
            />
          </>
        }
      />
      <div className="space-y-4">
        {r.demo ? (
          <p
            role="note"
            className="flex items-center gap-2 rounded-md border border-dashed border-border-strong px-3 py-2 text-sm text-fg"
          >
            <FlaskConical aria-hidden className="size-4 text-fg-muted" />
            Demo data, do not send.
          </p>
        ) : null}
        {notice ? (
          <p
            role="status"
            className="rounded-md border border-border-strong bg-surface-raised px-3 py-2 text-sm text-fg"
          >
            {notice}
          </p>
        ) : null}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-xs text-fg-muted">
          <span className="font-medium text-fg">{KIND_LABEL[r.kind]}</span>
          <span className="font-mono">{r.recipient.mailbox ?? "no mailbox yet"}</span>
          {r.recipient.shared_mailbox ? (
            <span>Replies from this contact are trusted by exact address only.</span>
          ) : null}
          {r.previously_reported ? (
            <span>Previously reported on {formatAbsolute(r.previously_reported)}</span>
          ) : null}
        </div>
        <StatusStepper status={r.status} />
        {canWrite ? null : (
          <p className="text-sm text-fg-muted">
            You can read everything here. Only an administrator changes a report.
          </p>
        )}
        <Actions r={r} onChanged={refresh} />
        {r.status === "sent" || r.status === "closed" ? <OutcomeCard r={r} /> : null}
        <IdentityCard r={r} />
        <MessageCard r={r} />
        <SubjectsCard r={r} />
        <NotesCard key={`${r.revision}:${r.notes ?? ""}`} r={r} onSaved={(d) => refresh(d)} />
        <HistoryCard r={r} />
      </div>
    </>
  )
}
