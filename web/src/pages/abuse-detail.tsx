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
import { DeskNotice } from "@/components/abuse/desk-notice"
import { FormSwitch } from "@/components/abuse/form-switch"
import { StrictSwitch } from "@/components/abuse/strict-switch"
import { OutcomeBadge } from "@/components/results/badges"
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
import { t, tk } from "@/i18n"
import { tNodes } from "@/i18n/rich"
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
  KIND_HEADING,
  KINDS,
  kindLabel,
  lowerNoun,
  nextActions,
  reviewBlocker,
  STATUS_LABEL,
  type FileFormat,
  type MessageFormat,
  type ReportDetail,
  type ReportOptions,
  type ReportStatus,
  type ReportSubject,
  withSameDayConfirm,
} from "@/lib/abuse"
import { MetaLine } from "@/components/meta-line"
import { formatAbsolute, formatNumber } from "@/lib/format"
import { saveBlob } from "@/lib/samples"

function BackLink() {
  return (
    <Link
      to="/defend/abuse"
      className="inline-flex items-center gap-1.5 text-fg-muted transition-colors hover:text-fg"
    >
      <ArrowLeft aria-hidden className="size-3.5" />
      {t("abuse_page_title")}
    </Link>
  )
}

/* --- Identity check ------------------------------------------------------------------------ */

function IdentityCard({ r }: { r: ReportDetail }) {
  const ok = r.guard.ok
  return (
    <FindingCard
      eyebrow={t("abuse_detail_identity")}
      finding={describeGuard(r.guard, r.redaction)}
      detail={ok ? t("abuse_detail_identity_detail") : undefined}
      className={ok ? "normal-nums" : "border-sev-warning/40 normal-nums"}
    >
      <div className="flex items-start gap-2.5 text-sm">
        {ok ? (
          <>
            <CircleCheck aria-hidden className="mt-0.5 size-4 shrink-0 text-status-ok" />
            <span className="font-medium text-fg">{t("abuse_row_checked")}</span>
          </>
        ) : (
          <>
            <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-sev-warning" />
            <div className="space-y-2">
              <span className="font-medium text-fg">{t("abuse_row_blocked")}</span>
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
                {tNodes(
                  "abuse_detail_blocked_note",
                  {},
                  {
                    link: (
                      <Link
                        to="/settings?tab=reporting#reporting-never"
                        className="font-medium text-fg underline underline-offset-4"
                      >
                        {t("abuse_detail_blocked_link")}
                      </Link>
                    ),
                  },
                )}
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

  async function save(f: FileFormat, fallback: string, subject?: string, kind?: string) {
    setFileError(null)
    try {
      const { blob, filename } = await downloadFile(r.public_id, f, subject, kind)
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
      eyebrow={t("send_queue_field_message")}
      finding={
        r.guard.ok
          ? t("abuse_detail_message_ready", { to: r.recipient.mailbox ?? t("abuse_detail_no_one") })
          : t("abuse_detail_message_held")
      }
      action={
        <SegmentedControl
          label={t("abuse_detail_format_aria")}
          value={format}
          onChange={setFormat}
          options={FORMAT_OPTIONS}
        />
      }
    >
      {!r.guard.ok ? (
        <p className="text-sm text-fg-muted">{t("abuse_detail_see_check")}</p>
      ) : q.isPending ? (
        <div aria-busy className="space-y-3">
          <SkeletonCard />
        </div>
      ) : q.isError ? (
        <div role="alert" className="space-y-2 text-sm text-fg-muted">
          <p className="font-medium text-fg">
            {reasons ? t("abuse_detail_blocked_title") : t("abuse_detail_format_unavailable")}
          </p>
          <p>
            {reasons
              ? reasons.map(guardReason).join(" ")
              : apiError?.code === "settings_incomplete"
                ? t("abuse_detail_settings_incomplete")
                : describeAbuseError(q.error)}
          </p>
          {apiError?.code === "settings_incomplete" ? (
            <Link
              to={`/settings?tab=reporting${missing.length ? `&missing=${missing.join(",")}` : ""}`}
              className="font-medium text-fg underline underline-offset-4"
            >
              {t("abuse_detail_set_contact")}
            </Link>
          ) : null}
        </div>
      ) : m && format === "xarf" ? (
        <XarfFiles r={r} files={m.attachments} onSave={save} error={fileError} />
      ) : m ? (
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <CopyField label={t("abuse_detail_field_to")} value={m.to} />
            <CopyField label={t("send_queue_field_subject")} value={m.subject} />
          </div>
          <CopyField label={t("abuse_detail_field_body")} value={m.body} multiline />
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-fg-muted">{t("abuse_detail_attach")}</span>
            <Button variant="outline" size="sm" onClick={() => void save("txt", `report.txt`)}>
              report.txt
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void save("evidence_csv", "evidence.csv")}
            >
              evidence.csv
            </Button>
            {format === "eml" ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => void save("eml", `abuse-${short}.eml`)}
              >
                abuse-{short}.eml
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

/**
 * The X-ARF tab: one JSON report per source, exactly what the mail carries, read only, each with
 * a copy and a download button.
 */
function XarfFiles({
  r,
  files,
  onSave,
  error,
}: {
  r: ReportDetail
  files: { name: string; content: string }[]
  onSave: (f: FileFormat, fallback: string, subject?: string, kind?: string) => Promise<void>
  error: string | null
}) {
  const sourceOf = (name: string) => r.subjects.find((s) => s.xarf_file === name)
  return (
    <div className="space-y-4">
      <p className="text-sm text-fg-muted">
        {t("abuse_detail_xarf_intro", { count: files.length, file: "xarf.json" })}
      </p>
      {files.map((f) => {
        const found = sourceOf(f.name)
        const source = found?.value
        return (
          <div key={f.name} className="space-y-2">
            <CopyField
              label={source ? `${f.name} (${source})` : f.name}
              value={f.content}
              multiline
            />
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                void onSave(
                  "xarf_json",
                  f.name,
                  files.length > 1 ? source : undefined,
                  files.length > 1 ? found?.kind : undefined,
                )
              }
            >
              {t("abuse_form_kit_download", { name: f.name })}
            </Button>
          </div>
        )
      })}
      <p role="status" className="text-xs text-fg-muted empty:hidden">
        {error}
      </p>
    </div>
  )
}

/* --- Subjects ------------------------------------------------------------------------------ */

/** The marks of one source: its outcome, its X-ARF file, and whether it is too old to go alone. */
function SubjectMarks({ s }: { s: ReportSubject }) {
  if (!s.outcome && !s.stale && !s.xarf_file) return null
  return (
    <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-fg-muted">
      {s.outcome ? <OutcomeBadge outcome={s.outcome} className="-ml-1" /> : null}
      {s.stale ? (
        <span title={t("abuse_detail_stale_title")}>{t("abuse_form_kit_stale")}</span>
      ) : null}
      {s.xarf_file ? <span className="font-mono">{s.xarf_file}</span> : null}
    </span>
  )
}

/** Sources by kind, in the order of the mail (attack sources, payload hosts, command servers). */
function groupSubjects(r: ReportDetail): { kind: string | null; items: ReportSubject[] }[] {
  if (r.kind !== "digest") return [{ kind: null, items: r.subjects }]
  return KINDS.map((k) => ({
    kind: t("abuse_detail_group_heading", {
      heading: KIND_HEADING[k],
      count: r.subjects.filter((s) => s.kind === k).length,
    }),
    items: r.subjects.filter((s) => s.kind === k),
  })).filter((g) => g.items.length > 0)
}

function SubjectsCard({ r }: { r: ReportDetail }) {
  const groups = groupSubjects(r)
  return (
    <FindingCard
      eyebrow={t("abuse_detail_subjects")}
      finding={t("abuse_detail_subjects_finding", { kind: r.kind, count: r.subjects.length })}
      detail={t("abuse_detail_subjects_detail")}
      className="normal-nums"
      bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
    >
      {groups.map((g) => (
        <SubjectGroup key={g.kind ?? "all"} r={r} heading={g.kind} subjects={g.items} />
      ))}
    </FindingCard>
  )
}

function SubjectGroup({
  r,
  heading,
  subjects,
}: {
  r: ReportDetail
  heading: string | null
  subjects: ReportSubject[]
}) {
  return (
    <section aria-label={heading ?? t("abuse_detail_subjects_aria")}>
      {heading ? (
        <h3 className="border-t px-4 pt-3 pb-1 type-subtitle text-fg sm:px-5">{heading}</h3>
      ) : null}
      <ul aria-label={t("abuse_detail_subjects_aria")} className="divide-y border-t sm:hidden">
        {subjects.map((s) => (
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
              <span>{t("abuse_detail_sessions", { count: s.sessions })}</span>
              <span>
                {tNodes("abuse_detail_last", {}, { time: <RelativeTime iso={s.last_ts} /> })}
              </span>
            </MetaLine>
            <div className="mt-1.5">
              <SubjectMarks s={s} />
            </div>
          </li>
        ))}
      </ul>
      <div className="overflow-x-auto sm:border-t">
        <table className="hidden w-full text-left text-sm sm:table">
          <caption className="sr-only">{t("abuse_detail_subjects_aria")}</caption>
          <thead className="text-xs text-fg-muted">
            <tr className="border-b">
              <th scope="col" className="px-4 py-2 font-medium sm:px-5">
                {r.kind === "attack_source"
                  ? t("abuse_form_field_address")
                  : r.kind === "digest"
                    ? t("abuse_detail_col_source")
                    : t("abuse_detail_col_host")}
              </th>
              <th scope="col" className="px-2 py-2 font-medium">
                {t("abuse_detail_col_network")}
              </th>
              <th scope="col" className="px-2 py-2 text-right font-medium">
                {t("abuse_detail_col_sessions")}
              </th>
              <th scope="col" className="px-4 py-2 font-medium sm:px-5">
                {t("abuse_form_field_last_seen")}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {subjects.map((s) => (
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
                  <div className="mt-1">
                    <SubjectMarks s={s} />
                  </div>
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
    </section>
  )
}

/* --- Notes and options --------------------------------------------------------------------- */

const OPTION_LABEL: { key: keyof ReportOptions; labelKey: string; hintKey: string }[] = [
  {
    key: "defang",
    labelKey: tk("reporting_defang"),
    hintKey: tk("reporting_defang_hint"),
  },
  {
    key: "include_usernames",
    labelKey: tk("reporting_usernames"),
    hintKey: tk("reporting_usernames_hint"),
  },
  {
    key: "show_redaction_counts",
    labelKey: tk("reporting_redaction"),
    hintKey: tk("reporting_redaction_hint"),
  },
  {
    key: "include_reply_contact",
    labelKey: tk("reporting_include_contact"),
    hintKey: tk("abuse_detail_contact_hint"),
  },
]

/** Saves a patch of the report; both the options and the notes cards use it. */
function useReportPatch(r: ReportDetail, onSaved: (d: ReportDetail) => void) {
  const [error, setError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: (body: Parameters<typeof abuseApi.patch>[1]) => abuseApi.patch(r.public_id, body),
    onSuccess: (d) => {
      setError(null)
      onSaved(d)
    },
    onError: (e) => setError(describeAbuseError(e)),
  })
  return { save, error }
}

/** The switches that change what the message says: they sit right under the message. */
function OptionsCard({ r, onSaved }: { r: ReportDetail; onSaved: (d: ReportDetail) => void }) {
  const { canWrite } = useAuth()
  const id = useId()
  const editable = canWrite && (r.status === "draft" || r.status === "reviewed")
  const { save, error } = useReportPatch(r, onSaved)
  const minute = r.options.time_precision === "minute"
  return (
    <FindingCard eyebrow={t("abuse_detail_options")} finding={t("abuse_detail_options_finding")}>
      <fieldset className="space-y-3" disabled={!editable}>
        <legend className="sr-only">{t("abuse_detail_options")}</legend>
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
            {t("reporting_round_times")}
            <span className="block text-xs text-fg-muted">{t("abuse_detail_round_hint")}</span>
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
              {t(o.labelKey)}
              <span className="block text-xs text-fg-muted">
                {t(o.hintKey, { example: "hxxp://203.0.113[.]9" })}
              </span>
            </label>
          </div>
        ))}
      </fieldset>
      <p role="alert" className="mt-3 text-sm text-fg empty:hidden">
        {error}
      </p>
    </FindingCard>
  )
}

function NotesCard({ r, onSaved }: { r: ReportDetail; onSaved: (d: ReportDetail) => void }) {
  const { canWrite } = useAuth()
  const id = useId()
  const editable = canWrite && (r.status === "draft" || r.status === "reviewed")
  const [notes, setNotes] = useState(r.notes ?? "")
  const { save, error } = useReportPatch(r, onSaved)
  return (
    <FindingCard eyebrow={t("abuse_detail_notes")} finding={t("abuse_detail_notes_finding")}>
      <div className="space-y-2">
        <label htmlFor={id} className="text-sm font-medium text-fg">
          {t("abuse_detail_your_notes")}
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
              {t("abuse_detail_save_notes")}
            </Button>
          </>
        ) : (
          <p id={id} className="text-sm whitespace-pre-wrap text-fg-muted">
            {r.notes ?? t("abuse_detail_no_notes")}
          </p>
        )}
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
      eyebrow={t("abuse_detail_history")}
      finding={t("abuse_detail_last_change", { status: lowerNoun(STATUS_LABEL[r.status]) })}
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
                ? t("abuse_detail_history_move", {
                    from: STATUS_LABEL[h.from],
                    to: STATUS_LABEL[h.to],
                  })
                : t("abuse_detail_history_written", { status: STATUS_LABEL[h.to] })}
            </span>
            <span className="text-fg-muted">
              {h.actor === "ingest"
                ? t("abuse_detail_history_auto")
                : t("abuse_detail_history_by", { actor: h.actor })}
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
      const run = (confirm: boolean) =>
        abuseApi.setStatus(r.public_id, {
          to,
          revision: r.revision,
          ...(sentAt ? { sent_at: sentAt } : {}),
          ...(confirm ? { confirm_same_day: true } : {}),
        })
      // A provider gets one mail a day: a second "sent" today asks first.
      const d = to === "sent" ? await withSameDayConfirm(run) : await run(false)
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
    // Sticky under the page header, so the review actions stay in reach while the message is read.
    <div className="sticky top-14 z-10 -mx-1 space-y-3 border-b bg-bg px-1 py-3">
      <div className="flex flex-wrap items-center gap-2">
        {next.includes("reviewed") ? (
          <Button size="sm" disabled={blocker !== null} onClick={() => go("reviewed")}>
            {t("abuse_detail_mark_reviewed")}
          </Button>
        ) : null}
        {next.includes("sent") && !r.demo ? (
          <Button
            size="sm"
            variant={mode === "click" ? "outline" : "default"}
            onClick={() => setSentOpen(true)}
          >
            {t("abuse_detail_mark_sent")}
          </Button>
        ) : null}
        {next.includes("closed") ? (
          <Button size="sm" onClick={() => go("closed")}>
            {t("abuse_detail_mark_closed")}
          </Button>
        ) : null}
        {next.includes("draft") ? (
          <Button size="sm" variant="outline" onClick={() => setConfirm("draft")}>
            {t("abuse_detail_reopen")}
          </Button>
        ) : null}
        {canRegenerate ? (
          <Button size="sm" variant="outline" onClick={() => setConfirm("regenerate")}>
            <RefreshCw aria-hidden /> {t("abuse_detail_regenerate")}
          </Button>
        ) : null}
        {next.includes("discarded") ? (
          <Button size="sm" variant="ghost" onClick={() => setConfirm("discarded")}>
            {t("abuse_detail_discard")}
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
                {t("abuse_page_open_settings")}
              </Link>
            ) : null}
          </span>
        </p>
      ) : null}
      {r.demo ? <p className="text-sm text-fg-muted">{t("abuse_detail_demo_no_send")}</p> : null}
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
            ? t("abuse_detail_discard_title")
            : confirm === "draft"
              ? t("abuse_detail_reopen_title")
              : t("abuse_detail_regenerate_title")
        }
        description={
          confirm === "discarded"
            ? t("abuse_detail_discard_description")
            : confirm === "draft"
              ? t("abuse_detail_reopen_description")
              : t("abuse_detail_regenerate_description")
        }
        confirmLabel={
          confirm === "discarded"
            ? t("abuse_detail_discard")
            : confirm === "draft"
              ? t("abuse_detail_reopen_confirm")
              : t("abuse_detail_regenerate")
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
        <PageHeader help="abuse-report" title={t("abuse_detail_title")} eyebrow={<BackLink />} />
        <EmptyState
          icon={FileSearch}
          title={gone ? t("abuse_detail_gone") : t("abuse_detail_load_failed")}
          description={gone ? t("abuse_detail_gone_description") : q.error.message}
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/defend/abuse">{t("abuse_detail_back_to_reports")}</Link>
            </Button>
          }
        />
      </>
    )
  }
  if (!q.data) {
    return (
      <>
        <PageHeader help="abuse-report" title={t("abuse_detail_title")} eyebrow={<BackLink />} />
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
        eyebrow={<BackLink />}
        title={r.recipient.name}
        description={<span className="normal-nums">{describeReport(r)}</span>}
        actions={
          <>
            <ReadOnlyBadge />
            <ExportMenu
              scope={{ report: r.public_id }}
              blockedReason={r.guard.ok ? undefined : t("abuse_detail_export_blocked")}
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
            {t("abuse_detail_demo")}
          </p>
        ) : null}
        <DeskNotice
          recipient={r.recipient}
          asns={r.asns.map((a) => a.asn)}
          onChanged={() => refresh(null)}
        />
        <StrictSwitch recipient={r.recipient} onChanged={() => refresh(null)} />
        <FormSwitch recipient={r.recipient} onChanged={() => refresh(null)} />
        {notice ? (
          <p
            role="status"
            className="rounded-md border border-border-strong bg-surface-raised px-3 py-2 text-sm text-fg"
          >
            {notice}
          </p>
        ) : null}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-xs text-fg-muted">
          <span className="font-medium text-fg">{kindLabel(r.kind)}</span>
          {r.part && r.part > 1 ? <span>{t("abuse_row_part", { part: r.part })}</span> : null}
          <span className="font-mono">{r.recipient.mailbox ?? t("abuse_page_no_mailbox")}</span>
          {r.recipient.shared_mailbox ? <span>{t("abuse_detail_shared_mailbox")}</span> : null}
          {r.previously_reported ? (
            <span>
              {t("abuse_detail_previously", { date: formatAbsolute(r.previously_reported) })}
            </span>
          ) : null}
        </div>
        <StatusStepper status={r.status} />
        {canWrite ? null : <p className="text-sm text-fg-muted">{t("abuse_detail_read_only")}</p>}
        <Actions r={r} onChanged={refresh} />
        {r.status === "sent" || r.status === "closed" ? <OutcomeCard r={r} /> : null}
        <IdentityCard r={r} />
        <MessageCard r={r} />
        <OptionsCard key={`${r.revision}:options`} r={r} onSaved={(d) => refresh(d)} />
        <SubjectsCard r={r} />
        <NotesCard key={`${r.revision}:${r.notes ?? ""}`} r={r} onSaved={(d) => refresh(d)} />
        <HistoryCard r={r} />
      </div>
    </>
  )
}
