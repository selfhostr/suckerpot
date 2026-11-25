import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Eye, EyeOff, Trash2, TriangleAlert } from "lucide-react"
import { cn } from "@/lib/utils"
import { useId, useState } from "react"
import { useSearchParams } from "react-router"
import { Field, FormError, UnsavedHint } from "@/components/form-parts"
import { useUnsaved } from "@/hooks/use-unsaved"
import { FindingCard } from "@/components/finding-card"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import {
  abuseApi,
  abuseKeys,
  describeAbuseError,
  describeSettingsIssue,
  guardReason,
  guardReasonsOf,
  isStale,
  REFERENCE_STYLE_OPTIONS,
  settingsIssuesOf,
  TLP_OPTIONS,
  type ReferenceStyle,
  type ReportSettings,
  type SelfTerm,
  type Tlp,
} from "@/lib/abuse"
import { t, tk } from "@/i18n"

const TERM_KIND: Record<SelfTerm["kind"], string> = {
  address: tk("reporting_never_kind_address"),
  cidr: tk("reporting_never_kind_cidr"),
  name: tk("reporting_never_kind_name"),
  text: tk("reporting_never_kind_text"),
}

const blank = (v: string): string | null => (v.trim() === "" ? null : v.trim())

function Toggle({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string
  hint: string
  checked: boolean
  onChange: (on: boolean) => void
}) {
  const id = useId()
  return (
    <div className="flex items-start gap-3">
      <Switch id={id} checked={checked} onCheckedChange={onChange} className="mt-0.5" />
      <label htmlFor={id} className="text-sm text-fg">
        {label}
        <span className="block text-xs text-fg-muted">{hint}</span>
      </label>
    </div>
  )
}

function SettingsForm({
  initial,
  onStale,
  onSaved,
}: {
  initial: ReportSettings
  onStale: () => void
  /** `recheck`: texts that blocked every draft were fixed, so the open drafts are checked again. */
  onSaved: (recheck: boolean) => void
}) {
  const qc = useQueryClient()
  const ids = {
    reply: useId(),
    sig: useId(),
    intro: useId(),
    outro: useId(),
    ua: useId(),
    org: useId(),
    formName: useId(),
    note: useId(),
    subj: useId(),
    err: useId(),
  }
  const [s, setS] = useState(initial)
  const { unsaved, markSaved } = useUnsaved(s)
  const [params] = useSearchParams()
  const flagged = new Set((params.get("missing") ?? "").split(",").filter(Boolean))
  // The server names the reply contact when it is the one thing missing; it stays flagged until set.
  const needContact =
    flagged.has("reply_contact") && !(s.reply_contact ?? "").trim()
      ? t("reporting_contact_required")
      : undefined
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  // The texts that would block every report, by field: the ones already saved, then the ones the
  // server refused. A field leaves the list as soon as it is edited.
  const [issues, setIssues] = useState<Record<string, string[]>>(initial.field_issues ?? {})
  const [refused, setRefused] = useState(false)
  const save = useMutation({
    mutationFn: () => abuseApi.saveSettings(s),
    onSuccess: (d) => {
      onSaved(Object.keys(issues).length > 0)
      markSaved(s)
      setError(null)
      setIssues({})
      setRefused(false)
      setSaved(true)
      qc.setQueryData(abuseKeys.settings, d)
      void qc.invalidateQueries({ queryKey: abuseKeys.all })
    },
    onError: (e) => {
      setSaved(false)
      if (isStale(e)) {
        onStale()
        return
      }
      const found = settingsIssuesOf(e)
      if (found) {
        setIssues(found)
        setRefused(true)
        setError(null)
        return
      }
      const why = guardReasonsOf(e)
      setError(
        why
          ? (why.length > 0 ? why : ["unknown"]).map(guardReason).join(" ")
          : describeAbuseError(e),
      )
    },
  })
  const set = <K extends keyof ReportSettings>(k: K, v: ReportSettings[K]) => {
    setSaved(false)
    setIssues((p) =>
      k in p ? Object.fromEntries(Object.entries(p).filter(([name]) => name !== k)) : p,
    )
    setS((p) => ({ ...p, [k]: v }))
  }
  const blocking = Object.keys(issues).length
  const issueOf = (field: string) => {
    const codes = issues[field]
    return codes ? describeSettingsIssue(field, codes) : undefined
  }
  const invalid = (field: string, id: string) =>
    issues[field] ? { "aria-invalid": true, "aria-describedby": `${id}-error` } : {}
  const summary =
    error ??
    (blocking > 0
      ? t("reporting_blocking_summary", { refused: refused ? "yes" : "no", count: blocking })
      : null)
  return (
    <form
      className="grid gap-6"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        save.mutate()
      }}
    >
      <div className="grid gap-4 md:grid-cols-2">
        <Field
          id={ids.reply}
          label={t("reporting_reply_contact")}
          hint={t("reporting_reply_contact_hint")}
          error={needContact ?? issueOf("reply_contact")}
        >
          <Input
            id={ids.reply}
            type="email"
            maxLength={254}
            autoComplete="off"
            value={s.reply_contact ?? ""}
            placeholder="reports@example.net"
            onChange={(e) => set("reply_contact", blank(e.target.value))}
            {...invalid("reply_contact", ids.reply)}
          />
        </Field>
        <Field
          id={ids.sig}
          label={t("reporting_signature")}
          optional
          hint={t("reporting_signature_hint")}
          error={issueOf("signature")}
        >
          <Input
            id={ids.sig}
            maxLength={200}
            autoComplete="off"
            value={s.signature ?? ""}
            onChange={(e) => set("signature", blank(e.target.value))}
            {...invalid("signature", ids.sig)}
          />
        </Field>
        <Field
          id={ids.intro}
          label={t("reporting_intro")}
          optional
          hint={t("reporting_intro_hint")}
          error={issueOf("intro")}
        >
          <Textarea
            id={ids.intro}
            rows={3}
            maxLength={1000}
            value={s.intro ?? ""}
            onChange={(e) => set("intro", blank(e.target.value))}
            {...invalid("intro", ids.intro)}
          />
        </Field>
        <Field
          id={ids.outro}
          label={t("reporting_outro")}
          optional
          hint={t("reporting_outro_hint")}
          error={issueOf("outro")}
        >
          <Textarea
            id={ids.outro}
            rows={3}
            maxLength={1000}
            value={s.outro ?? ""}
            onChange={(e) => set("outro", blank(e.target.value))}
            {...invalid("outro", ids.outro)}
          />
        </Field>
        <Field
          id={ids.ua}
          label={t("reporting_user_agent")}
          optional
          hint={t("reporting_user_agent_hint", { example: "Mozilla/5.0" })}
          error={issueOf("xarf_user_agent")}
        >
          <Input
            id={ids.ua}
            maxLength={64}
            autoComplete="off"
            value={s.xarf_user_agent ?? ""}
            className="font-mono"
            onChange={(e) => set("xarf_user_agent", blank(e.target.value))}
            {...invalid("xarf_user_agent", ids.ua)}
          />
        </Field>
        <Field
          id={ids.org}
          label={t("reporting_org")}
          optional
          hint={t("reporting_org_hint")}
          error={issueOf("xarf_org")}
        >
          <Input
            id={ids.org}
            maxLength={100}
            autoComplete="off"
            value={s.xarf_org ?? ""}
            onChange={(e) => set("xarf_org", e.target.value === "" ? null : e.target.value)}
            {...invalid("xarf_org", ids.org)}
          />
        </Field>
        <Field
          id={ids.formName}
          label={t("reporting_form_name")}
          optional
          hint={t("reporting_form_name_hint")}
          error={issueOf("form_name")}
        >
          <Input
            id={ids.formName}
            maxLength={100}
            autoComplete="off"
            value={s.form_name ?? ""}
            onChange={(e) => set("form_name", e.target.value === "" ? null : e.target.value)}
            {...invalid("form_name", ids.formName)}
          />
        </Field>
        <Field
          id={ids.note}
          label={t("reporting_note")}
          optional
          hint={t("reporting_note_hint")}
          error={issueOf("note")}
        >
          <Textarea
            id={ids.note}
            rows={3}
            maxLength={1000}
            value={s.note ?? ""}
            onChange={(e) => set("note", blank(e.target.value))}
            {...invalid("note", ids.note)}
          />
        </Field>
        <Field
          id={ids.subj}
          label={t("reporting_subject_template")}
          optional
          hint={t("reporting_subject_template_hint", { example: "Abuse report for {value}" })}
          error={issueOf("subject_template")}
        >
          <Input
            id={ids.subj}
            maxLength={200}
            autoComplete="off"
            value={s.subject_template ?? ""}
            onChange={(e) => set("subject_template", blank(e.target.value))}
            {...invalid("subject_template", ids.subj)}
          />
        </Field>
        <div className="flex flex-col gap-1.5">
          <span className="text-sm font-medium text-fg">{t("reporting_default_tlp")}</span>
          <SegmentedControl
            size="form"
            label={t("reporting_default_tlp_aria")}
            value={s.default_tlp}
            onChange={(v: Tlp) => set("default_tlp", v)}
            options={TLP_OPTIONS}
            className="self-start"
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <span className="text-sm font-medium text-fg">{t("reporting_reference")}</span>
          <SegmentedControl
            size="form"
            label={t("reporting_reference")}
            value={s.reference_style}
            onChange={(v: ReferenceStyle) => set("reference_style", v)}
            options={REFERENCE_STYLE_OPTIONS}
            className="scroll-fade-x max-w-full self-start overflow-x-auto"
          />
          <span className="text-xs text-fg-muted">{t("reporting_reference_hint")}</span>
        </div>
      </div>
      <fieldset className="grid gap-3">
        <legend className="mb-1 text-sm font-medium text-fg">{t("reporting_defaults")}</legend>
        <Toggle
          label={t("reporting_round_times")}
          hint={t("reporting_round_times_hint")}
          checked={s.round_times}
          onChange={(on) => set("round_times", on)}
        />
        <Toggle
          label={t("reporting_defang")}
          hint={t("reporting_defang_hint", { example: "hxxp://203.0.113[.]9" })}
          checked={s.default_options.defang}
          onChange={(on) => set("default_options", { ...s.default_options, defang: on })}
        />
        <Toggle
          label={t("reporting_usernames")}
          hint={t("reporting_usernames_hint")}
          checked={s.default_options.include_usernames}
          onChange={(on) => set("default_options", { ...s.default_options, include_usernames: on })}
        />
        <Toggle
          label={t("reporting_include_contact")}
          hint={t("reporting_include_contact_hint")}
          checked={s.default_options.include_reply_contact}
          onChange={(on) =>
            set("default_options", { ...s.default_options, include_reply_contact: on })
          }
        />
        <Toggle
          label={t("reporting_redaction")}
          hint={t("reporting_redaction_hint")}
          checked={s.default_options.show_redaction_counts}
          onChange={(on) =>
            set("default_options", { ...s.default_options, show_redaction_counts: on })
          }
        />
      </fieldset>
      <FormError id={ids.err} message={summary} />
      <div className="flex items-center gap-3">
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? t("reporting_saving") : t("common_save")}
        </Button>
        <span role="status" className="text-sm text-fg-muted empty:hidden">
          {saved ? t("reporting_saved") : null}
        </span>
        <UnsavedHint show={unsaved} />
      </div>
    </form>
  )
}

/** Text the reports must never contain: learned from traffic, or added by hand. */
export function NeverInReport() {
  const qc = useQueryClient()
  const [reveal, setReveal] = useState(false)
  const [kind, setKind] = useState<SelfTerm["kind"]>("address")
  const [value, setValue] = useState("")
  const [error, setError] = useState<string | null>(null)
  const id = useId()
  const q = useQuery({ queryKey: abuseKeys.terms(reveal), queryFn: () => abuseApi.terms(reveal) })
  const refresh = () => void qc.invalidateQueries({ queryKey: ["abuse", "terms"] })
  const fail = (e: unknown) => setError(describeAbuseError(e))
  const add = useMutation({
    mutationFn: () => abuseApi.addTerm(kind, value.trim()),
    onSuccess: () => {
      setValue("")
      setError(null)
      refresh()
    },
    onError: fail,
  })
  const confirm = useMutation({
    mutationFn: abuseApi.confirmTerm,
    onSuccess: refresh,
    onError: fail,
  })
  const del = useMutation({ mutationFn: abuseApi.deleteTerm, onSuccess: refresh, onError: fail })
  const terms = [...(q.data ?? [])].sort((a, b) => Number(a.confirmed) - Number(b.confirmed))
  const confirmed = terms.filter((term) => term.confirmed).length
  return (
    <FindingCard
      eyebrow={t("reporting_nav_never")}
      finding={
        q.isPending
          ? t("reporting_never_checking")
          : confirmed > 0
            ? t("reporting_never_finding", { count: confirmed, pending: terms.length - confirmed })
            : t("reporting_never_unknown")
      }
      action={
        <Button variant="outline" size="sm" onClick={() => setReveal((r) => !r)}>
          {reveal ? <EyeOff aria-hidden /> : <Eye aria-hidden />}
          {reveal ? t("reporting_never_hide") : t("reporting_never_reveal")}
        </Button>
      }
      bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
    >
      {q.isPending ? (
        <div className="px-4 sm:px-5">
          <SkeletonText lines={3} />
        </div>
      ) : (
        <>
          <p className="border-t px-4 py-3 text-xs text-fg-muted sm:px-5">
            {t("reporting_never_learned_note")}
          </p>
          <ul className="divide-y border-t">
            {terms.map((term) => (
              <li
                key={term.id}
                className={cn(
                  "flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 sm:px-5",
                  !term.confirmed && "tint-warning",
                )}
              >
                {!term.confirmed ? (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-sev-warning">
                    <TriangleAlert aria-hidden className="size-3.5" />
                    {t("reporting_never_needs_confirmation")}
                  </span>
                ) : null}
                <code className="font-mono text-xs text-fg">{term.value}</code>
                <span className="text-xs text-fg-muted">
                  {t("reporting_never_term_meta", {
                    kind: t(TERM_KIND[term.kind]),
                    source: term.source,
                    sources: term.distinct_sources,
                    confirmed: term.confirmed ? "yes" : "no",
                  })}
                </span>
                <span className="ml-auto flex gap-2">
                  {!term.confirmed ? (
                    <Button size="sm" variant="outline" onClick={() => confirm.mutate(term.id)}>
                      {t("common_confirm")}
                    </Button>
                  ) : null}
                  {term.source !== "sensor" ? (
                    <Button
                      size="icon-sm"
                      variant="ghost"
                      aria-label={t("reporting_never_delete_aria", { value: term.value })}
                      onClick={() => del.mutate(term.id)}
                    >
                      <Trash2 aria-hidden />
                    </Button>
                  ) : null}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
      <form
        className="flex flex-wrap items-end gap-3 border-t px-4 py-4 sm:px-5"
        onSubmit={(e) => {
          e.preventDefault()
          if (value.trim().length < 2) {
            setError(t("reporting_never_too_short"))
            return
          }
          add.mutate()
        }}
      >
        <div className="flex flex-col gap-1.5">
          <span className="text-xs font-medium text-fg-muted">{t("common_add")}</span>
          <SegmentedControl
            size="form"
            label={t("reporting_never_kind")}
            value={kind}
            onChange={setKind}
            options={[
              { value: "address", label: t("reporting_never_kind_address_label") },
              { value: "cidr", label: t("reporting_never_kind_cidr_label") },
              { value: "name", label: t("reporting_never_kind_name_label") },
              { value: "text", label: t("reporting_never_kind_text_label") },
            ]}
          />
        </div>
        <div className="flex min-w-48 flex-1 flex-col gap-1.5">
          <label htmlFor={id} className="text-xs font-medium text-fg-muted">
            {t("reporting_never_value")}
          </label>
          <Input
            id={id}
            autoComplete="off"
            value={value}
            maxLength={253}
            className="font-mono"
            onChange={(e) => setValue(e.target.value)}
          />
        </div>
        <Button type="submit" variant="outline" disabled={add.isPending}>
          {t("common_add")}
        </Button>
        <p role="alert" className="w-full text-sm text-fg empty:hidden">
          {error}
        </p>
      </form>
    </FindingCard>
  )
}

/** Settings, Reporting tab (administrators only): the wording and defaults of the drafts. */
export function ReportingCard() {
  const q = useQuery({ queryKey: abuseKeys.settings, queryFn: abuseApi.settings })
  const [stale, setStale] = useState(false)
  const [recheck, setRecheck] = useState(false)
  return (
    <>
      <section id="reporting-message" className="scroll-mt-16">
        <FindingCard
          eyebrow={t("reporting_eyebrow")}
          finding={
            q.isPending
              ? t("reporting_loading")
              : q.isError
                ? t("reporting_load_failed")
                : Object.keys(q.data.field_issues ?? {}).length > 0
                  ? t("reporting_finding_issues")
                  : q.data.reply_contact
                    ? t("reporting_finding_ready")
                    : t("reporting_finding_no_contact")
          }
          detail={t("reporting_detail")}
        >
          {q.isPending ? (
            <SkeletonText lines={4} />
          ) : q.data ? (
            <>
              {stale ? (
                <p role="alert" className="mb-4 text-sm text-fg">
                  {t("reporting_stale")}
                </p>
              ) : null}
              {recheck ? (
                <p role="status" className="mb-4 text-sm text-fg">
                  {t("reporting_recheck")}
                </p>
              ) : null}
              <SettingsForm
                key={q.data.revision}
                initial={q.data}
                onSaved={(r) => {
                  setStale(false)
                  setRecheck(r)
                }}
                onStale={() => {
                  setStale(true)
                  void q.refetch()
                }}
              />
            </>
          ) : null}
        </FindingCard>
      </section>
      <section id="reporting-never" className="scroll-mt-16">
        <NeverInReport />
      </section>
    </>
  )
}
