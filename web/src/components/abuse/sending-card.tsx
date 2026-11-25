import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Info, TriangleAlert } from "lucide-react"
import { useCallback, useEffect, useId, useState, type ReactNode } from "react"
import { Field, UnsavedHint } from "@/components/form-parts"
import { useUnsaved } from "@/hooks/use-unsaved"
import { FindingCard } from "@/components/finding-card"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonText } from "@/components/skeletons"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { intlLocale, t } from "@/i18n"
import { abuseKeys } from "@/lib/abuse"
import {
  autoWarning,
  capHint,
  CAP_RANGE,
  describeRequest,
  describeSendError,
  describeSentToday,
  HOLD_RANGE,
  inFlight,
  MODE_EXPLANATION,
  MODE_OPTIONS,
  PROTON_PRESET,
  sendApi,
  sendKeys,
  type SendMode,
  type SmtpConfig,
  type SmtpForm,
} from "@/lib/abuse-send"
import { ApiError } from "@/lib/api"
import { UserError } from "@/lib/users"

type Action = "save" | "test" | "remove"

function finding(c: SmtpConfig): string {
  if (!c.configured) return t("sending_finding_unconfigured")
  if (c.mode === "off") return t("sending_finding_off")
  if (c.mode === "click") return t("sending_finding_click")
  return t("sending_finding_auto", { minutes: c.auto_hold_minutes })
}

/** The start of a sentence goes mid-sentence: lower case it, except in German (nouns). */
const lowerFirst = (s: string) =>
  intlLocale().startsWith("de") ? s : s.charAt(0).toLowerCase() + s.slice(1)

function toForm(c: SmtpConfig): SmtpForm {
  return {
    host: c.host,
    port: c.port,
    security: c.security,
    username: c.username,
    from_address: c.from_address,
    from_name: c.from_name,
    mode: c.mode,
    auto_hold_minutes: c.auto_hold_minutes,
    daily_cap: c.daily_cap,
    password: "",
  }
}

/** A re-authentication call whose failures read as the dialog expects. */
async function reauth(fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn()
  } catch (e) {
    if (e instanceof ApiError && e.code === "reauth_failed") throw new UserError("wrong-password")
    throw new UserError("invalid", describeSendError(e))
  }
}

function SendingForm({
  initial,
  onModeChange,
}: {
  initial: SmtpConfig
  onModeChange: (m: SendMode) => void
}) {
  const qc = useQueryClient()
  const ids = {
    host: useId(),
    port: useId(),
    user: useId(),
    pass: useId(),
    from: useId(),
    name: useId(),
    hold: useId(),
    cap: useId(),
  }
  const [f, setF] = useState<SmtpForm>(() => toForm(initial))
  const { unsaved, markSaved } = useUnsaved(f)
  const [action, setAction] = useState<Action | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [preset, setPreset] = useState(false)
  const [saved, setSaved] = useState<string | null>(null)
  useEffect(() => {
    onModeChange(f.mode)
  }, [f.mode, onModeChange])
  const set = <K extends keyof SmtpForm>(k: K, v: SmtpForm[K]) => {
    setSaved(null)
    setF((p) => ({ ...p, [k]: v }))
  }
  const refresh = () => void qc.invalidateQueries({ queryKey: abuseKeys.all })
  const save = useMutation({ mutationFn: (pw: string) => sendApi.saveSmtp(f, pw) })

  function validate(): string | null {
    if (!f.host.trim()) return t("sending_invalid_host", { example: "smtp.example.net" })
    if (!Number.isInteger(f.port) || f.port < 1 || f.port > 65535)
      return t("imap_invalid_port")
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(f.from_address.trim()))
      return t("sending_invalid_from")
    if (!initial.password_set && !f.password) return t("sending_invalid_password")
    if (f.mode === "auto") {
      if (f.auto_hold_minutes < HOLD_RANGE.min || f.auto_hold_minutes > HOLD_RANGE.max)
        return t("sending_invalid_hold", { min: HOLD_RANGE.min, max: HOLD_RANGE.max })
      if (f.daily_cap < CAP_RANGE.min || f.daily_cap > CAP_RANGE.max)
        return t("sending_invalid_cap", { min: CAP_RANGE.min, max: CAP_RANGE.max })
    }
    return null
  }

  const num = (v: string, fallback: number) => (v === "" ? fallback : Number(v))

  return (
    <div className="grid gap-6">
      <div className="space-y-2.5">
        <SegmentedControl
          size="form"
          label={t("sending_mode_aria")}
          value={f.mode}
          onChange={(v) => set("mode", v)}
          options={MODE_OPTIONS.map((o) => ({
            ...o,
            disabled: o.value !== "off" && !initial.configured,
          }))}
        />
        {initial.configured ? null : (
          <p className="text-sm text-fg-muted">{t("sending_setup_first")}</p>
        )}
        <p className="text-sm text-fg-muted">{MODE_EXPLANATION[f.mode]}</p>
        {f.mode !== initial.mode ? (
          <p role="status" className="text-sm text-fg-muted">
            {t("sending_mode_unsaved", {
              mode: MODE_OPTIONS.find((o) => o.value === f.mode)?.label ?? f.mode,
            })}
          </p>
        ) : null}
        {f.mode === "auto" ? (
          <p
            role="note"
            className="flex items-start gap-2.5 rounded-md border border-border-strong bg-surface-raised px-3 py-2.5 text-sm text-fg"
          >
            <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
            {autoWarning()}
          </p>
        ) : null}
      </div>

      <form
        className="grid gap-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          const p = validate()
          setProblem(p)
          if (!p) setAction("save")
        }}
      >
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => {
              setPreset(true)
              setSaved(null)
              setF((p) => ({ ...p, ...PROTON_PRESET }))
            }}
          >
            {t("sending_proton")}
          </Button>
          <span className="text-xs text-fg-muted">
            {t("sending_proton_hint")}
          </span>
        </div>
        {preset ? (
          <p role="note" className="flex items-start gap-2 text-sm text-fg-muted">
            <Info aria-hidden className="mt-0.5 size-4 shrink-0" />
            {t("sending_proton_note")}
          </p>
        ) : null}
        <p className="text-sm text-fg-muted">
          {t("sending_free_proton")}
        </p>

        <div className="grid gap-4 md:grid-cols-2">
          <Field id={ids.host} label={t("imap_server")} hint={t("imap_server_hint")}>
            <Input
              id={ids.host}
              maxLength={253}
              autoComplete="off"
              spellCheck={false}
              value={f.host}
              placeholder="smtp.example.net"
              onChange={(e) => set("host", e.target.value.trim())}
            />
          </Field>
          <div className="grid grid-cols-[6rem_1fr] gap-4">
            <Field id={ids.port} label={t("imap_port")}>
              <Input
                id={ids.port}
                inputMode="numeric"
                autoComplete="off"
                value={String(f.port)}
                onChange={(e) => set("port", num(e.target.value.replace(/\D/g, ""), 0))}
              />
            </Field>
            <div className="flex flex-col gap-1.5">
              <span className="text-sm font-medium text-fg">{t("imap_security")}</span>
              <SegmentedControl
                size="form"
                label={t("imap_security")}
                value={f.security}
                onChange={(v) => set("security", v)}
                options={[
                  { value: "starttls", label: "STARTTLS" },
                  { value: "ssl", label: "SSL/TLS" },
                ]}
                className="self-start"
              />
              <p className="text-xs text-fg-muted">{t("imap_security_hint")}</p>
            </div>
          </div>
          <Field id={ids.user} label={t("imap_username")}>
            <Input
              id={ids.user}
              maxLength={254}
              autoComplete="off"
              value={f.username}
              onChange={(e) => set("username", e.target.value)}
            />
          </Field>
          <Field
            id={ids.pass}
            label={t("sending_password")}
            hint={
              initial.password_set ? t("sending_password_hint_set") : t("imap_password_hint_new")
            }
          >
            <Input
              id={ids.pass}
              type="password"
              autoComplete="new-password"
              value={f.password}
              placeholder={initial.password_set ? "••••••••" : ""}
              onChange={(e) => set("password", e.target.value)}
            />
          </Field>
          <Field
            id={ids.from}
            label={t("sending_from_address")}
            hint={t("sending_from_address_hint")}
          >
            <Input
              id={ids.from}
              type="email"
              maxLength={254}
              autoComplete="off"
              value={f.from_address}
              placeholder="reports@example.org"
              onChange={(e) => set("from_address", e.target.value.trim())}
            />
          </Field>
          <Field id={ids.name} label={t("sending_from_name")} hint={t("sending_from_name_hint")}>
            <Input
              id={ids.name}
              maxLength={100}
              autoComplete="off"
              value={f.from_name}
              onChange={(e) => set("from_name", e.target.value)}
            />
          </Field>
          {f.mode === "auto" ? (
            <>
              <Field
                id={ids.hold}
                label={t("sending_hold")}
                hint={t("sending_hold_hint", {
                  min: HOLD_RANGE.min,
                  max: HOLD_RANGE.max,
                  cap: capHint(),
                })}
              >
                <Input
                  id={ids.hold}
                  inputMode="numeric"
                  value={String(f.auto_hold_minutes)}
                  onChange={(e) =>
                    set("auto_hold_minutes", num(e.target.value.replace(/\D/g, ""), 0))
                  }
                />
              </Field>
              <Field
                id={ids.cap}
                label={t("sending_cap")}
                hint={t("sending_cap_hint", {
                  min: CAP_RANGE.min,
                  max: CAP_RANGE.max,
                  cap: capHint(),
                })}
              >
                <Input
                  id={ids.cap}
                  inputMode="numeric"
                  value={String(f.daily_cap)}
                  onChange={(e) => set("daily_cap", num(e.target.value.replace(/\D/g, ""), 0))}
                />
              </Field>
            </>
          ) : null}
        </div>

        <p className="text-sm text-fg-muted tabular-nums">
          {describeSentToday({
            sent_today: initial.sent_today,
            daily_cap: initial.daily_cap,
            mode: initial.mode,
          })}
        </p>

        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit">{t("sending_save")}</Button>
          <UnsavedHint show={unsaved} />
          {initial.configured ? (
            <>
              <Button type="button" variant="outline" onClick={() => setAction("test")}>
                {t("sending_test")}
              </Button>
              <Button type="button" variant="ghost" onClick={() => setAction("remove")}>
                {t("sending_remove")}
              </Button>
            </>
          ) : null}
        </div>
        {initial.configured ? (
          <p className="text-sm text-fg-muted">
            {initial.last_test
              ? t("sending_last_test", {
                  result: lowerFirst(describeRequest(initial.last_test) ?? ""),
                })
              : t("sending_no_test")}
          </p>
        ) : null}
        <p role="alert" className="text-sm text-fg empty:hidden">
          {problem}
        </p>
        <p role="status" className="text-sm text-fg-muted empty:hidden">
          {saved}
        </p>
      </form>

      <Dialogs
        action={action}
        onClose={() => setAction(null)}
        onSave={async (pw) => {
          await reauth(() => save.mutateAsync(pw))
          setSaved(t("sending_saved"))
          markSaved(f)
          refresh()
        }}
        onTest={async (pw) => {
          await reauth(() => sendApi.testSmtp(pw))
          refresh()
        }}
        onRemove={async (pw) => {
          await reauth(() => sendApi.removeSmtp(pw))
          refresh()
        }}
        from={f.from_address}
      />
    </div>
  )
}

function Dialogs({
  action,
  onClose,
  onSave,
  onTest,
  onRemove,
  from,
}: {
  action: Action | null
  onClose: () => void
  onSave: (pw: string) => Promise<void>
  onTest: (pw: string) => Promise<void>
  onRemove: (pw: string) => Promise<void>
  from: string
}): ReactNode {
  const hint = t("sending_dialog_hint")
  const base = { hint, onOpenChange: (o: boolean) => !o && onClose(), onDone: () => undefined }
  return (
    <>
      <AdminActionDialog
        {...base}
        open={action === "save"}
        title={t("sending_save_title")}
        description={t("sending_save_description")}
        confirmLabel={t("common_save")}
        pendingLabel={t("sending_saving")}
        run={onSave}
      />
      <AdminActionDialog
        {...base}
        open={action === "test"}
        title={t("sending_test_title")}
        description={t("sending_test_description", {
          to: from || t("sending_from_address_fallback"),
        })}
        confirmLabel={t("sending_test_confirm")}
        pendingLabel={t("sending_test_pending")}
        run={onTest}
      />
      <AdminActionDialog
        {...base}
        open={action === "remove"}
        title={t("sending_remove_title")}
        description={t("sending_remove_description")}
        confirmLabel={t("common_remove")}
        pendingLabel={t("sending_removing")}
        run={onRemove}
      />
    </>
  )
}

/** Settings, Reporting tab (administrators only): optional SMTP and the sending mode. */
export function SendingCard() {
  const [formMode, setFormMode] = useState<SendMode | null>(null)
  const onModeChange = useCallback((m: SendMode) => setFormMode(m), [])
  const q = useQuery({
    queryKey: sendKeys.smtp,
    queryFn: sendApi.smtp,
    // A test result arrives a moment after the request.
    refetchInterval: (query) => (inFlight(query.state.data?.last_test?.status) ? 3000 : false),
  })
  return (
    <FindingCard
      eyebrow={t("sending_eyebrow")}
      finding={
        q.isPending
          ? t("sending_loading")
          : q.isError
            ? t("sending_load_failed")
            : formMode && formMode !== q.data.mode
              ? t("sending_saved_finding", { finding: finding(q.data) })
              : finding(q.data)
      }
      detail={t("sending_detail")}
    >
      {q.isPending ? (
        <SkeletonText lines={4} />
      ) : q.data ? (
        <SendingForm
          key={JSON.stringify([q.data.configured, q.data.mode, q.data.host, q.data.password_set])}
          initial={q.data}
          onModeChange={onModeChange}
        />
      ) : null}
    </FindingCard>
  )
}
