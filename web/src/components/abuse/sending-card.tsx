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
import { abuseKeys } from "@/lib/abuse"
import {
  AUTO_WARNING,
  CAP_HINT,
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
  if (!c.configured) return "SuckerPot does not send reports. Set up SMTP to let it."
  if (c.mode === "off")
    return "Sending is off. Reports are copied or opened from the To send queue."
  if (c.mode === "click") return "Reports are sent only when you click Send now."
  return `Ready reports are sent automatically after ${c.auto_hold_minutes} minutes.`
}

const lowerFirst = (s: string) => s.charAt(0).toLowerCase() + s.slice(1)

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
    if (!f.host.trim()) return "Enter the mail server name, such as smtp.example.net."
    if (!Number.isInteger(f.port) || f.port < 1 || f.port > 65535)
      return "The port must be a number from 1 to 65535."
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(f.from_address.trim()))
      return "Enter the from address as a full mailbox."
    if (!initial.password_set && !f.password) return "Enter the SMTP password or token."
    if (f.mode === "auto") {
      if (f.auto_hold_minutes < HOLD_RANGE.min || f.auto_hold_minutes > HOLD_RANGE.max)
        return `The waiting time must be between ${HOLD_RANGE.min} and ${HOLD_RANGE.max} minutes.`
      if (f.daily_cap < CAP_RANGE.min || f.daily_cap > CAP_RANGE.max)
        return `The daily limit must be between ${CAP_RANGE.min} and ${CAP_RANGE.max}.`
    }
    return null
  }

  const num = (v: string, fallback: number) => (v === "" ? fallback : Number(v))

  return (
    <div className="grid gap-6">
      <div className="space-y-2.5">
        <SegmentedControl
          size="form"
          label="Sending mode"
          value={f.mode}
          onChange={(v) => set("mode", v)}
          options={MODE_OPTIONS.map((o) => ({
            ...o,
            disabled: o.value !== "off" && !initial.configured,
          }))}
        />
        {initial.configured ? null : <p className="text-sm text-fg-muted">Set up SMTP first.</p>}
        <p className="text-sm text-fg-muted">{MODE_EXPLANATION[f.mode]}</p>
        {f.mode !== initial.mode ? (
          <p role="status" className="text-sm text-fg-muted">
            Not saved yet. Save to switch to{" "}
            {MODE_OPTIONS.find((o) => o.value === f.mode)?.label ?? f.mode}.
          </p>
        ) : null}
        {f.mode === "auto" ? (
          <p
            role="note"
            className="flex items-start gap-2.5 rounded-md border border-border-strong bg-surface-raised px-3 py-2.5 text-sm text-fg"
          >
            <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
            {AUTO_WARNING}
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
            Proton (paid plan, custom domain)
          </Button>
          <span className="text-xs text-fg-muted">
            Fills the server, port and security. The password is an SMTP token from Proton&apos;s
            settings.
          </span>
        </div>
        {preset ? (
          <p role="note" className="flex items-start gap-2 text-sm text-fg-muted">
            <Info aria-hidden className="mt-0.5 size-4 shrink-0" />
            The password is an SMTP token created in Proton&apos;s settings, not your login
            password. The username is the address that owns the token.
          </p>
        ) : null}
        <p className="text-sm text-fg-muted">
          Free Proton addresses have no SMTP: use the To send queue.
        </p>

        <div className="grid gap-4 md:grid-cols-2">
          <Field id={ids.host} label="Server" hint="A name, not an address.">
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
            <Field id={ids.port} label="Port">
              <Input
                id={ids.port}
                inputMode="numeric"
                autoComplete="off"
                value={String(f.port)}
                onChange={(e) => set("port", num(e.target.value.replace(/\D/g, ""), 0))}
              />
            </Field>
            <div className="flex flex-col gap-1.5">
              <span className="text-sm font-medium text-fg">Security</span>
              <SegmentedControl
                size="form"
                label="Security"
                value={f.security}
                onChange={(v) => set("security", v)}
                options={[
                  { value: "starttls", label: "STARTTLS" },
                  { value: "ssl", label: "SSL/TLS" },
                ]}
                className="self-start"
              />
              <p className="text-xs text-fg-muted">Plain text is not offered.</p>
            </div>
          </div>
          <Field id={ids.user} label="Username">
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
            label="Password or token"
            hint={
              initial.password_set
                ? "Set. Leave empty to keep it; type a new one to replace it. It is never shown again."
                : "Stored encrypted. It is never shown again."
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
            label="From address"
            hint="Checked against the identity guard, like every report."
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
          <Field id={ids.name} label="From name" hint="Optional. Empty by default.">
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
                label="Waiting time (minutes)"
                hint={`${HOLD_RANGE.min} to ${HOLD_RANGE.max}. Time to cancel before a report leaves. ${CAP_HINT}`}
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
                label="Daily limit"
                hint={`${CAP_RANGE.min} to ${CAP_RANGE.max} automatic sends per UTC day. ${CAP_HINT}`}
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
          <Button type="submit">Save sending settings</Button>
          <UnsavedHint show={unsaved} />
          {initial.configured ? (
            <>
              <Button type="button" variant="outline" onClick={() => setAction("test")}>
                Send a test
              </Button>
              <Button type="button" variant="ghost" onClick={() => setAction("remove")}>
                Remove SMTP
              </Button>
            </>
          ) : null}
        </div>
        {initial.configured ? (
          <p className="text-sm text-fg-muted">
            {initial.last_test
              ? `Last test to the from address: ${lowerFirst(describeRequest(initial.last_test) ?? "")}`
              : "No test sent yet. A test is a short neutral message to the from address."}
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
          setSaved("Saved.")
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
  const hint = "Changing the sending settings asks for your own dashboard password again."
  const base = { hint, onOpenChange: (o: boolean) => !o && onClose(), onDone: () => undefined }
  return (
    <>
      <AdminActionDialog
        {...base}
        open={action === "save"}
        title="Save the sending settings?"
        description="The mail server password is stored encrypted and never shown again."
        confirmLabel="Save"
        pendingLabel="Saving…"
        run={onSave}
      />
      <AdminActionDialog
        {...base}
        open={action === "test"}
        title="Send a test message?"
        description={`A short neutral message goes to ${from || "the from address"}, through the VPN, using the saved settings.`}
        confirmLabel="Send test"
        pendingLabel="Sending…"
        run={onTest}
      />
      <AdminActionDialog
        {...base}
        open={action === "remove"}
        title="Remove the SMTP settings?"
        description="The server details and the stored password are deleted and sending goes back to Off. Reports are not affected."
        confirmLabel="Remove"
        pendingLabel="Removing…"
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
      eyebrow="Sending"
      finding={
        q.isPending
          ? "Loading the sending settings…"
          : q.isError
            ? "The sending settings could not be loaded."
            : formMode && formMode !== q.data.mode
              ? `Saved: ${finding(q.data)}`
              : finding(q.data)
      }
      detail="Optional. SuckerPot sends a report only if you set up SMTP and choose a sending mode."
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
