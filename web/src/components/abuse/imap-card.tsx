import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Info } from "lucide-react"
import { useId, useState } from "react"
import { Field, UnsavedHint } from "@/components/form-parts"
import { useUnsaved } from "@/hooks/use-unsaved"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { ApiError } from "@/lib/api"
import { formatNumber, plural } from "@/lib/format"
import {
  describeImapError,
  describeRepliesError,
  AUTHSERV_RE,
  POLL_RANGE,
  repliesApi,
  repliesKeys,
  validHint,
  type ImapConfig,
  type ImapForm,
  type ImapRequest,
} from "@/lib/replies"
import { UserError } from "@/lib/users"

type Action = "save" | "remove"

function finding(c: ImapConfig): string {
  if (!c.configured || !c.enabled)
    return "No mailbox: paste replies on the report page, or set one up here."
  return `Replies are read from your mailbox through the VPN, every ${c.poll_minutes} minutes.`
}

function toForm(c: ImapConfig): ImapForm {
  return {
    enabled: c.enabled,
    host: c.host,
    port: c.port,
    security: c.security,
    username: c.username,
    password: "",
    folder: c.folder,
    processed_action: c.processed_action,
    move_folder: c.move_folder ?? "",
    poll_minutes: c.poll_minutes,
    since: c.since ?? "",
    trusted_authserv_id: c.trusted_authserv_id ?? "",
  }
}

async function reauth(fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn()
  } catch (e) {
    if (e instanceof ApiError && e.code === "reauth_failed") throw new UserError("wrong-password")
    throw new UserError("invalid", describeRepliesError(e))
  }
}

function StatusLine({ c }: { c: ImapConfig }) {
  const s = c.state
  if (!c.configured) return null
  const err = describeImapError(s.last_error)
  return (
    <div className="space-y-1 text-sm text-fg-muted">
      <p>
        {s.last_poll_at ? (
          <>
            Last check <RelativeTime iso={s.last_poll_at} />
            {s.last_error
              ? "."
              : `: ${plural(s.counters.fetched ?? 0, "message")} read today, ${s.counters.matched ?? 0} matched to a report.`}
          </>
        ) : (
          "The mailbox has not been checked yet."
        )}
      </p>
      {err ? (
        <p role="status" className="flex items-start gap-2 text-fg">
          <Info aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
          {err}
        </p>
      ) : null}
    </div>
  )
}

function ImapSettingsForm({ initial }: { initial: ImapConfig }) {
  const qc = useQueryClient()
  const ids = {
    host: useId(),
    port: useId(),
    user: useId(),
    pass: useId(),
    folder: useId(),
    move: useId(),
    poll: useId(),
    since: useId(),
    authserv: useId(),
    enabled: useId(),
    folders: useId(),
  }
  const [f, setF] = useState<ImapForm>(() => toForm(initial))
  const { unsaved, markSaved } = useUnsaved(f)
  const [action, setAction] = useState<Action | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [saved, setSaved] = useState<string | null>(null)
  const [pending, setPending] = useState<{ id: number; kind: "test" | "poll" } | null>(null)
  const set = <K extends keyof ImapForm>(k: K, v: ImapForm[K]) => {
    setSaved(null)
    setF((p) => ({ ...p, [k]: v }))
  }
  const refresh = () => void qc.invalidateQueries({ queryKey: repliesKeys.imap })
  const save = useMutation({
    mutationFn: (pw: string) => repliesApi.saveImap(f, pw),
  })
  const start = useMutation({
    mutationFn: (kind: "test" | "poll") =>
      (kind === "test" ? repliesApi.test() : repliesApi.poll()).then((r) => ({ ...r, kind })),
    onSuccess: (r) => {
      setProblem(null)
      setPending({ id: r.id, kind: r.kind })
    },
    onError: (e) => setProblem(describeRepliesError(e)),
  })
  const request = useQuery({
    queryKey: pending ? repliesKeys.request(pending.id) : ["abuse", "imap", "request", "none"],
    queryFn: () => repliesApi.request(pending?.id ?? 0),
    enabled: pending !== null,
    refetchInterval: (q) => (q.state.data?.status === "pending" || !q.state.data ? 1000 : false),
  })
  const req: ImapRequest | undefined = pending ? request.data : undefined
  const folders = req?.result.folders ?? []
  // A finished test wins over the hint of the last poll. Never saved by itself.
  const hint =
    validHint(req?.kind === "test" && req.status === "done" ? req.result.authserv_hint : null) ??
    validHint(initial.state.authserv_hint)
  const suggest = hint && f.trusted_authserv_id.toLowerCase() !== hint.id ? hint : null

  function validate(): string | null {
    if (!f.host.trim()) return "Enter the mail server name, such as imap.example.net."
    if (!Number.isInteger(f.port) || f.port < 1 || f.port > 65535)
      return "The port must be a number from 1 to 65535."
    if (!f.username.trim()) return "Enter the mailbox username."
    if (!initial.password_set && !f.password) return "Enter the mailbox password."
    if (f.trusted_authserv_id && !AUTHSERV_RE.test(f.trusted_authserv_id))
      return "The provider name can only use letters, digits, dots and hyphens."
    if (!f.folder.trim()) return "Enter the folder to read, usually INBOX."
    if (f.processed_action === "move" && (!f.move_folder.trim() || f.move_folder === f.folder))
      return "Pick a different folder to move processed replies to."
    if (f.poll_minutes < POLL_RANGE.min || f.poll_minutes > POLL_RANGE.max)
      return `Check every ${POLL_RANGE.min} to ${POLL_RANGE.max} minutes.`
    return null
  }

  const num = (v: string) => (v === "" ? 0 : Number(v))

  return (
    <div className="grid gap-5">
      <StatusLine c={initial} />
      {initial.shared_mailbox ? (
        <p
          role="note"
          className="flex items-start gap-2.5 rounded-md border border-border-strong bg-surface-raised px-3 py-2.5 text-sm text-fg"
        >
          <Info aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
          This looks like a free or shared mailbox: use a mailbox dedicated to reports.
        </p>
      ) : null}
      {initial.worker_enabled ? null : (
        <p
          role="note"
          className="flex items-start gap-2.5 rounded-md border border-border-strong bg-surface-raised px-3 py-2.5 text-sm text-fg"
        >
          <Info aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
          Reading replies is switched off on this server (ABUSE_REPLIES_ENABLED). You can save the
          settings, but the mailbox is not read until it is turned on.
        </p>
      )}
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
        <div className="flex items-start gap-3">
          <Switch
            id={ids.enabled}
            checked={f.enabled}
            onCheckedChange={(on) => set("enabled", on)}
            className="mt-0.5"
          />
          <label htmlFor={ids.enabled} className="text-sm text-fg">
            Read replies from this mailbox
            <span className="block text-xs text-fg-muted">
              Use a dedicated mailbox or alias for reports. It should be the reply contact you put
              in your reports. Proton needs Proton Bridge, which SuckerPot does not include.
            </span>
          </label>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <Field id={ids.host} label="Server" hint="A name, not an address.">
            <Input
              id={ids.host}
              maxLength={253}
              autoComplete="off"
              spellCheck={false}
              value={f.host}
              placeholder="imap.example.net"
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
                onChange={(e) => set("port", num(e.target.value.replace(/\D/g, "")))}
              />
            </Field>
            <div className="flex flex-col gap-1.5">
              <span className="text-sm font-medium text-fg">Security</span>
              <SegmentedControl
                label="Security"
                value={f.security}
                onChange={(v) => {
                  set("security", v)
                  set("port", v === "ssl" ? 993 : 143)
                }}
                options={[
                  { value: "ssl", label: "SSL/TLS" },
                  { value: "starttls", label: "STARTTLS" },
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
            label="Password"
            hint={
              initial.password_set
                ? "Set. Leave empty to keep it; type a new one to replace it. It is never shown again. If you change the server, port, username or security, type the password again: the stored one is not sent to a new server."
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
          <Field id={ids.folder} label="Folder to read" hint="Usually INBOX.">
            <Input
              id={ids.folder}
              maxLength={100}
              autoComplete="off"
              value={f.folder}
              onChange={(e) => set("folder", e.target.value)}
            />
          </Field>
          <Field
            id={ids.poll}
            label="Check every (minutes)"
            hint={`${POLL_RANGE.min} to ${formatNumber(POLL_RANGE.max)}.`}
          >
            <Input
              id={ids.poll}
              inputMode="numeric"
              value={String(f.poll_minutes)}
              onChange={(e) => set("poll_minutes", num(e.target.value.replace(/\D/g, "")))}
            />
          </Field>
          <div className="flex flex-col gap-1.5">
            <span className="text-sm font-medium text-fg">After a reply is read</span>
            <SegmentedControl
              label="After a reply is read"
              value={f.processed_action}
              onChange={(v) => set("processed_action", v)}
              options={[
                { value: "mark_read", label: "Mark as read" },
                { value: "move", label: "Move to a folder" },
              ]}
              className="self-start"
            />
            <p className="text-xs text-fg-muted">SuckerPot never deletes or sends mail.</p>
          </div>
          {f.processed_action === "move" ? (
            <Field
              id={ids.move}
              label="Move to"
              hint={
                folders.length
                  ? "Test the connection to list the folders."
                  : "Must differ from the folder to read."
              }
            >
              <Input
                id={ids.move}
                list={ids.folders}
                maxLength={100}
                autoComplete="off"
                value={f.move_folder}
                onChange={(e) => set("move_folder", e.target.value)}
              />
              <datalist id={ids.folders}>
                {folders.map((x) => (
                  <option key={x} value={x} />
                ))}
              </datalist>
            </Field>
          ) : null}
          <Field
            id={ids.authserv}
            label="Mail provider name"
            hint="The name your mail provider writes at the start of its Authentication-Results header. Without it, no reply is ever treated as authenticated."
            optional
          >
            <Input
              id={ids.authserv}
              maxLength={255}
              autoComplete="off"
              spellCheck={false}
              value={f.trusted_authserv_id}
              placeholder="mx.example.net"
              onChange={(e) => set("trusted_authserv_id", e.target.value.trim())}
            />
            {suggest ? (
              <p className="flex flex-wrap items-center gap-x-2 text-xs text-fg">
                <span>
                  Your provider signs as <code>{suggest.id}</code> (seen on {suggest.seen} of{" "}
                  {plural(suggest.of, "recent message")}).
                </span>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => set("trusted_authserv_id", suggest.id)}
                >
                  Use it
                </Button>
              </p>
            ) : null}
          </Field>
          <Field
            id={ids.since}
            label="Ignore mail before"
            hint={
              f.since
                ? `Mail received before ${new Intl.DateTimeFormat("en-US", { dateStyle: "long" }).format(new Date(`${f.since}T00:00:00`))} is never read.`
                : "Older mail in the mailbox is never read."
            }
            optional
          >
            <Input
              id={ids.since}
              type="date"
              value={f.since}
              onChange={(e) => set("since", e.target.value)}
            />
          </Field>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit">Save mailbox settings</Button>
          <UnsavedHint show={unsaved} />
          {initial.configured ? (
            <>
              <Button
                type="button"
                variant="outline"
                disabled={start.isPending || !initial.worker_enabled}
                onClick={() => start.mutate("test")}
              >
                Test connection
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={start.isPending || !initial.enabled || !initial.worker_enabled}
                onClick={() => start.mutate("poll")}
              >
                Check now
              </Button>
              <Button type="button" variant="ghost" onClick={() => setAction("remove")}>
                Remove mailbox
              </Button>
            </>
          ) : null}
        </div>
        {req ? (
          <p role="status" className="text-sm text-fg-muted">
            {req.status === "pending"
              ? req.kind === "test"
                ? "Testing the connection…"
                : "Checking the mailbox…"
              : req.status === "failed"
                ? (describeImapError(req.error_code) ?? "The check failed.")
                : req.kind === "test"
                  ? `Connected. ${plural(req.result.messages ?? 0, "message")} in the folder${
                      req.result.move_supported ? "" : "; this server cannot move messages"
                    }.`
                  : `Done. ${plural(req.result.messages ?? 0, "new message")} read.`}
          </p>
        ) : null}
        <p role="alert" className="text-sm text-fg empty:hidden">
          {problem}
        </p>
        <p role="status" className="text-sm text-fg-muted empty:hidden">
          {saved}
        </p>
      </form>

      <AdminActionDialog
        hint="Changing the mailbox settings asks for your own dashboard password again."
        open={action === "save"}
        onOpenChange={(o) => !o && setAction(null)}
        onDone={() => undefined}
        title="Save the mailbox settings?"
        description="The mailbox password is stored encrypted and never shown again."
        confirmLabel="Save"
        pendingLabel="Saving…"
        run={async (pw) => {
          await reauth(() => save.mutateAsync(pw))
          setSaved("Saved.")
          markSaved(f)
          refresh()
        }}
      />
      <AdminActionDialog
        hint="Removing the mailbox asks for your own dashboard password again."
        open={action === "remove"}
        onOpenChange={(o) => !o && setAction(null)}
        onDone={() => undefined}
        title="Remove the mailbox?"
        description="The server details and the stored password are deleted. Replies already stored stay."
        confirmLabel="Remove"
        pendingLabel="Removing…"
        run={async (pw) => {
          await reauth(() => repliesApi.removeImap(pw))
          refresh()
        }}
      />
    </div>
  )
}

/** Settings, Reporting tab (administrators only): the mailbox that replies are read from. */
export function ImapCard() {
  const q = useQuery({ queryKey: repliesKeys.imap, queryFn: repliesApi.imap })
  return (
    <FindingCard
      eyebrow="Replies"
      finding={
        q.isPending
          ? "Loading the mailbox settings…"
          : q.isError
            ? "The mailbox settings could not be loaded."
            : finding(q.data)
      }
      detail="Optional. SuckerPot reads the replies to your reports so the Results page can tell who answered."
    >
      {q.isPending ? (
        <SkeletonText lines={4} />
      ) : q.data ? (
        <ImapSettingsForm
          key={JSON.stringify([
            q.data.configured,
            q.data.host,
            q.data.password_set,
            q.data.enabled,
          ])}
          initial={q.data}
        />
      ) : null}
    </FindingCard>
  )
}
