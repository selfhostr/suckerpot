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
import { intlLocale, t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { ApiError } from "@/lib/api"
import { formatNumber } from "@/lib/format"
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
  if (!c.configured || !c.enabled) return t("imap_finding_none")
  return t("imap_finding_active", { minutes: c.poll_minutes })
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
        {s.last_poll_at
          ? s.last_error
            ? tNodes("imap_last_check_error", {}, { time: <RelativeTime iso={s.last_poll_at} /> })
            : tNodes(
                "imap_last_check_ok",
                { read: s.counters.fetched ?? 0, matched: s.counters.matched ?? 0 },
                { time: <RelativeTime iso={s.last_poll_at} /> },
              )
          : t("imap_never_checked")}
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
    if (!f.host.trim()) return t("imap_invalid_host", { example: "imap.example.net" })
    if (!Number.isInteger(f.port) || f.port < 1 || f.port > 65535) return t("imap_invalid_port")
    if (!f.username.trim()) return t("imap_invalid_username")
    if (!initial.password_set && !f.password) return t("imap_invalid_password")
    if (f.trusted_authserv_id && !AUTHSERV_RE.test(f.trusted_authserv_id))
      return t("imap_invalid_provider_name")
    if (!f.folder.trim()) return t("imap_invalid_folder", { example: "INBOX" })
    if (f.processed_action === "move" && (!f.move_folder.trim() || f.move_folder === f.folder))
      return t("imap_invalid_move_folder")
    if (f.poll_minutes < POLL_RANGE.min || f.poll_minutes > POLL_RANGE.max)
      return t("imap_invalid_poll", { min: POLL_RANGE.min, max: POLL_RANGE.max })
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
          {t("imap_shared_mailbox")}
        </p>
      ) : null}
      {initial.worker_enabled ? null : (
        <p
          role="note"
          className="flex items-start gap-2.5 rounded-md border border-border-strong bg-surface-raised px-3 py-2.5 text-sm text-fg"
        >
          <Info aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
          {t("imap_worker_off", { setting: "ABUSE_REPLIES_ENABLED" })}
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
            {t("imap_enable")}
            <span className="block text-xs text-fg-muted">{t("imap_enable_hint")}</span>
          </label>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <Field id={ids.host} label={t("imap_server")} hint={t("imap_server_hint")}>
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
            <Field id={ids.port} label={t("imap_port")}>
              <Input
                id={ids.port}
                inputMode="numeric"
                autoComplete="off"
                value={String(f.port)}
                onChange={(e) => set("port", num(e.target.value.replace(/\D/g, "")))}
              />
            </Field>
            <div className="flex flex-col gap-1.5">
              <span className="text-sm font-medium text-fg">{t("imap_security")}</span>
              <SegmentedControl
                size="form"
                label={t("imap_security")}
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
            label={t("imap_password")}
            hint={initial.password_set ? t("imap_password_hint_set") : t("imap_password_hint_new")}
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
            id={ids.folder}
            label={t("imap_folder")}
            hint={t("imap_folder_hint", { example: "INBOX" })}
          >
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
            label={t("imap_poll")}
            hint={t("imap_poll_hint", { min: POLL_RANGE.min, max: formatNumber(POLL_RANGE.max) })}
          >
            <Input
              id={ids.poll}
              inputMode="numeric"
              value={String(f.poll_minutes)}
              onChange={(e) => set("poll_minutes", num(e.target.value.replace(/\D/g, "")))}
            />
          </Field>
          <div className="flex flex-col gap-1.5">
            <span className="text-sm font-medium text-fg">{t("imap_after")}</span>
            <SegmentedControl
              size="form"
              label={t("imap_after")}
              value={f.processed_action}
              onChange={(v) => set("processed_action", v)}
              options={[
                { value: "mark_read", label: t("imap_after_mark_read") },
                { value: "move", label: t("imap_after_move") },
              ]}
              className="self-start"
            />
            <p className="text-xs text-fg-muted">{t("imap_after_hint")}</p>
          </div>
          {f.processed_action === "move" ? (
            <Field
              id={ids.move}
              label={t("imap_move_to")}
              hint={folders.length ? t("imap_move_to_hint_list") : t("imap_move_to_hint")}
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
            label={t("imap_provider_name")}
            hint={t("imap_provider_name_hint", { header: "Authentication-Results" })}
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
                  {tNodes(
                    "imap_provider_suggest",
                    { seen: suggest.seen, of: suggest.of },
                    { id: <code>{suggest.id}</code> },
                  )}
                </span>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => set("trusted_authserv_id", suggest.id)}
                >
                  {t("imap_provider_use")}
                </Button>
              </p>
            ) : null}
          </Field>
          <Field
            id={ids.since}
            label={t("imap_since")}
            hint={
              f.since
                ? t("imap_since_hint_date", {
                    date: new Intl.DateTimeFormat(intlLocale(), { dateStyle: "long" }).format(
                      new Date(`${f.since}T00:00:00`),
                    ),
                  })
                : t("imap_since_hint")
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
          <Button type="submit">{t("imap_save")}</Button>
          <UnsavedHint show={unsaved} />
          {initial.configured ? (
            <>
              <Button
                type="button"
                variant="outline"
                disabled={start.isPending || !initial.worker_enabled}
                onClick={() => start.mutate("test")}
              >
                {t("imap_test")}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={start.isPending || !initial.enabled || !initial.worker_enabled}
                onClick={() => start.mutate("poll")}
              >
                {t("imap_check_now")}
              </Button>
              <Button type="button" variant="ghost" onClick={() => setAction("remove")}>
                {t("imap_remove")}
              </Button>
            </>
          ) : null}
        </div>
        {req ? (
          <p role="status" className="text-sm text-fg-muted">
            {req.status === "pending"
              ? req.kind === "test"
                ? t("imap_testing")
                : t("imap_checking")
              : req.status === "failed"
                ? (describeImapError(req.error_code) ?? t("imap_check_failed"))
                : req.kind === "test"
                  ? t("imap_connected", {
                      count: req.result.messages ?? 0,
                      canMove: req.result.move_supported ? "yes" : "no",
                    })
                  : t("imap_done", { count: req.result.messages ?? 0 })}
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
        hint={t("imap_save_dialog_hint")}
        open={action === "save"}
        onOpenChange={(o) => !o && setAction(null)}
        onDone={() => undefined}
        title={t("imap_save_dialog_title")}
        description={t("imap_save_dialog_description")}
        confirmLabel={t("common_save")}
        pendingLabel={t("imap_saving")}
        run={async (pw) => {
          await reauth(() => save.mutateAsync(pw))
          setSaved(t("imap_saved"))
          markSaved(f)
          refresh()
        }}
      />
      <AdminActionDialog
        hint={t("imap_remove_dialog_hint")}
        open={action === "remove"}
        onOpenChange={(o) => !o && setAction(null)}
        onDone={() => undefined}
        title={t("imap_remove_dialog_title")}
        description={t("imap_remove_dialog_description")}
        confirmLabel={t("common_remove")}
        pendingLabel={t("imap_removing")}
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
      eyebrow={t("imap_eyebrow")}
      finding={
        q.isPending ? t("imap_loading") : q.isError ? t("imap_load_failed") : finding(q.data)
      }
      detail={t("imap_detail")}
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
