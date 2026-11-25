import { useQuery, useQueryClient } from "@tanstack/react-query"
import {
  CircleCheck,
  FileUp,
  LoaderCircle,
  RefreshCw,
  RotateCw,
  ShieldAlert,
  TriangleAlert,
  Undo2,
  X,
} from "lucide-react"
import { useEffect, useId, useRef, useState } from "react"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { formatBytes } from "@/lib/format"
import { describeUserError, UserError } from "@/lib/users"
import { egressReason, sampleKeys } from "@/lib/samples"
import {
  CHECK_POLL_MS,
  CHECK_WATCH_MS,
  checkAnswered,
  describeNetwork,
  describeVpn,
  SWITCH_POLL_MS,
  SWITCH_WATCH_MS,
  VPN_CONF_MAX_BYTES,
  VPN_MESSAGES,
  vpnApi,
  vpnKeys,
  type TrustedExit,
  type VpnStatus,
} from "@/lib/vpn"
import { cn } from "@/lib/utils"

function Field({
  label,
  children,
  className,
}: {
  label: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={cn("min-w-0 space-y-1", className)}>
      <dt className="text-xs text-fg-muted">{label}</dt>
      <dd className="text-sm text-fg">{children}</dd>
    </div>
  )
}

/** This tab's wording for the gate reason; the shared sentences stay as they are. */
function gateReason(code: string | null): string {
  if (code === "ip_not_allowed") return t("vpn_gate_reason_not_trusted")
  if (code === "exit_is_self") return t("vpn_gate_reason_self")
  if (code === "exit_asn_denied") return t("vpn_gate_reason_denied")
  return egressReason(code)
}

const mono = "font-mono text-xs break-all"

/** Settings, VPN tab (admin only): where outbound traffic leaves, and replacing the tunnel. */
export function VpnTab() {
  const qc = useQueryClient()
  // After an upload the tab looks again every few seconds, for a couple of minutes.
  const [watching, setWatching] = useState(false)
  // After "Check now" it looks every 3 seconds, for a minute at most, until ingest has answered.
  const [check, setCheck] = useState<{ since: number } | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [reconnecting, setReconnecting] = useState(false)
  const q = useQuery({
    queryKey: vpnKeys.status,
    queryFn: vpnApi.status,
    refetchInterval: (query) => {
      const waiting = check && !(query.state.data && checkAnswered(query.state.data, check.since))
      return waiting ? CHECK_POLL_MS : watching ? SWITCH_POLL_MS : 30_000
    },
  })
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: vpnKeys.status })
    void qc.invalidateQueries({ queryKey: sampleKeys.egress })
  }
  const restarted = () => {
    setWatching(true)
    refresh()
  }
  useEffect(() => {
    if (!watching) return
    const timer = setTimeout(() => setWatching(false), SWITCH_WATCH_MS)
    return () => clearTimeout(timer)
  }, [watching])
  const v = q.data
  useEffect(() => {
    if (!check) return
    const timer = setTimeout(() => {
      setCheck(null)
      setNotice(t("vpn_check_no_answer"))
    }, CHECK_WATCH_MS)
    return () => clearTimeout(timer)
  }, [check])
  // Over as soon as ingest has looked at the gate after the request (or after one minute, above).
  const checking = check !== null && !(v && checkAnswered(v, check.since))

  async function checkNow() {
    setNotice(null)
    try {
      const r = await vpnApi.check()
      const asked = r?.requested_at ? Date.parse(r.requested_at) : NaN
      setCheck({ since: Number.isNaN(asked) ? Date.now() : asked })
      void qc.invalidateQueries({ queryKey: vpnKeys.status })
    } catch (e) {
      setNotice(e instanceof UserError ? (e.detail ?? describeUserError(e)) : VPN_MESSAGES.generic)
    }
  }

  const controls = v ? (
    <TunnelButtons
      checking={checking}
      canReconnect={v.config_writable}
      onCheck={() => void checkNow()}
      onReconnect={() => setReconnecting(true)}
      notice={notice}
    />
  ) : null

  return (
    // Wide screens: the tunnel's status on the left, what changes it on the right.
    <div className="grid grid-cols-1 gap-4 2xl:grid-cols-2 2xl:items-start">
      <div className="grid grid-cols-1 gap-4">
        <FindingCard
          eyebrow={t("settings_tab_vpn")}
          finding={
            v ? describeVpn(v) : q.isError ? t("setup_vpn_unavailable") : t("setup_vpn_checking")
          }
          detail={t("vpn_detail")}
        >
          {!v ? (
            q.isPending ? (
              <SkeletonText lines={4} className="py-1" />
            ) : (
              <p className="text-sm text-fg-muted">{t("settings_status_unavailable")}</p>
            )
          ) : (
            <div className="space-y-5">
              {watching ? (
                <p
                  role="status"
                  className="flex items-center gap-2 rounded-md border bg-bg px-3 py-2 text-sm text-fg-muted"
                >
                  <LoaderCircle aria-hidden className="size-4 shrink-0 animate-spin" />
                  {t("vpn_restarting")}
                </p>
              ) : null}
              <StatusDetails v={v} />
              {controls}
            </div>
          )}
        </FindingCard>

        {v && !v.config_writable ? (
          <p className="flex items-start gap-2 rounded-lg border border-dashed px-4 py-3 text-sm text-fg-muted sm:px-5">
            <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-sev-warning" />
            {t("vpn_not_writable")}
          </p>
        ) : null}
      </div>

      <div className="grid grid-cols-1 gap-4">
        {v?.trust_blocked ? (
          <BlockedCallout
            reason={v.trust_blocked}
            exitIp={v.gate.egress_ip}
            network={describeNetwork(v.gate)}
            canRevert={v.source === "upload" && v.config_writable}
            onDone={restarted}
          />
        ) : null}

        {v?.trust_candidate ? (
          <TrustCallout
            cidr={v.trust_candidate}
            exitIp={v.gate.egress_ip}
            network={describeNetwork(v.gate)}
            onDone={refresh}
          />
        ) : null}

        <AdminActionDialog
          open={reconnecting}
          onOpenChange={setReconnecting}
          title={t("vpn_reconnect_title")}
          description={t("vpn_reconnect_description")}
          hint={t("vpn_reconnect_hint")}
          confirmLabel={t("vpn_reconnect")}
          pendingLabel={t("vpn_reconnecting")}
          run={async (password) => {
            await vpnApi.reconnect(password)
          }}
          onDone={() => {
            setNotice(null)
            restarted()
          }}
        />

        <UploadCard onUploaded={restarted} disabled={v ? !v.config_writable : false} />

        <TrustedExitsCard
          exits={v?.trusted_exits ?? []}
          loading={q.isPending}
          onChanged={refresh}
        />

        {v?.source === "upload" && !v.trust_blocked ? (
          <RevertCard onDone={restarted} disabled={!v.config_writable} />
        ) : null}
      </div>
    </div>
  )
}

/** "Check now" and "Reconnect", with the progress of a check in words. */
function TunnelButtons({
  checking,
  canReconnect,
  onCheck,
  onReconnect,
  notice,
}: {
  checking: boolean
  canReconnect: boolean
  onCheck: () => void
  onReconnect: () => void
  notice: string | null
}) {
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" size="sm" onClick={onCheck} disabled={checking}>
          {checking ? (
            <LoaderCircle aria-hidden className="size-4 animate-spin" />
          ) : (
            <RefreshCw aria-hidden className="size-4" />
          )}
          {checking ? t("vpn_checking") : t("vpn_check_now")}
        </Button>
        <Button variant="outline" size="sm" onClick={onReconnect} disabled={!canReconnect}>
          <RotateCw aria-hidden className="size-4" />
          {t("vpn_reconnect")}
        </Button>
      </div>
      {checking ? (
        <p role="status" className="text-xs text-fg-muted">
          {t("vpn_check_wait")}
        </p>
      ) : notice ? (
        <p role="status" className="text-xs text-fg-muted">
          {notice}
        </p>
      ) : null}
      <p className="text-xs text-fg-muted">{t("vpn_buttons_note")}</p>
    </div>
  )
}

function StatusDetails({ v }: { v: VpnStatus }) {
  const open = v.gate.state === "open"
  return (
    <dl className="grid grid-cols-2 gap-4">
      <Field label={t("vpn_field_source")}>
        {v.source === "upload" ? t("vpn_source_upload") : t("vpn_source_env")}
      </Field>
      <Field label={t("vpn_field_gate")}>
        {open ? (
          <span className="inline-flex items-start gap-1.5 text-sm font-medium text-status-ok">
            <CircleCheck aria-hidden className="mt-0.5 size-3.5" strokeWidth={2.25} />
            {t("common_open")}
          </span>
        ) : (
          <span className="inline-flex items-start gap-1.5 text-sm font-medium text-sev-warning">
            <TriangleAlert aria-hidden className="mt-0.5 size-3.5" strokeWidth={2.25} />
            {t("vpn_gate_closed", { reason: gateReason(v.gate.reason) })}
          </span>
        )}
      </Field>
      <Field label={t("vpn_field_endpoint")}>
        {v.endpoint_ip ? (
          <span className={mono}>
            {v.endpoint_ip}
            {v.endpoint_port ? `:${v.endpoint_port}` : ""}
          </span>
        ) : (
          <span className="text-fg-muted">{t("vpn_not_reported")}</span>
        )}
      </Field>
      <Field label={t("vpn_field_exit")}>
        {v.gate.egress_ip ? (
          <>
            <span className={mono}>{v.gate.egress_ip}</span>
            {describeNetwork(v.gate) ? (
              <span className="block text-xs text-fg-muted">{describeNetwork(v.gate)}</span>
            ) : null}
          </>
        ) : (
          <span className="text-fg-muted">{t("vpn_not_checked")}</span>
        )}
      </Field>
      <Field label={t("vpn_field_addresses")} className="col-span-2 sm:col-span-1">
        {v.addresses?.length ? (
          <span className={mono}>{v.addresses.join(", ")}</span>
        ) : (
          <span className="text-fg-muted">{t("vpn_not_reported")}</span>
        )}
      </Field>
      <Field label={t("vpn_field_fingerprint")} className="col-span-2 sm:col-span-1">
        {v.peer_key_fingerprint ? (
          <span className={mono}>{v.peer_key_fingerprint}</span>
        ) : (
          <span className="text-fg-muted">{t("vpn_not_reported")}</span>
        )}
      </Field>
      {v.source === "upload" && v.uploaded_at ? (
        <Field label={t("vpn_field_uploaded")} className="col-span-2 sm:col-span-1">
          <RelativeTime iso={v.uploaded_at} className="text-sm" />
          {v.uploaded_by ? (
            <span className="text-fg-muted"> {t("vpn_uploaded_by", { user: v.uploaded_by })}</span>
          ) : null}
        </Field>
      ) : null}
      <Field label={t("vpn_field_last_check")} className="col-span-2 sm:col-span-1">
        {v.gate.checked_at ? (
          <RelativeTime iso={v.gate.checked_at} className="text-sm" />
        ) : (
          <span className="text-fg-muted">{t("vpn_not_yet")}</span>
        )}
        {v.last_check_request && !v.last_check_request.done_at ? (
          <span className="block text-xs text-fg-muted">
            {tNodes(
              "vpn_check_requested",
              {},
              {
                time: <RelativeTime iso={v.last_check_request.requested_at} className="text-xs" />,
              },
            )}
          </span>
        ) : null}
      </Field>
    </dl>
  )
}

/* --- Trust ---------------------------------------------------------------- */

/** The exit can never be trusted: it looks like the home connection or a denied network. */
function BlockedCallout({
  reason,
  exitIp,
  network,
  canRevert,
  onDone,
}: {
  reason: "exit_is_self" | "exit_asn_denied"
  exitIp: string | null
  network: string | null
  canRevert: boolean
  onDone: () => void
}) {
  const [open, setOpen] = useState(false)
  return (
    <section
      aria-labelledby="vpn-blocked-title"
      className="flex flex-col gap-3 rounded-lg border border-sev-warning/40 bg-card px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-5"
    >
      <div className="flex min-w-0 items-start gap-3">
        <ShieldAlert aria-hidden className="mt-0.5 size-5 shrink-0 text-sev-warning" />
        <div className="min-w-0 space-y-1">
          <h3 id="vpn-blocked-title" className="type-subtitle text-fg">
            {t("vpn_blocked_title")}
          </h3>
          <p className="text-sm text-fg-muted">
            {tNodes(
              "vpn_blocked_body",
              {
                hasIp: exitIp ? "yes" : "no",
                suffix: network ? ` (${network})` : "",
                reason: reason === "exit_is_self" ? "self" : "denied",
              },
              { ip: <span className="font-mono text-fg">{exitIp}</span> },
            )}
          </p>
        </div>
      </div>
      {canRevert ? (
        <>
          <Button variant="outline" onClick={() => setOpen(true)} className="shrink-0">
            <Undo2 aria-hidden className="size-4" />
            {t("vpn_revert_button")}
          </Button>
          <RevertDialog open={open} onOpenChange={setOpen} onDone={onDone} />
        </>
      ) : null}
    </section>
  )
}

function TrustCallout({
  cidr,
  exitIp,
  network,
  onDone,
}: {
  cidr: string
  exitIp: string | null
  network: string | null
  onDone: () => void
}) {
  const [open, setOpen] = useState(false)
  return (
    <section
      aria-labelledby="vpn-trust-title"
      className="flex flex-col gap-3 rounded-lg border border-sev-warning/40 bg-card px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-5"
    >
      <div className="flex min-w-0 items-start gap-3">
        <ShieldAlert aria-hidden className="mt-0.5 size-5 shrink-0 text-sev-warning" />
        <div className="min-w-0 space-y-1">
          <h3 id="vpn-trust-title" className="type-subtitle text-fg">
            {t("vpn_trust_title")}
          </h3>
          <p className="text-sm text-fg-muted">
            {tNodes(
              "vpn_trust_body",
              { suffix: network ? ` (${network})` : "" },
              { ip: <span className="font-mono text-fg">{exitIp ?? cidr}</span> },
            )}
          </p>
        </div>
      </div>
      <Button onClick={() => setOpen(true)} className="shrink-0">
        {t("vpn_trust_button", { cidr })}
      </Button>
      <AdminActionDialog
        open={open}
        onOpenChange={setOpen}
        title={t("vpn_trust_dialog_title", { cidr })}
        description={t("vpn_trust_dialog_description", { cidr })}
        hint={t("vpn_change_hint")}
        confirmLabel={t("vpn_trust_button", { cidr })}
        pendingLabel={t("vpn_trusting")}
        run={async (password) => {
          await vpnApi.trust(password)
        }}
        onDone={onDone}
      >
        <p className="rounded-md border bg-bg px-3 py-3 text-sm text-fg">
          {exitIp ? (
            <>
              <span className="font-mono">{exitIp}</span>
              {network ? ` · ${network}` : ""}
              <br />
            </>
          ) : null}
          {t("vpn_trust_check")}
        </p>
      </AdminActionDialog>
    </section>
  )
}

function TrustedExitsCard({
  exits,
  loading,
  onChanged,
}: {
  exits: TrustedExit[]
  loading: boolean
  onChanged: () => void
}) {
  const [removing, setRemoving] = useState<TrustedExit | null>(null)
  return (
    <FindingCard
      eyebrow={t("vpn_exits_title")}
      finding={
        loading
          ? t("vpn_exits_checking")
          : exits.length === 0
            ? t("vpn_exits_none")
            : t("vpn_exits_count", { count: exits.length })
      }
      detail={t("vpn_exits_detail")}
      bodyClassName="px-0 sm:px-0 pt-3 pb-1 sm:pb-1"
    >
      {exits.length > 0 ? (
        <ul aria-label={t("vpn_exits_title")} className="divide-y border-t">
          {exits.map((x) => (
            <li
              key={x.id}
              className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 px-4 py-3 sm:px-5"
            >
              <div className="min-w-0">
                <span className="font-mono text-sm text-fg">{x.cidr}</span>
                <p className="text-xs text-fg-muted">
                  {tNodes(
                    "vpn_exit_added",
                    { user: x.created_by },
                    { time: <RelativeTime iso={x.created_at} className="text-xs" /> },
                  )}
                </p>
              </div>
              <Button
                variant="outline"
                size="sm"
                aria-label={t("vpn_exit_remove_label", { cidr: x.cidr })}
                onClick={() => setRemoving(x)}
              >
                <X aria-hidden className="size-3.5" />
                {t("common_remove")}
              </Button>
            </li>
          ))}
        </ul>
      ) : null}
      <AdminActionDialog
        open={removing !== null}
        onOpenChange={(o) => {
          if (!o) setRemoving(null)
        }}
        title={t("vpn_untrust_title", { cidr: removing?.cidr ?? "" })}
        description={t("vpn_untrust_description")}
        hint={t("vpn_change_hint")}
        confirmLabel={t("common_remove")}
        pendingLabel={t("vpn_removing")}
        run={async (password) => {
          if (removing) await vpnApi.untrust(removing.id, password)
        }}
        onDone={onChanged}
      />
    </FindingCard>
  )
}

/* --- Upload --------------------------------------------------------------- */

export function UploadCard({
  onUploaded,
  disabled,
  first = false,
}: {
  onUploaded: () => void
  disabled: boolean
  /** No tunnel yet (first run): the card sets one up instead of replacing it. */
  first?: boolean
}) {
  const inputId = useId()
  const inputRef = useRef<HTMLInputElement>(null)
  // The file text lives here only until it is sent (or removed), and is dropped right after.
  const [file, setFile] = useState<{ name: string; bytes: number; text: string } | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const [confirm, setConfirm] = useState(false)

  function take(f: File | undefined) {
    setProblem(null)
    setFile(null)
    if (!f) return
    if (!f.name.toLowerCase().endsWith(".conf")) {
      setProblem(t("vpn_upload_choose_conf"))
      return
    }
    if (f.size > VPN_CONF_MAX_BYTES) {
      setProblem(VPN_MESSAGES.tooLarge)
      return
    }
    const reader = new FileReader()
    reader.onerror = () => setProblem(t("vpn_upload_unreadable"))
    reader.onload = () => {
      const text = typeof reader.result === "string" ? reader.result : ""
      if (new Blob([text]).size > VPN_CONF_MAX_BYTES) setProblem(VPN_MESSAGES.tooLarge)
      else setFile({ name: f.name, bytes: f.size, text })
    }
    reader.readAsText(f)
  }

  function clear() {
    setFile(null)
    setProblem(null)
    if (inputRef.current) inputRef.current.value = ""
  }

  return (
    <FindingCard
      eyebrow={first ? t("vpn_upload_title_first") : t("vpn_upload_title")}
      finding={first ? t("vpn_upload_finding_first") : t("vpn_upload_finding")}
      detail={t("vpn_upload_detail")}
    >
      <div className="space-y-4">
        <div
          onDragOver={(e) => {
            e.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragging(false)
            take(e.dataTransfer.files[0])
          }}
          className={cn(
            "flex flex-col items-center gap-3 rounded-lg border border-dashed px-4 py-6 text-center",
            dragging && "border-fg bg-muted",
          )}
        >
          <FileUp aria-hidden className="size-6 text-fg-muted" />
          <p className="text-sm text-fg-muted">
            {tNodes(
              "vpn_upload_drop",
              {},
              { file: <code className="font-mono text-fg">.conf</code> },
            )}
          </p>
          <input
            ref={inputRef}
            id={inputId}
            type="file"
            accept=".conf"
            className="sr-only"
            tabIndex={-1}
            aria-label={t("vpn_upload_file_label")}
            disabled={disabled}
            onChange={(e) => take(e.target.files?.[0])}
          />
          <Button variant="outline" disabled={disabled} onClick={() => inputRef.current?.click()}>
            {t("vpn_upload_choose")}
          </Button>
        </div>
        {problem ? (
          <p role="alert" className="flex items-start gap-1.5 text-sm text-fg">
            <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-sev-warning" />
            {problem}
          </p>
        ) : null}
        {file ? (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border bg-bg px-3 py-2">
            <p className="min-w-0 text-sm text-fg">
              <span className="font-mono text-xs break-all">{file.name}</span>{" "}
              <span className="text-fg-muted">· {formatBytes(file.bytes)}</span>
            </p>
            <div className="flex gap-2">
              <Button variant="ghost" size="sm" onClick={clear}>
                {t("vpn_upload_remove")}
              </Button>
              <Button size="sm" onClick={() => setConfirm(true)}>
                {t("vpn_upload_review")}
              </Button>
            </div>
          </div>
        ) : null}
      </div>
      <AdminActionDialog
        open={confirm}
        onOpenChange={setConfirm}
        title={t("vpn_upload_dialog_title")}
        description={t("vpn_upload_dialog_description")}
        hint={t("vpn_change_hint")}
        confirmLabel={t("vpn_upload_dialog_confirm")}
        pendingLabel={t("vpn_uploading")}
        run={async (password) => {
          if (!file) return
          await vpnApi.upload(file.text, password)
        }}
        onDone={() => {
          clear()
          onUploaded()
        }}
      >
        <ul className="space-y-2 rounded-md border bg-bg px-3 py-3 text-sm text-fg">
          <li className="flex items-start gap-2">
            <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-sev-warning" />
            {t("vpn_upload_warning_ip")}
          </li>
          <li className="flex items-start gap-2">
            <LoaderCircle aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
            {t("vpn_upload_warning_restart")}
          </li>
        </ul>
      </AdminActionDialog>
    </FindingCard>
  )
}

/* --- Revert --------------------------------------------------------------- */

function RevertDialog({
  open,
  onOpenChange,
  onDone,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onDone: () => void
}) {
  return (
    <AdminActionDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t("vpn_revert_title")}
      description={t("vpn_revert_description")}
      hint={t("vpn_change_hint")}
      confirmLabel={t("vpn_revert_confirm")}
      pendingLabel={t("vpn_restarting_label")}
      run={async (password) => {
        await vpnApi.revert(password)
      }}
      onDone={onDone}
    />
  )
}

function RevertCard({ onDone, disabled }: { onDone: () => void; disabled: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-dashed px-4 py-3 sm:px-5">
      <p className="text-sm text-fg-muted">
        {tNodes("vpn_revert_note", {}, { env: <code className="font-mono text-fg">.env</code> })}
      </p>
      <Button variant="outline" disabled={disabled} onClick={() => setOpen(true)}>
        <Undo2 aria-hidden className="size-4" />
        {t("vpn_revert_button")}
      </Button>
      <RevertDialog open={open} onOpenChange={setOpen} onDone={onDone} />
    </div>
  )
}
