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
  if (code === "ip_not_allowed") return "exit not in a trusted range"
  if (code === "exit_is_self") return "the exit is this system's own address"
  if (code === "exit_asn_denied") return "the exit network is on your deny list"
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
    const t = setTimeout(() => setWatching(false), SWITCH_WATCH_MS)
    return () => clearTimeout(t)
  }, [watching])
  const v = q.data
  useEffect(() => {
    if (!check) return
    const t = setTimeout(() => {
      setCheck(null)
      setNotice("No answer yet. Ingest checks again by itself; the result shows under Last check.")
    }, CHECK_WATCH_MS)
    return () => clearTimeout(t)
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
          eyebrow="VPN"
          finding={
            v
              ? describeVpn(v)
              : q.isError
                ? "The VPN status is not available."
                : "Checking the VPN…"
          }
          detail="Enrichment and the sample collector only talk to the internet through this tunnel."
        >
          {!v ? (
            q.isPending ? (
              <SkeletonText lines={4} className="py-1" />
            ) : (
              <p className="text-sm text-fg-muted">This status is not available right now.</p>
            )
          ) : (
            <div className="space-y-5">
              {watching ? (
                <p
                  role="status"
                  className="flex items-center gap-2 rounded-md border bg-bg px-3 py-2 text-sm text-fg-muted"
                >
                  <LoaderCircle aria-hidden className="size-4 shrink-0 animate-spin" />
                  The tunnel is restarting. This page checks every 5 seconds.
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
            The vpn-config volume is not mounted or not writable. Uploading and reverting are off
            until it is.
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
          title="Reconnect the tunnel?"
          description="The tunnel restarts. Lookups and downloads pause until it is back and checked, usually within a minute. Events are still recorded."
          hint="Reconnecting asks for your own dashboard password again."
          confirmLabel="Reconnect"
          pendingLabel="Reconnecting…"
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
          {checking ? "Checking…" : "Check now"}
        </Button>
        <Button variant="outline" size="sm" onClick={onReconnect} disabled={!canReconnect}>
          <RotateCw aria-hidden className="size-4" />
          Reconnect
        </Button>
      </div>
      {checking ? (
        <p role="status" className="text-xs text-fg-muted">
          Ingest looks at the exit within a few seconds.
        </p>
      ) : notice ? (
        <p role="status" className="text-xs text-fg-muted">
          {notice}
        </p>
      ) : null}
      <p className="text-xs text-fg-muted">
        Check now asks ingest to test the gate without waiting. Reconnect restarts the tunnel on the
        same settings.
      </p>
    </div>
  )
}

function StatusDetails({ v }: { v: VpnStatus }) {
  const open = v.gate.state === "open"
  return (
    <dl className="grid grid-cols-2 gap-4">
      <Field label="Source">
        {v.source === "upload" ? "Uploaded configuration" : "Settings from .env"}
      </Field>
      <Field label="Gate">
        {open ? (
          <span className="inline-flex items-start gap-1.5 text-sm font-medium text-status-ok">
            <CircleCheck aria-hidden className="mt-0.5 size-3.5" strokeWidth={2.25} />
            Open
          </span>
        ) : (
          <span className="inline-flex items-start gap-1.5 text-sm font-medium text-sev-warning">
            <TriangleAlert aria-hidden className="mt-0.5 size-3.5" strokeWidth={2.25} />
            Closed: {gateReason(v.gate.reason)}
          </span>
        )}
      </Field>
      <Field label="Endpoint">
        {v.endpoint_ip ? (
          <span className={mono}>
            {v.endpoint_ip}
            {v.endpoint_port ? `:${v.endpoint_port}` : ""}
          </span>
        ) : (
          <span className="text-fg-muted">Not reported</span>
        )}
      </Field>
      <Field label="Exit address">
        {v.gate.egress_ip ? (
          <>
            <span className={mono}>{v.gate.egress_ip}</span>
            {describeNetwork(v.gate) ? (
              <span className="block text-xs text-fg-muted">{describeNetwork(v.gate)}</span>
            ) : null}
          </>
        ) : (
          <span className="text-fg-muted">Not checked yet</span>
        )}
      </Field>
      <Field label="Interface addresses" className="col-span-2 sm:col-span-1">
        {v.addresses?.length ? (
          <span className={mono}>{v.addresses.join(", ")}</span>
        ) : (
          <span className="text-fg-muted">Not reported</span>
        )}
      </Field>
      <Field label="Peer key fingerprint" className="col-span-2 sm:col-span-1">
        {v.peer_key_fingerprint ? (
          <span className={mono}>{v.peer_key_fingerprint}</span>
        ) : (
          <span className="text-fg-muted">Not reported</span>
        )}
      </Field>
      {v.source === "upload" && v.uploaded_at ? (
        <Field label="Uploaded" className="col-span-2 sm:col-span-1">
          <RelativeTime iso={v.uploaded_at} className="text-sm" />
          {v.uploaded_by ? <span className="text-fg-muted"> by {v.uploaded_by}</span> : null}
        </Field>
      ) : null}
      <Field label="Last check" className="col-span-2 sm:col-span-1">
        {v.gate.checked_at ? (
          <RelativeTime iso={v.gate.checked_at} className="text-sm" />
        ) : (
          <span className="text-fg-muted">Not yet</span>
        )}
        {v.last_check_request && !v.last_check_request.done_at ? (
          <span className="block text-xs text-fg-muted">
            A check was asked for{" "}
            <RelativeTime iso={v.last_check_request.requested_at} className="text-xs" />; waiting
            for ingest.
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
            This exit cannot be trusted
          </h3>
          <p className="text-sm text-fg-muted">
            {exitIp ? (
              <>
                The exit <span className="font-mono text-fg">{exitIp}</span>
                {network ? ` (${network})` : ""}{" "}
              </>
            ) : (
              "The exit "
            )}
            {reason === "exit_is_self"
              ? "looks like your own internet connection, not a VPN."
              : "belongs to a network on your deny list."}{" "}
            Outbound lookups stay paused. The uploaded file probably does not come from your VPN
            provider.
          </p>
        </div>
      </div>
      {canRevert ? (
        <>
          <Button variant="outline" onClick={() => setOpen(true)} className="shrink-0">
            <Undo2 aria-hidden className="size-4" />
            Use the .env settings again
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
            Trust needed
          </h3>
          <p className="text-sm text-fg-muted">
            The new exit <span className="font-mono text-fg">{exitIp ?? cidr}</span>
            {network ? ` (${network})` : ""} is outside the trusted ranges. Outbound lookups stay
            paused until you trust it.
          </p>
        </div>
      </div>
      <Button onClick={() => setOpen(true)} className="shrink-0">
        Trust {cidr}
      </Button>
      <AdminActionDialog
        open={open}
        onOpenChange={setOpen}
        title={`Trust ${cidr}?`}
        description={`Outbound lookups will resume through any address in ${cidr}. Only do this if the range belongs to your VPN provider.`}
        hint="Changing the VPN asks for your own dashboard password again."
        confirmLabel={`Trust ${cidr}`}
        pendingLabel="Trusting…"
        run={async (password) => {
          await vpnApi.trust(password)
        }}
        onDone={onDone}
      >
        <p className="rounded-md border bg-bg px-3 py-3 text-sm text-fg">
          {exitIp ? (
            <>
              <span className="font-mono">{exitIp}</span>
              {network ? ` — ${network}` : ""}
              <br />
            </>
          ) : null}
          Check that this network is your VPN provider, not your internet provider.
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
      eyebrow="Trusted exits"
      finding={
        loading
          ? "Checking the trusted exits…"
          : exits.length === 0
            ? "No extra exit range is trusted."
            : `${exits.length} extra exit ${exits.length === 1 ? "range is" : "ranges are"} trusted.`
      }
      detail="The ranges from .env are always trusted. Ranges added here are used on top of them."
      bodyClassName="px-0 sm:px-0 pt-3 pb-1 sm:pb-1"
    >
      {exits.length > 0 ? (
        <ul aria-label="Trusted exits" className="divide-y border-t">
          {exits.map((x) => (
            <li
              key={x.id}
              className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 px-4 py-3 sm:px-5"
            >
              <div className="min-w-0">
                <span className="font-mono text-sm text-fg">{x.cidr}</span>
                <p className="text-xs text-fg-muted">
                  Added <RelativeTime iso={x.created_at} className="text-xs" /> by {x.created_by}
                </p>
              </div>
              <Button
                variant="outline"
                size="sm"
                aria-label={`Remove ${x.cidr}`}
                onClick={() => setRemoving(x)}
              >
                <X aria-hidden className="size-3.5" />
                Remove
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
        title={`Stop trusting ${removing?.cidr ?? ""}?`}
        description="Outbound lookups pause if the VPN exit is in this range and not covered by .env."
        hint="Changing the VPN asks for your own dashboard password again."
        confirmLabel="Remove"
        pendingLabel="Removing…"
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
      setProblem("Choose a .conf file from your VPN provider.")
      return
    }
    if (f.size > VPN_CONF_MAX_BYTES) {
      setProblem(VPN_MESSAGES.tooLarge)
      return
    }
    const reader = new FileReader()
    reader.onerror = () => setProblem("The file could not be read.")
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
      eyebrow={first ? "Set up the tunnel" : "Replace the tunnel"}
      finding={
        first
          ? "Upload the WireGuard file from your VPN provider to start the tunnel."
          : "Upload the WireGuard file from your VPN provider to change where traffic leaves."
      }
      detail="The file is checked strictly, the private key is never shown again, and the new exit stays untrusted until you trust it."
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
            Drop a <code className="font-mono text-fg">.conf</code> file here (4 KiB at most), or
          </p>
          <input
            ref={inputRef}
            id={inputId}
            type="file"
            accept=".conf"
            className="sr-only"
            tabIndex={-1}
            aria-label="WireGuard configuration file"
            disabled={disabled}
            onChange={(e) => take(e.target.files?.[0])}
          />
          <Button variant="outline" disabled={disabled} onClick={() => inputRef.current?.click()}>
            Choose a file
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
                Remove file
              </Button>
              <Button size="sm" onClick={() => setConfirm(true)}>
                Review and upload
              </Button>
            </div>
          </div>
        ) : null}
      </div>
      <AdminActionDialog
        open={confirm}
        onOpenChange={setConfirm}
        title="Replace the VPN configuration?"
        description="The tunnel will use the uploaded file instead of the settings in .env."
        hint="Changing the VPN asks for your own dashboard password again."
        confirmLabel="Upload and restart the tunnel"
        pendingLabel="Uploading…"
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
            The VPN endpoint sees your home IP: only upload a file from your own VPN provider.
          </li>
          <li className="flex items-start gap-2">
            <LoaderCircle aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
            The tunnel restarts; outbound lookups pause for a few seconds.
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
      title="Use the .env settings again?"
      description="The uploaded file is deleted and the tunnel restarts on the settings in .env. Outbound lookups pause for a few seconds."
      hint="Changing the VPN asks for your own dashboard password again."
      confirmLabel="Use .env settings"
      pendingLabel="Restarting…"
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
        Drop the uploaded file and go back to the VPN settings in{" "}
        <code className="font-mono text-fg">.env</code>.
      </p>
      <Button variant="outline" disabled={disabled} onClick={() => setOpen(true)}>
        <Undo2 aria-hidden className="size-4" />
        Use the .env settings again
      </Button>
      <RevertDialog open={open} onOpenChange={setOpen} onDone={onDone} />
    </div>
  )
}
