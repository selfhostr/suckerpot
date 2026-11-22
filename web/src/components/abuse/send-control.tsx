import { useQueryClient } from "@tanstack/react-query"
import { Send } from "lucide-react"
import { useEffect, useRef, useState, type ReactNode } from "react"
import { useAuth } from "@/app/auth"
import { useSendMode } from "@/components/abuse/send-hooks"
import { ConfirmDialog } from "@/components/abuse/status-dialogs"
import { Button } from "@/components/ui/button"
import { abuseKeys, withSameDayConfirm } from "@/lib/abuse"
import {
  describeRequest,
  describeSendError,
  inFlight,
  sendApi,
  type SendRequest,
} from "@/lib/abuse-send"
import { formatClock } from "@/lib/format"

interface SendControlProps {
  reportId: string
  recipient: string
  /** True when the report can be sent: it is in the queue, or passes the same checks. */
  ready: boolean
  /** When the automatic mode will send it, or null. */
  scheduledAt: string | null
  lastRequest: SendRequest | null
  /** The revision the owner has read; the server refuses the send if it moved on. */
  revision?: number
  /** Buttons that sit in the same row as Send now (the queue passes its own). */
  actions?: ReactNode
  /** Send now is the one filled button of its screen; false when another action leads. */
  primary?: boolean
}

/**
 * What SuckerPot's own sending adds to a report: "Send now" in click mode, "Sending at hh:mm" with
 * Cancel in automatic mode, and the state of the last request in plain words.
 */
export function SendControl({
  reportId,
  recipient,
  ready,
  scheduledAt,
  lastRequest,
  revision,
  actions,
  primary = true,
}: SendControlProps) {
  const { canWrite } = useAuth()
  const mode = useSendMode()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [cancelError, setCancelError] = useState<string | null>(null)
  const status = lastRequest?.status
  const was = useRef(status)

  // A request that finished changes the report itself: reload it.
  useEffect(() => {
    if (inFlight(was.current) && !inFlight(status)) {
      void qc.invalidateQueries({ queryKey: abuseKeys.all })
    }
    was.current = status
  }, [status, qc])

  if (!canWrite) return null
  const pending = inFlight(status)
  const sentence = describeRequest(lastRequest)
  const at = mode === "auto" && !pending ? scheduledAt : null
  const canSend = mode === "click" && ready && !pending

  if (!sentence && !at && !canSend && !actions) return null

  async function cancel() {
    setCancelError(null)
    try {
      await sendApi.cancel(reportId)
      await qc.invalidateQueries({ queryKey: abuseKeys.all })
    } catch (e) {
      setCancelError(describeSendError(e))
    }
  }

  return (
    <div className="space-y-2">
      {canSend ? (
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant={primary ? "default" : "outline"} onClick={() => setOpen(true)}>
            <Send aria-hidden /> Send now
          </Button>
        </div>
      ) : null}
      {actions ? (
        <div className="flex flex-wrap items-center gap-2">
          {canSend ? <span className="text-sm text-fg-muted">Or send it yourself:</span> : null}
          {actions}
        </div>
      ) : null}
      {at ? (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-fg-muted">
          <span>
            Sending at <span className="tabular-nums">{formatClock(at)}</span>
          </span>
          <span aria-hidden>·</span>
          <Button size="xs" variant="outline" onClick={() => void cancel()}>
            Cancel
          </Button>
        </p>
      ) : null}
      {sentence ? (
        <p
          role="status"
          className={status === "failed" ? "text-sm text-fg" : "text-sm text-fg-muted"}
        >
          {sentence}
        </p>
      ) : null}
      <p role="alert" className="text-sm text-fg empty:hidden">
        {cancelError}
      </p>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title="Send this report now?"
        description={`The message goes to ${recipient} from your SMTP account, through the VPN. It cannot be recalled once sent.`}
        confirmLabel="Send now"
        describe={describeSendError}
        run={async () => {
          // A provider gets one mail a day: a second one today asks first.
          await withSameDayConfirm((confirm) => sendApi.send(reportId, revision, confirm))
          await qc.invalidateQueries({ queryKey: abuseKeys.all })
        }}
      />
    </div>
  )
}
