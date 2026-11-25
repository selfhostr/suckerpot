import { useQueryClient } from "@tanstack/react-query"
import { Check, CircleCheck, ExternalLink, Info, SkipForward } from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { CopyField } from "@/components/abuse/copy-field"
import { SendControl } from "@/components/abuse/send-control"
import { useSendMode, useSendQueue } from "@/components/abuse/send-hooks"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { SkeletonList } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { abuseApi, abuseKeys, describeAbuseError, withSameDayConfirm } from "@/lib/abuse"
import { buildMailto, describeQueue, type QueueItem } from "@/lib/abuse-send"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"

const isTyping = (target: EventTarget | null): boolean =>
  target instanceof HTMLElement &&
  (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName))

function Kbd({ children }: { children: string }) {
  return (
    <kbd className="rounded-sm border bg-bg px-1.5 py-0.5 font-sans text-2xs text-fg">
      {children}
    </kbd>
  )
}

/** Make Proton Mail the app that email links open in. Generic: browsers differ. */
function HandlerHelp() {
  return (
    <details className="group rounded-md border px-3 py-2 text-sm">
      <summary className="cursor-pointer rounded-sm text-fg-muted marker:text-fg-subtle hover:text-fg focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
        {t("send_queue_handler_title")}
      </summary>
      <div className="mt-2 space-y-2 text-fg-muted">
        <p>{t("send_queue_handler_free")}</p>
        <p>{t("send_queue_handler_link")}</p>
        <ol className="list-decimal space-y-1 pl-5">
          <li>
            {t("send_queue_handler_browser")}
          </li>
          <li>{t("send_queue_handler_os")}</li>
          <li>
            {t("send_queue_handler_copy")}
          </li>
        </ol>
      </div>
    </details>
  )
}

/**
 * The reports that are ready, one at a time: copy the message or open it in a mail app, send it
 * yourself, then record it and move on. Works with any mailbox, including free Proton addresses.
 */
export function SendQueue() {
  const qc = useQueryClient()
  const q = useSendQueue()
  const [skipped, setSkipped] = useState<string[]>([])
  const [done, setDone] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copiedNote, setCopiedNote] = useState<{ id: string; full: boolean } | null>(null)
  const openRef = useRef<HTMLAnchorElement>(null)
  const mode = useSendMode()

  const sorted = useMemo<QueueItem[]>(() => {
    const items = q.data?.items ?? []
    const rest = items.filter((i) => !skipped.includes(i.id))
    const later = skipped.flatMap((id) => items.filter((i) => i.id === id))
    return [...rest, ...later]
  }, [q.data, skipped])
  const current = sorted[0]
  const total = done + sorted.length

  const sentNext = useCallback(async () => {
    if (!current || busy) return
    setBusy(true)
    setError(null)
    try {
      // The message was read in full on this page, which is the review: a draft steps through it.
      let d = await abuseApi.report(current.id)
      if (d.status === "draft") {
        d = await abuseApi.setStatus(current.id, {
          to: "reviewed",
          revision: d.revision,
        })
      }
      const revision = d.revision
      await withSameDayConfirm((confirm) =>
        abuseApi.setStatus(current.id, {
          to: "sent",
          revision,
          ...(confirm ? { confirm_same_day: true } : {}),
        }),
      )
      setDone((n) => n + 1)
      setCopiedNote(null)
      await qc.invalidateQueries({ queryKey: abuseKeys.all })
    } catch (e) {
      setError(describeAbuseError(e))
    } finally {
      setBusy(false)
    }
  }, [current, busy, qc])

  const skip = useCallback(() => {
    if (!current || sorted.length < 2) return
    setSkipped((s) => [...s.filter((id) => id !== current.id), current.id])
    setCopiedNote(null)
    setError(null)
  }, [current, sorted.length])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return
      if (document.querySelector('[role="dialog"]')) return
      if (e.key === "o") openRef.current?.click()
      else if (e.key === "n") void sentNext()
      else if (e.key === "s") skip()
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [sentNext, skip])

  if (q.isPending) return <SkeletonList rows={3} />
  if (q.isError)
    return (
      <EmptyState
        icon={Info}
        title={t("send_queue_load_failed")}
        description={describeAbuseError(q.error)}
        action={
          <Button variant="outline" size="sm" onClick={() => void q.refetch()}>
            {t("common_try_again")}
          </Button>
        }
      />
    )
  if (!current)
    return (
      <EmptyState
        icon={CircleCheck}
        title={done > 0 ? t("send_queue_all_done") : t("send_queue_nothing")}
        description={
          done > 0
            ? t("send_queue_sent_count", { count: done })
            : t("send_queue_empty_explain", {
                needContact: q.data.missing.length > 0 ? "yes" : "no",
              })
        }
      />
    )

  const mail = buildMailto(current.recipient, current.subject, current.body_text)

  return (
    <div className="space-y-4 normal-nums">
      <p
        role="note"
        className="flex items-start gap-2.5 rounded-md border border-dashed border-border-strong px-3 py-2.5 text-sm text-fg"
      >
        <Info aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
        {t("send_queue_vpn_note")}
      </p>
      <FindingCard
        eyebrow={t("send_queue_eyebrow")}
        finding={describeQueue(sorted.length)}
        action={
          <span
            className="text-sm text-fg-muted tabular-nums"
            aria-label={t("send_queue_progress_aria")}
          >
            {t("send_queue_progress", { current: done + 1, total })}
          </span>
        }
      >
        <div key={current.id} className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <CopyField label={t("send_queue_field_recipient")} value={current.recipient} />
            <CopyField label={t("send_queue_field_subject")} value={current.subject} />
          </div>
          <CopyField label={t("send_queue_field_message")} value={current.body_text} multiline />
          <SendControl
            reportId={current.id}
            ready
            scheduledAt={current.scheduled_at}
            lastRequest={current.last_request}
            recipient={current.recipient}
            actions={
              <>
                <Button asChild size="sm" variant={mode === "click" ? "outline" : "default"}>
                  <a
                    ref={openRef}
                    href={mail.href}
                    onClick={() => {
                      // Not available on a plain-http page: the note below still tells what happened.
                      void Promise.resolve()
                        .then(() => navigator.clipboard.writeText(current.body_text))
                        .catch(() => undefined)
                      setCopiedNote({ id: current.id, full: mail.bodyIncluded })
                    }}
                  >
                    <ExternalLink aria-hidden /> {t("send_queue_open_mail")}
                  </a>
                </Button>
                <Button size="sm" variant="outline" disabled={busy} onClick={() => void sentNext()}>
                  <Check aria-hidden /> {busy ? t("send_queue_saving") : t("send_queue_mark_next")}
                </Button>
                <Button size="sm" variant="ghost" disabled={sorted.length < 2} onClick={skip}>
                  <SkipForward aria-hidden /> {t("send_queue_skip")}
                </Button>
              </>
            }
          />
          <p role="status" className="text-sm text-fg-muted empty:hidden">
            {copiedNote?.id === current.id
              ? mail.bodyIncluded
                ? t("send_queue_copied_full")
                : t("send_queue_copied_too_long")
              : null}
          </p>
          <p role="alert" className="text-sm text-fg empty:hidden">
            {error}
          </p>
          <p className="hidden text-xs text-fg-muted md:block">
            {tNodes(
              "send_queue_shortcuts",
              {},
              { o: <Kbd>o</Kbd>, n: <Kbd>n</Kbd>, s: <Kbd>s</Kbd> },
            )}
          </p>
        </div>
      </FindingCard>
      <HandlerHelp />
    </div>
  )
}
