import { ArrowRight, CircleCheck, FlaskConical, TriangleAlert } from "lucide-react"
import { Link } from "react-router"
import { OutcomeBadge } from "@/components/results/badges"
import { RelativeTime } from "@/components/relative-time"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { browserTimeZone, formatWindow, plural } from "@/lib/format"
import { describeBlockedRow, KIND_LABEL, type ReportItem } from "@/lib/abuse"

/** Identity check state as icon plus word: amber when it is blocked. */
export function GuardState({ ok }: { ok: boolean }) {
  return ok ? (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-fg-muted">
      <CircleCheck aria-hidden className="size-3.5 text-status-ok" />
      Checked
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-fg">
      <TriangleAlert aria-hidden className="size-3.5 text-sev-warning" />
      Blocked
    </span>
  )
}

/** One report of a provider: kind, size, window and check state. Opens the report. */
export function ReportRow({ r }: { r: ReportItem }) {
  const why = describeBlockedRow(r.guard)
  return (
    <li>
      <Link
        to={`/defend/abuse/${r.public_id}`}
        className="group grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1.5 px-4 py-3 transition-colors hover:bg-surface-hover focus-visible:bg-surface-hover focus-visible:outline-none sm:grid-cols-[10rem_1fr_auto_auto_1rem] sm:px-5"
      >
        <span className="flex items-center gap-2">
          <span className="text-xs font-medium text-fg-muted">{KIND_LABEL[r.kind]}</span>
        </span>
        <span className="order-3 col-span-2 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-sm text-fg-muted sm:order-none sm:col-span-1">
          <span className="text-fg">
            {r.kind === "attack_source"
              ? plural(r.subject_count, "address", "addresses")
              : r.kind === "payload_host"
                ? plural(r.subject_count, "host")
                : plural(r.subject_count, "server")}
          </span>
          <Tooltip>
            <TooltipTrigger asChild>
              <time tabIndex={0} dateTime={r.window_end} className="tabular-nums">
                {formatWindow(r.window_start, r.window_end)}
              </time>
            </TooltipTrigger>
            <TooltipContent side="top">
              {r.window_start} to {r.window_end}
              <span className="ml-1.5 text-fg-subtle">UTC, shown in {browserTimeZone()}</span>
            </TooltipContent>
          </Tooltip>
          {r.demo ? (
            <span className="inline-flex items-center gap-1 text-xs">
              <FlaskConical aria-hidden className="size-3" /> Demo
            </span>
          ) : null}
          {r.outcome ? <OutcomeBadge outcome={r.outcome.effective} className="-ml-1" /> : null}
          {why ? <span className="text-xs text-fg-muted">{why}</span> : null}
        </span>
        <GuardState ok={r.guard.ok} />
        <RelativeTime iso={r.updated_at} className="hidden text-xs sm:inline" />
        <ArrowRight
          aria-hidden
          className="hidden size-4 text-fg-subtle transition-transform group-hover:translate-x-0.5 sm:block"
        />
      </Link>
    </li>
  )
}
