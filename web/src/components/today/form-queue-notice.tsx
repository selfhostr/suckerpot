import { ArrowRight, ClipboardPaste } from "lucide-react"
import { Link } from "react-router"
import { FORM_QUEUE_LINK, formQueueSentence, type FormQueueCount } from "@/lib/today"
import { cn } from "@/lib/utils"

/**
 * A one-line reminder at the top of Today while form reports wait (M38). These desks take no mail,
 * so nothing goes out until the owner pastes the report into the provider's form: easy to miss.
 * Renders nothing when the queue is empty (or for a viewer, who gets no count from the API).
 */
export function FormQueueNotice({
  count,
  className,
}: {
  count: FormQueueCount | null | undefined
  className?: string
}) {
  const sentence = formQueueSentence(count)
  if (!sentence) return null
  return (
    <section
      aria-label="Reports to submit by web form"
      data-testid="form-queue-notice"
      className={cn(
        "flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border bg-surface px-4 py-2.5 shadow-sm",
        className,
      )}
    >
      <ClipboardPaste aria-hidden className="size-4 shrink-0 text-fg-muted" strokeWidth={1.85} />
      <p className="min-w-0 flex-1 text-sm text-pretty text-fg">{sentence}.</p>
      <Link
        to={FORM_QUEUE_LINK}
        className="inline-flex min-h-10 items-center gap-1 rounded-xs text-sm font-medium text-fg underline underline-offset-4 hover:text-fg-muted sm:min-h-0"
      >
        Open the form queue
        <ArrowRight aria-hidden className="size-3.5" />
      </Link>
    </section>
  )
}
