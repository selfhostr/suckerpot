import { CircleCheck, Info } from "lucide-react"
import { useState } from "react"
import { FormKit } from "@/components/abuse/form-kit"
import { useFormQueue } from "@/components/abuse/form-hooks"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { SkeletonList } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { t } from "@/i18n"
import { describeAbuseError } from "@/lib/abuse"
import {
  describeFormItem,
  describeFormQueue,
  weekSpanLabel,
  type FormQueueItem,
} from "@/lib/abuse-forms"

function Card({
  item,
  open,
  onToggle,
  onDone,
}: {
  item: FormQueueItem
  open: boolean
  onToggle: () => void
  onDone: () => void
}) {
  const id = `form-${item.public_id}`
  return (
    <section
      aria-labelledby={id}
      className="overflow-hidden rounded-lg border bg-surface shadow-sm"
    >
      <header className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-5">
        <span className="min-w-0 space-y-0.5">
          <h2 id={id} className="type-card-title text-fg">
            {item.recipient.name}
          </h2>
          <span className="block text-xs text-fg-muted">
            {weekSpanLabel(item.window_start, item.window_end)} · {describeFormItem(item)}
            {item.form_host ? (
              <>
                {" · "}
                <span className="font-mono">{item.form_host}</span>
              </>
            ) : null}
          </span>
        </span>
        <Button size="sm" variant={open ? "ghost" : "outline"} onClick={onToggle}>
          {open ? t("abuse_form_queue_close_kit") : t("abuse_form_queue_open_kit")}
        </Button>
      </header>
      {open ? (
        <div className="border-t px-4 py-4 sm:px-5">
          <FormKit item={item} onDone={onDone} />
        </div>
      ) : null}
    </section>
  )
}

/**
 * Desks that take reports only through their web form: one card per provider and week. The card
 * opens the copy kit. Nothing is submitted by SuckerPot: the owner pastes each field and records
 * the submission with "Submitted".
 */
export function FormQueue() {
  const q = useFormQueue()
  const [open, setOpen] = useState<string | null>(null)
  const [done, setDone] = useState(0)

  if (q.isPending) return <SkeletonList rows={3} />
  if (q.isError)
    return (
      <EmptyState
        icon={Info}
        title={t("abuse_form_queue_load_failed")}
        description={describeAbuseError(q.error)}
        action={
          <Button variant="outline" size="sm" onClick={() => void q.refetch()}>
            {t("common_try_again")}
          </Button>
        }
      />
    )
  const items = q.data.items
  if (items.length === 0)
    return (
      <EmptyState
        icon={CircleCheck}
        title={done > 0 ? t("abuse_form_queue_all_done") : t("abuse_form_queue_nothing")}
        description={
          done > 0
            ? t("abuse_form_queue_recorded", { count: done })
            : t("abuse_form_queue_empty_explain", {
                needContact: q.data.missing.length > 0 ? "yes" : "no",
              })
        }
      />
    )
  return (
    <div className="space-y-4 normal-nums">
      <FindingCard
        eyebrow={t("abuse_form_queue_eyebrow")}
        finding={describeFormQueue(items.length)}
      >
        <p className="text-sm text-fg-muted">
          {t("abuse_form_queue_howto")}
        </p>
      </FindingCard>
      {items.map((item) => (
        <Card
          key={item.public_id}
          item={item}
          open={open === item.public_id}
          onToggle={() => setOpen((o) => (o === item.public_id ? null : item.public_id))}
          onDone={() => {
            setOpen(null)
            setDone((n) => n + 1)
          }}
        />
      ))}
    </div>
  )
}
