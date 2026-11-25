import { Check, Minus } from "lucide-react"
import { TermText } from "@/components/term"
import { BENEFIT, CONSENTS, NETWORK_FACTS, NEVER_SHARED, RESIDUAL_RISK } from "@/lib/network"
import { cn } from "@/lib/utils"

const TERMS = ["consensus", "blinded-indicator", "eligible-node"] as const

function Column({
  title,
  icon: Icon,
  items,
}: {
  title: string
  icon: typeof Check
  items: readonly { key: string; head?: string; text: string }[]
}) {
  return (
    <section className="min-w-0 space-y-3">
      <h4 className="type-subtitle text-fg">{title}</h4>
      <ul className="space-y-2.5">
        {items.map((i) => (
          <li key={i.key} className="flex items-start gap-2.5 text-sm text-fg-muted">
            <Icon
              aria-hidden
              className="mt-0.5 size-4 shrink-0 text-fg-subtle"
              strokeWidth={2.25}
            />
            <span>
              {i.head ? <span className="font-medium text-fg">{i.head}. </span> : null}
              <TermText text={i.text} terms={TERMS} />
            </span>
          </li>
        ))}
      </ul>
    </section>
  )
}

/**
 * Exactly what is shared and what never is, in plain words. Shown to everyone: on the Overview
 * before joining, in Settings and in the setup step. The wording comes from `lib/network.ts`, so
 * every place says the same thing.
 */
export function SharedExplainer({
  compact = false,
  className,
}: {
  /** Skips the benefit paragraph and the facts: for the setup step. */
  compact?: boolean
  className?: string
}) {
  return (
    <div className={cn("space-y-5", className)}>
      {compact ? null : <p className="max-w-3xl text-sm text-fg-muted">{BENEFIT}</p>}
      <div className="grid gap-6 md:grid-cols-2">
        <Column
          title="What is shared, once you join"
          icon={Check}
          items={CONSENTS.map((c) => ({ key: c.id, head: c.title, text: c.shared }))}
        />
        <Column
          title="What is never shared"
          icon={Minus}
          items={NEVER_SHARED.map((t) => ({ key: t, text: t }))}
        />
      </div>
      {compact ? null : (
        <ul className="space-y-1.5 border-t pt-4 text-sm text-fg-muted">
          {NETWORK_FACTS.map((f) => (
            <li key={f} className="max-w-3xl">
              <TermText text={f} terms={TERMS} />
            </li>
          ))}
        </ul>
      )}
      <p className="max-w-3xl rounded-md border bg-bg px-3 py-2 text-sm text-fg-muted">
        <span className="font-medium text-fg">One risk to know about. </span>
        {RESIDUAL_RISK}
      </p>
    </div>
  )
}
