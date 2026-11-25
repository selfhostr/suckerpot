import { Check } from "lucide-react"
import { useId } from "react"
import { t } from "@/i18n"
import { CONSENTS } from "@/lib/network"

/**
 * The short, read-only list of what a member shares. Joining sends all five consents, so there is
 * nothing to tick: this list is how the person knows what they agree to.
 */
export function WhatYouShare() {
  const title = `${useId()}-title`
  return (
    <section className="space-y-2" aria-labelledby={title}>
      <h4 id={title} className="type-subtitle text-fg">
        {t("network_what_you_share_title")}
      </h4>
      <ul className="space-y-1.5">
        {CONSENTS.map((c) => (
          <li key={c.id} className="flex items-start gap-2 text-sm text-fg-muted">
            <Check
              aria-hidden
              className="mt-0.5 size-4 shrink-0 text-fg-subtle"
              strokeWidth={2.25}
            />
            {c.title}
          </li>
        ))}
      </ul>
      <p className="text-xs text-fg-muted">{t("network_what_you_share_never")}</p>
    </section>
  )
}
