import { ArrowDownToLine, KeyRound, SquareTerminal, Globe, type LucideIcon } from "lucide-react"
import { useIpMask } from "@/app/ip-mask"
import { t, tk } from "@/i18n"
import { maskIpsInText } from "@/lib/format"
import { foldRepeats, type Excerpt, type ExcerptLine } from "@/lib/campaigns"
import { cn } from "@/lib/utils"

const KIND: Record<ExcerptLine["kind"], { icon: LucideIcon; labelKey: string }> = {
  login: { icon: KeyRound, labelKey: tk("campaign_excerpt_login") },
  command: { icon: SquareTerminal, labelKey: tk("campaign_excerpt_command") },
  request: { icon: Globe, labelKey: tk("campaign_excerpt_request") },
  download: { icon: ArrowDownToLine, labelKey: tk("campaign_excerpt_download") },
}

/**
 * A few real lines from one session of the campaign, as recorded. Text only: nothing in it is
 * a link or is ever run. Addresses are masked in screenshot mode. A line repeated back to back is
 * shown once with its count, so the excerpt reads as steps, not as noise.
 */
export function ExcerptBlock({ excerpt, className }: { excerpt: Excerpt; className?: string }) {
  const { masked } = useIpMask()
  return (
    <ol
      aria-label={t("campaign_excerpt_label")}
      className={cn(
        "divide-y overflow-hidden rounded-md border bg-bg font-mono text-xs",
        className,
      )}
    >
      {foldRepeats(excerpt.lines).map(({ line, times }, i) => {
        const { icon: Icon, labelKey } = KIND[line.kind]
        return (
          <li
            key={`${i}-${line.text}`}
            style={{ animationDelay: `${i * 35}ms` }}
            className="flex animate-fade-in items-start gap-2.5 px-3 py-2"
          >
            <Icon aria-hidden className="mt-0.5 size-3.5 shrink-0 text-fg-subtle" />
            <span className="sr-only">
              {t("campaign_excerpt_line_kind", { kind: t(labelKey) })}
            </span>
            <span className="min-w-0 break-all whitespace-pre-wrap text-fg">
              {masked ? maskIpsInText(line.text) : line.text}
            </span>
            {times > 1 ? (
              <span className="ml-auto shrink-0 rounded-sm border px-1.5 font-sans text-2xs text-fg-muted">
                <span aria-hidden>× </span>
                <span className="sr-only">{t("campaign_excerpt_repeats", { count: times })}</span>
                <span aria-hidden>{times}</span>
              </span>
            ) : null}
          </li>
        )
      })}
    </ol>
  )
}
