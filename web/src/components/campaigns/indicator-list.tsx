import { Check, Copy } from "lucide-react"
import { useIpMask } from "@/app/ip-mask"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useCopy } from "@/hooks/use-copy"
import { t } from "@/i18n"
import { maskIpsInText } from "@/lib/format"
import { KEY_KIND_LABEL, type CampaignIndicator } from "@/lib/campaigns"

function CopyButton({ text, label }: { text: string; label: string }) {
  const { copied, copy } = useCopy()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={() => void copy(text)}
          className="inline-flex size-7 shrink-0 items-center justify-center rounded-sm text-fg-subtle transition-colors duration-150 hover:bg-surface-raised hover:text-fg"
          aria-label={copied ? t("common_copied") : label}
        >
          {copied ? (
            <Check aria-hidden className="size-3.5" />
          ) : (
            <Copy aria-hidden className="size-3.5" />
          )}
        </button>
      </TooltipTrigger>
      <TooltipContent side="top">{copied ? t("common_copied") : label}</TooltipContent>
    </Tooltip>
  )
}

/**
 * What ties the campaign together, with the defanged form of every host: it can be pasted into a
 * ticket or a block rule without ever becoming a live link. Copy buttons hide in screenshot mode.
 */
export function IndicatorList({ items }: { items: readonly CampaignIndicator[] }) {
  const { masked } = useIpMask()
  return (
    <ul className="divide-y" aria-label={t("campaign_indicators_label")}>
      {items.map((i) => {
        const long = i.value.length > 40
        // Mask the raw value first, then defang it: a defanged address would slip past the mask.
        const shown =
          i.kind === "payload_host" && masked
            ? maskIpsInText(i.value).replaceAll(".", "[.]")
            : masked
              ? maskIpsInText(i.defanged)
              : i.defanged
        return (
          <li
            key={`${i.kind}:${i.value}`}
            className="flex items-center gap-2 py-2.5 first:pt-0 last:pb-0"
          >
            <div className="min-w-0 flex-1 space-y-0.5">
              <p className="text-xs text-fg-muted">
                {KEY_KIND_LABEL[i.kind]}
                <span className="text-fg-subtle">
                  {" "}
                  · {t("campaign_indicator_sources", { count: i.sources })}
                </span>
                {i.confidence === "low" ? (
                  <span className="ml-2 rounded-sm border border-border-strong px-1.5 py-px text-2xs text-fg-muted">
                    {t("campaign_indicator_low_confidence")}
                  </span>
                ) : null}
              </p>
              <p
                className="font-mono text-xs break-all text-fg"
                title={long && !masked ? i.value : undefined}
              >
                {long ? `${shown.slice(0, 16)}…${shown.slice(-8)}` : shown}
              </p>
            </div>
            {masked ? null : (
              <CopyButton
                text={i.defanged}
                label={t("campaign_indicator_copy", { kind: KEY_KIND_LABEL[i.kind].toLowerCase() })}
              />
            )}
          </li>
        )
      })}
    </ul>
  )
}
