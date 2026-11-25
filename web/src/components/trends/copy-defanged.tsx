import { Check, Copy } from "lucide-react"
import { useIpMask } from "@/app/ip-mask"
import { t } from "@/i18n"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useCopy } from "@/hooks/use-copy"
import { defangUrl } from "@/lib/trends"
import { cn } from "@/lib/utils"

/**
 * Copies the defanged form of a malware URL (hxxp://host[.]tld/path), so it
 * can be pasted into a ticket without ever becoming a live link. Hidden in
 * screenshot mode, like every copy button.
 */
export function CopyDefanged({ url, className }: { url: string; className?: string }) {
  const { copied, copy } = useCopy()
  const { masked } = useIpMask()
  if (masked) return null
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={(e) => {
            e.preventDefault()
            e.stopPropagation()
            void copy(defangUrl(url))
          }}
          className={cn(
            "inline-flex size-7 shrink-0 items-center justify-center rounded-sm text-fg-subtle transition-colors duration-150 hover:bg-surface-raised hover:text-fg",
            className,
          )}
          aria-label={copied ? t("common_copied") : t("trends_copy_defanged")}
        >
          {copied ? (
            <Check aria-hidden className="size-3.5" />
          ) : (
            <Copy aria-hidden className="size-3.5" />
          )}
        </button>
      </TooltipTrigger>
      <TooltipContent side="top">
        {copied ? t("common_copied") : t("trends_copy_defanged")}
      </TooltipContent>
    </Tooltip>
  )
}
