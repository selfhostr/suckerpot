import { useId } from "react"
import { useIpMask } from "@/app/ip-mask"
import { Switch } from "@/components/ui/switch"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"

/** "Mask IPs" switch for screenshot mode. */
export function MaskToggle({ className }: { className?: string }) {
  const { masked, setMasked } = useIpMask()
  const id = useId()
  return (
    <div className={cn("flex items-center justify-between gap-2", className)}>
      <label htmlFor={id} className="text-xs text-fg-muted">
        {t("ui_mask_ips")}
        <span className="sr-only"> {t("ui_mask_ips_sr")}</span>
      </label>
      <Switch id={id} size="sm" checked={masked} onCheckedChange={setMasked} />
    </div>
  )
}
