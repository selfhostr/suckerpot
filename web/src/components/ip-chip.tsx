import { Check, Copy } from "lucide-react"
import { Link } from "react-router"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { t } from "@/i18n"
import { useIpMask } from "@/app/ip-mask"
import { subjectProps } from "@/app/view-transitions"
import { useCopy } from "@/hooks/use-copy"
import { maskIp } from "@/lib/format"
import { cn } from "@/lib/utils"

interface IPChipProps {
  ip: string
  /** Defaults to the Attacks list filtered by this address. Pass null for no link. */
  href?: string | null
  /** Force masking on or off; defaults to the global "Mask IPs" setting. */
  masked?: boolean
  copyable?: boolean
  /** `chip`: bordered pill. `ghost`: plain mono text, copy button on hover (dense lists). */
  variant?: "chip" | "ghost"
  /** Shared-element key: the address morphs into the page this row opens (view-transitions.ts). */
  subject?: string
  className?: string
}

/** Monospaced address with a copy button; clicking opens the filtered view. */
export function IPChip({
  ip,
  href,
  masked: maskedProp,
  copyable = true,
  variant = "chip",
  subject,
  className,
}: IPChipProps) {
  const { copied, copy } = useCopy()
  const { masked: maskAll } = useIpMask()
  const masked = maskedProp ?? maskAll
  const shown = masked ? maskIp(ip) : ip
  const to = href === undefined ? `/attacks?src_ip=${encodeURIComponent(ip)}` : href

  return (
    <span
      className={cn(
        "group/ip relative inline-flex h-(--chip) max-w-full items-center rounded-sm font-mono text-xs text-fg",
        variant === "chip" ? "border border-border bg-surface-hover/60" : "-ml-1.5",
        className,
      )}
    >
      {to ? (
        <Link
          to={to}
          {...(subject ? subjectProps(subject) : null)}
          className="truncate rounded-sm px-1.5 transition-colors duration-150 hover:text-fg hover:underline hover:decoration-fg-subtle hover:underline-offset-4"
          aria-label={
            masked ? t("ipchip_masked_link") : t("ipchip_link", { ip })
          }
        >
          {shown}
        </Link>
      ) : (
        <span {...(subject ? subjectProps(subject) : null)} className="truncate px-1.5">
          {shown}
        </span>
      )}
      {copyable && !masked ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              onClick={(e) => {
                e.preventDefault()
                e.stopPropagation()
                void copy(ip)
              }}
              className={cn(
                "mr-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-xs text-fg-subtle transition-[color,background-color,opacity] duration-150 hover:bg-surface-raised hover:text-fg focus-visible:text-fg focus-visible:opacity-100",
                variant === "ghost" &&
                  "opacity-0 group-hover/ip:opacity-100 group-hover/row:opacity-100 pointer-coarse:hidden",
              )}
              aria-label={copied ? t("common_copied") : t("ipchip_copy", { ip })}
            >
              {copied ? (
                <Check aria-hidden className="size-3" />
              ) : (
                <Copy aria-hidden className="size-3" />
              )}
            </button>
          </TooltipTrigger>
          <TooltipContent side="top">{copied ? t("common_copied") : t("ipchip_copy_tip")}</TooltipContent>
        </Tooltip>
      ) : null}
    </span>
  )
}
