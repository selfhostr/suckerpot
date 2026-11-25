import { Check, Copy } from "lucide-react"
import { t } from "@/i18n"
import { Button } from "@/components/ui/button"
import { useCopy } from "@/hooks/use-copy"

/** Copies a text to the clipboard; the label names what is copied for screen readers. */
export function CopyButton({
  text,
  label,
  children,
  variant = "ghost",
  size,
}: {
  text: string
  label: string
  /** A visible caption turns the icon button into a labelled one. */
  children?: React.ReactNode
  variant?: "ghost" | "outline"
  size?: "icon-sm" | "sm"
}) {
  const { copied, copy } = useCopy()
  const Icon = copied ? Check : Copy
  return (
    <Button
      type="button"
      variant={variant}
      size={size ?? (children ? "sm" : "icon-sm")}
      onClick={() => void copy(text)}
      aria-label={children ? undefined : copied ? t("common_copied") : label}
      className="text-fg-muted hover:text-fg"
    >
      <Icon aria-hidden />
      {children ? (copied ? t("common_copied") : children) : null}
    </Button>
  )
}
