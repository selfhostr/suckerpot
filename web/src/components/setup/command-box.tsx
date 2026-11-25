import { Check, Copy } from "lucide-react"
import { Button } from "@/components/ui/button"
import { useCopy } from "@/hooks/use-copy"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"

/**
 * A host command to copy. The dashboard never edits `.env` and never runs anything (M28 P5):
 * the owner pastes this into a terminal on the machine that hosts SuckerPot.
 */
export function CommandBox({
  command,
  label,
  hint,
  className,
}: {
  command: string
  /** What the command does, in a few words ("Command to change the sensors"). */
  label: string
  hint?: React.ReactNode
  className?: string
}) {
  const { copied, copy } = useCopy()
  return (
    <div className={cn("space-y-1.5", className)}>
      <div className="flex items-center gap-2 rounded-md border bg-surface px-3 py-2">
        <code
          aria-label={label}
          className="min-w-0 flex-1 font-mono text-xs break-all text-fg sm:text-sm"
        >
          {command}
        </code>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void copy(command)}
          aria-label={t("setup_command_copy_label", { command })}
          className="shrink-0"
        >
          {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
          {copied ? t("common_copied") : t("common_copy")}
        </Button>
      </div>
      <span role="status" className="sr-only">
        {copied ? t("setup_command_copied") : ""}
      </span>
      {hint ? <p className="text-xs text-fg-muted">{hint}</p> : null}
    </div>
  )
}
