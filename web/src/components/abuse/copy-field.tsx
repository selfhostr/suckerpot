import { Check, Copy } from "lucide-react"
import { useIpMask } from "@/app/ip-mask"
import { ExpandToggle } from "@/components/expand-toggle"
import { Button } from "@/components/ui/button"
import { useCopy } from "@/hooks/use-copy"
import { useExpandable } from "@/hooks/use-expandable"
import { maskIpsInText } from "@/lib/format"
import { cn } from "@/lib/utils"

interface CopyFieldProps {
  label: string
  value: string
  /** A scrollable block (the body) instead of a single line. */
  multiline?: boolean
  className?: string
}

/**
 * A read-only field of the draft with its own copy button. In screenshot mode the text is masked
 * and the button is hidden, like every other copy button.
 */
export function CopyField({ label, value, multiline = false, className }: CopyFieldProps) {
  const { copied, copy } = useCopy()
  const { masked } = useIpMask()
  const { ref: boxRef, expanded, overflowing, toggle } = useExpandable<HTMLPreElement>()
  const shown = masked ? maskIpsInText(value) : value
  return (
    <div className={cn("min-w-0 space-y-1.5", className)}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-fg-muted">{label}</span>
        {masked ? null : (
          <Button
            variant="ghost"
            size="xs"
            onClick={() => void copy(value)}
            aria-label={copied ? `${label} copied` : `Copy ${label.toLowerCase()}`}
          >
            {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
            <span aria-live="polite">{copied ? "Copied" : "Copy"}</span>
          </Button>
        )}
      </div>
      {/* The frame holds the border, so the scroll fade only fades the text. */}
      <div className="overflow-hidden rounded-md border bg-bg has-[pre:focus-visible]:ring-2 has-[pre:focus-visible]:ring-ring">
        <pre
          ref={boxRef}
          aria-label={label}
          tabIndex={multiline ? 0 : undefined}
          className={cn(
            "scroll-fade-y overflow-auto px-3 py-2 font-mono text-xs/5 break-words whitespace-pre-wrap text-fg outline-none",
            multiline ? cn("min-h-32", !expanded && "max-h-80") : "max-h-20",
          )}
        >
          {shown || " "}
        </pre>
      </div>
      {multiline ? (
        <ExpandToggle
          expanded={expanded}
          overflowing={overflowing}
          onToggle={toggle}
          label={label.toLowerCase()}
        />
      ) : null}
    </div>
  )
}
