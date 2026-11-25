import { useIpMask } from "@/app/ip-mask"
import { ExpandToggle } from "@/components/expand-toggle"
import { CopyButton } from "@/components/defend/copy-button"
import { useExpandable } from "@/hooks/use-expandable"
import { maskIpsInText } from "@/lib/format"
import { cn } from "@/lib/utils"

/**
 * Monospace text with a copy button. Always rendered as plain text, never as HTML: rule text and
 * values come from attacker traffic. Addresses are masked, and copying is off, in screenshot mode.
 */
export function CodeBlock({
  text,
  label,
  caption,
  className,
}: {
  text: string
  /** Accessible name of the block, e.g. "Sigma rule". */
  label: string
  caption?: string
  className?: string
}) {
  const { masked } = useIpMask()
  const { ref: boxRef, expanded, overflowing, toggle } = useExpandable<HTMLPreElement>()
  return (
    <figure className={cn("overflow-hidden rounded-md border bg-bg", className)}>
      <figcaption className="flex items-center justify-between gap-2 border-b px-3 py-1.5 text-xs text-fg-muted">
        <span className="truncate">{caption ?? label}</span>
        {masked ? null : <CopyButton text={text} label={`Copy ${label}`} />}
      </figcaption>
      <pre
        ref={boxRef}
        tabIndex={0}
        aria-label={label}
        className={cn(
          "scroll-fade-y overflow-auto px-3 py-2.5 font-mono text-xs leading-5 whitespace-pre text-fg",
          !expanded && "max-h-80",
        )}
      >
        <code>{masked ? maskIpsInText(text) : text}</code>
      </pre>
      <ExpandToggle
        expanded={expanded}
        overflowing={overflowing}
        onToggle={toggle}
        label={label}
        className="m-1"
      />
    </figure>
  )
}
