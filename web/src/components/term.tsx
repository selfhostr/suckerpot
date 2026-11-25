import { Fragment, useEffect, useRef, useState } from "react"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { GLOSSARY, splitTerms, type TermId } from "@/lib/glossary"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"

interface TermProps {
  id: TermId
  /** What to show in the text; defaults to the glossary's own word. */
  children?: React.ReactNode
  className?: string
}

/**
 * A security term with its plain-English definition. A dotted underline marks it; the
 * definition opens on hover, on a tap, and on Enter or Space (it is a real button), and closes
 * on Escape or when the pointer leaves. Do not nest it inside another button or link.
 */
export function Term({ id, children, className }: TermProps) {
  const entry = GLOSSARY[id]
  const [open, setOpen] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const lastPointer = useRef("")
  useEffect(() => () => clearTimeout(timer.current), [])

  // Hovering with a mouse opens the definition; a short grace period lets the pointer travel
  // from the word to the definition. Touch and keyboard use the button itself.
  // A click that follows a mouse hover keeps the definition open instead of toggling it shut.
  const press = (e: React.PointerEvent) => {
    lastPointer.current = e.pointerType
  }
  const click = (e: React.MouseEvent) => {
    if (open && lastPointer.current === "mouse") e.preventDefault()
    lastPointer.current = ""
  }
  const enter = (e: React.PointerEvent) => {
    if (e.pointerType !== "mouse") return
    clearTimeout(timer.current)
    setOpen(true)
  }
  const leave = (e: React.PointerEvent) => {
    if (e.pointerType !== "mouse") return
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setOpen(false), 120)
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          data-term={id}
          onPointerEnter={enter}
          onPointerLeave={leave}
          onPointerDown={press}
          onClick={click}
          className={cn(
            "inline cursor-help rounded-xs border-0 bg-transparent p-0 text-inherit [font:inherit]",
            "underline decoration-fg-subtle decoration-dotted underline-offset-4",
            "hover:decoration-fg-muted",
            className,
          )}
        >
          {children ?? entry.term}
          <span className="sr-only">{t("ui_term_definition_sr")}</span>
        </button>
      </PopoverTrigger>
      <PopoverContent
        side="top"
        className="w-72 max-w-[calc(100vw-2rem)] p-3 text-sm"
        onPointerEnter={enter}
        onPointerLeave={leave}
        onOpenAutoFocus={(e) => e.preventDefault()}
      >
        <p className="mb-1 text-xs font-medium text-fg-muted">{entry.term}</p>
        <p className="text-pretty text-fg">{entry.short}</p>
      </PopoverContent>
    </Popover>
  )
}

/**
 * A sentence written elsewhere (the API writes the Today sentences) with its first mention of
 * each glossary word turned into a `Term`. `terms` limits which words may be explained.
 */
export function TermText({ text, terms }: { text: string; terms?: readonly TermId[] }) {
  return (
    <>
      {splitTerms(text, terms).map((part, i) =>
        typeof part === "string" ? (
          <Fragment key={i}>{part}</Fragment>
        ) : (
          <Term key={i} id={part.id}>
            {part.text}
          </Term>
        ),
      )}
    </>
  )
}
