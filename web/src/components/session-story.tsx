import { CountryFlag } from "@/components/country-flag"
import { IPChip } from "@/components/ip-chip"
import type { Session } from "@/lib/api"
import { describeSession } from "@/lib/describe-session"
import { cn } from "@/lib/utils"

interface SessionStoryProps {
  session: Session
  masked?: boolean
  /** `inline`: one line that truncates (lists). `block`: wraps freely (headers). */
  layout?: "inline" | "block"
  /** Chip style for the address; lists use `ghost` to stay quiet. */
  ipVariant?: "chip" | "ghost"
  /** Fixed width for the address, so stories line up in lists. */
  ipClassName?: string
  className?: string
}

/**
 * "203.0.113.9 (Netherlands, Polder Cloud BV) tried 37 SSH passwords, then ran
 * 5 commands." The address is a chip, the origin is muted, the action reads first.
 */
export function SessionStory({
  session,
  masked,
  layout = "inline",
  ipVariant = "chip",
  ipClassName,
  className,
}: SessionStoryProps) {
  const { subject, origin, predicate } = describeSession(session)
  const inline = layout === "inline"

  return (
    <p
      className={cn(
        "min-w-0 text-fg",
        inline
          ? "flex items-center gap-2 overflow-hidden whitespace-nowrap"
          : "flex flex-wrap items-center gap-x-2 gap-y-1.5",
        className,
      )}
    >
      <IPChip
        ip={subject}
        masked={masked}
        variant={ipVariant}
        className={cn("relative z-10 shrink-0", ipClassName)}
      />
      {origin ? (
        <span className="inline-flex shrink-0 items-center gap-1.5 text-fg-muted">
          <CountryFlag code={session.country} className="relative z-10" />
          <span className={cn(inline && "hidden max-w-48 truncate xl:inline 2xl:max-w-80")}>
            {origin}
          </span>
        </span>
      ) : null}
      <span className={cn(inline && "truncate")}>{predicate}</span>
    </p>
  )
}
