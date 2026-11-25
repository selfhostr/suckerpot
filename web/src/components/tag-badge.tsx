import { Link } from "react-router"
import { t } from "@/i18n"
import { tagSeverity } from "@/lib/severity"
import { cn } from "@/lib/utils"

interface TagBadgeProps {
  tag: string
  /** Defaults to the Attacks list filtered by this tag. Pass null for a static badge. */
  href?: string | null
  className?: string
}

/**
 * A rules-engine tag. Neutral by default; tags that mean a payload or exploit
 * carry a red diamond, tags that mean harm short of that (ransom note, rogue
 * master, phone fraud, persistence, a BlueKeep probe, a guessed weak password) an orange triangle. Shape + colour + an
 * sr-only word, so the meaning never rests on colour alone.
 */
export function TagBadge({ tag, href, className }: TagBadgeProps) {
  const level = tagSeverity(tag)
  const severe = level === "severe"
  const to = href === undefined ? `/attacks?tag=${encodeURIComponent(tag)}` : href
  const classes = cn(
    "relative inline-flex h-(--chip) shrink-0 items-center gap-1.5 rounded-sm border px-2 font-mono text-2xs font-medium",
    severe
      ? "border-sev-severe/40 text-fg"
      : level === "warning"
        ? "border-sev-warning/40 text-fg"
        : "border-border-strong text-fg-muted",
    to && "transition-colors duration-150 hover:border-fg-subtle hover:text-fg",
    className,
  )
  const content = (
    <>
      {severe ? (
        <span aria-hidden className="size-1.5 rotate-45 rounded-[1px] bg-sev-severe" />
      ) : level === "warning" ? (
        <svg aria-hidden viewBox="0 0 8 8" className="size-2 fill-sev-warning">
          <path d="M4 .5 7.6 7.2H.4Z" />
        </svg>
      ) : null}
      {tag}
      {level ? <span className="sr-only"> {t("tag_level", { level })}</span> : null}
    </>
  )
  return to ? (
    <Link to={to} className={classes}>
      {content}
    </Link>
  ) : (
    <span className={classes}>{content}</span>
  )
}
