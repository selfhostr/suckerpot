import { ExternalLink } from "lucide-react"
import { Link } from "react-router"
import type { StoryStage } from "@/lib/campaigns"
import { t as tr } from "@/i18n"
import { cn } from "@/lib/utils"

interface TechniqueChipsProps {
  stages: readonly StoryStage[]
  campaignId: number
  className?: string
}

/**
 * The ATT&CK techniques behind a campaign, once each, in story order. The stages themselves are
 * drawn once, by the stage trail above; this only adds what the trail cannot say. A chip opens the
 * campaign's sessions that used the technique; the small link reads about it on attack.mitre.org.
 */
export function TechniqueChips({ stages, campaignId, className }: TechniqueChipsProps) {
  const seen = new Set<string>()
  const techniques = stages
    .flatMap((s) => s.techniques)
    .filter((t) => (seen.has(t.id) ? false : (seen.add(t.id), true)))
  if (techniques.length === 0) return null
  return (
    <ul
      className={cn("flex flex-wrap gap-1.5", className)}
      aria-label={tr("campaign_techniques_label")}
    >
      {techniques.map((t) => (
        <li key={t.id} className="inline-flex max-w-full min-w-0 items-center">
          <Link
            to={`/attacks?campaign_id=${campaignId}&technique=${encodeURIComponent(t.id)}`}
            aria-label={tr("campaign_technique_show_sessions", { name: t.name, id: t.id })}
            className="inline-flex h-(--chip) min-w-0 items-center gap-1.5 rounded-l-sm border border-border-strong px-2 text-xs text-fg-muted transition-colors duration-150 hover:border-fg-subtle hover:text-fg"
          >
            <span className="shrink-0 font-mono text-fg">{t.id}</span>
            <span className="max-w-48 min-w-0 truncate">{t.name}</span>
          </Link>
          <a
            href={t.url}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex size-6 shrink-0 items-center justify-center rounded-r-sm border border-l-0 border-border-strong text-fg-subtle transition-colors duration-150 hover:text-fg"
            aria-label={tr("campaign_technique_read_about", { id: t.id, name: t.name })}
          >
            <ExternalLink aria-hidden className="size-3" />
          </a>
        </li>
      ))}
    </ul>
  )
}
