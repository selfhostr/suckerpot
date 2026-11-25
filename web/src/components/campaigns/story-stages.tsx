import { ExternalLink } from "lucide-react"
import { Link } from "react-router"
import { STAGE_ICON } from "@/components/campaigns/stage-icons"
import { STAGE_META, type StoryStage } from "@/lib/campaigns"
import { cn } from "@/lib/utils"

interface StoryStagesProps {
  stages: readonly StoryStage[]
  campaignId: number
  className?: string
}

/**
 * The attack as steps, in the order it unfolds. Each step answers one plain question
 * ("How did they get in?"), says it in a sentence, and lists the ATT&CK techniques behind it.
 * Steps slide in one after the other (not at all with reduced motion).
 */
export function StoryStages({ stages, campaignId, className }: StoryStagesProps) {
  return (
    <ol className={cn("relative space-y-5", className)} aria-label="Stages of the attack">
      {stages.map((s, i) => {
        const Icon = STAGE_ICON[s.stage]
        const last = i === stages.length - 1
        return (
          <li
            key={s.stage}
            style={{ animationDelay: `${i * 70}ms` }}
            className="relative grid animate-slide-in grid-cols-[2rem_minmax(0,1fr)] gap-x-3"
          >
            {!last ? (
              <span
                aria-hidden
                className="absolute top-8 bottom-[-1.25rem] left-4 w-px -translate-x-1/2 bg-border-strong"
              />
            ) : null}
            <span
              aria-hidden
              className="relative z-10 flex size-8 items-center justify-center rounded-full border bg-surface-raised text-fg-muted shadow-sm"
            >
              <Icon className="size-4" strokeWidth={1.75} />
            </span>
            <div className="min-w-0 space-y-1.5 pt-0.5">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <h4 className="type-subtitle text-fg">
                  <span className="mr-1.5 text-xs text-fg-subtle tabular-nums">{i + 1}.</span>
                  {s.label}
                </h4>
                <span className="text-xs text-fg-subtle">{STAGE_META[s.stage].question}</span>
              </div>
              <p className="text-sm text-pretty text-fg">{s.summary}</p>
              <ul className="flex flex-wrap gap-1.5 pt-0.5" aria-label={`Techniques: ${s.label}`}>
                {s.techniques.map((t) => (
                  <li key={t.id} className="inline-flex max-w-full min-w-0 items-center">
                    <Link
                      to={`/attacks?campaign_id=${campaignId}&technique=${encodeURIComponent(t.id)}`}
                      aria-label={`${t.name}, ${t.id}. Show the sessions of this campaign that used it.`}
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
                      aria-label={`Read about ${t.id} ${t.name} on attack.mitre.org (opens in a new tab)`}
                    >
                      <ExternalLink aria-hidden className="size-3" />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          </li>
        )
      })}
    </ol>
  )
}
