import { ArrowRight, ChevronDown } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { Link } from "react-router"
import { Collapse } from "@/components/collapse"
import { CountryFlag } from "@/components/country-flag"
import { IPChip } from "@/components/ip-chip"
import { SensorBadge } from "@/components/sensor-badge"
import { SeverityBadge } from "@/components/severity-badge"
import { TagBadge } from "@/components/tag-badge"
import { TermText } from "@/components/term"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { formatRelative } from "@/lib/format"
import { motionFrozen } from "@/lib/motion"
import { STAGE_META, stepMeta, storySeverity, type StoryItem } from "@/lib/story"
import { cn } from "@/lib/utils"

/** True once the element has been on screen; stays true (the path plays once). */
function useSeen(skip: boolean) {
  const ref = useRef<HTMLOListElement>(null)
  const [seen, setSeen] = useState(false)
  useEffect(() => {
    const el = ref.current
    if (skip || !el) return
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setSeen(true)
          io.disconnect()
        }
      },
      { threshold: 0.3 },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [skip])
  return [ref, skip || seen] as const
}

/** The path of one attacker, one step per line, drawn in one after the other. */
function StepPath({ steps }: { steps: StoryItem["steps"] }) {
  const reduced = useReducedMotion()
  const [ref, shown] = useSeen(
    reduced || motionFrozen() || typeof IntersectionObserver === "undefined",
  )
  return (
    <ol ref={ref} aria-label="What it did, step by step" className="relative space-y-2">
      {steps.map((s, i) => {
        const meta = stepMeta(s.kind)
        const Icon = meta.icon
        return (
          <li
            key={`${s.ts}-${i}`}
            className={cn(
              "relative flex items-start gap-3 transition-[opacity,transform] duration-300 ease-out",
              shown ? "translate-y-0 opacity-100" : "translate-y-1 opacity-0",
            )}
            style={{ transitionDelay: shown ? `${i * 140}ms` : "0ms" }}
          >
            {i < steps.length - 1 ? (
              <span
                aria-hidden
                className="absolute top-8 left-[15px] h-[calc(100%-1.5rem)] w-px bg-border-strong"
              />
            ) : null}
            <span
              aria-hidden
              className={cn(
                "relative inline-flex size-8 shrink-0 items-center justify-center rounded-full border bg-surface-raised",
                meta.severe
                  ? "border-sev-severe text-sev-severe"
                  : "border-border-strong text-fg-muted",
              )}
            >
              <Icon className="size-4" strokeWidth={1.85} />
            </span>
            <span className="min-w-0 pt-1 text-sm text-fg">
              {s.plain}
              {meta.severe ? <span className="sr-only"> (serious)</span> : null}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

/** Everything an analyst needs, one click away. Attacker-controlled text is rendered as text. */
function Technical({ story }: { story: StoryItem }) {
  return (
    <div className="mt-3 space-y-4 rounded-md border bg-surface-hover/40 p-3 sm:p-4">
      <ul className="space-y-1 font-mono text-xs break-words text-fg-muted">
        {story.steps.map((s, i) => (
          <li key={`${s.ts}-${i}`}>
            <span className="text-fg-subtle">{s.kind}</span> {s.technical}
          </li>
        ))}
      </ul>
      {story.tags.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {story.tags.map((t) => (
            <TagBadge key={t} tag={t} />
          ))}
        </div>
      ) : null}
      {story.techniques.length > 0 ? (
        <p className="text-xs text-fg-muted">
          ATT&amp;CK:{" "}
          {story.techniques.map((t, i) => (
            <span key={t.id}>
              {i > 0 ? ", " : ""}
              <Link
                to="/techniques"
                title={t.name}
                className="font-mono text-fg underline underline-offset-4 hover:text-fg-muted"
              >
                {t.id}
              </Link>
            </span>
          ))}
        </p>
      ) : null}
      <p className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-fg-muted">
        {story.asn ? (
          <span className="tabular-nums">
            AS{story.asn} {story.org ?? ""}
          </span>
        ) : null}
        {story.campaign ? (
          <Link
            to={`/campaigns/${story.campaign.id}`}
            className="text-fg underline underline-offset-4 hover:text-fg-muted"
          >
            Campaign: {story.campaign.name}
          </Link>
        ) : null}
      </p>
    </div>
  )
}

/**
 * One notable visit told as a short story: a plain title and summary, the path it took, who it
 * was, and a "Technical details" disclosure for the expert.
 */
export function StoryCard({ story, index = 0 }: { story: StoryItem; index?: number }) {
  const [open, setOpen] = useState(false)
  const detailId = `story-${story.session_id}-tech`
  const stage = STAGE_META[story.stage] as (typeof STAGE_META)[keyof typeof STAGE_META] | undefined
  return (
    <Card
      data-story={story.session_id}
      style={{ "--motion-i": index } as React.CSSProperties}
      className="motion-stagger h-full animate-card-in gap-0 rounded-lg py-0 shadow-sm"
    >
      <div className="flex flex-1 flex-col px-4 pt-4 pb-4 sm:px-5 sm:pt-5">
        <p className="flex items-center gap-x-2 text-xs text-fg-muted">
          <SensorBadge sensor={story.sensor} className="shrink-0" />
          <SeverityBadge severity={storySeverity(story.severity)} className="shrink-0" />
          {stage ? <span className="min-w-0 truncate">{stage.label}</span> : null}
          <time dateTime={story.started_at} className="ml-auto shrink-0">
            {formatRelative(story.started_at)}
          </time>
        </p>
        <h3 className="mt-2 text-base font-medium text-pretty text-fg">
          <TermText text={story.title} terms={["botnet", "brute-force", "exploit", "malware"]} />
        </h3>
        <p className="mt-1 text-sm text-pretty text-fg-muted">{story.summary}</p>
        <div className="mt-4">
          <StepPath steps={story.steps} />
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <CountryFlag code={story.country} showName />
          <IPChip ip={story.src_ip} />
        </div>
        {/* Both ways in share one row: the session for everyone, the details for the expert. */}
        <div className="mt-auto flex flex-wrap items-center justify-between gap-x-4 gap-y-2 pt-4">
          <Button asChild variant="outline" size="sm">
            <Link to={story.href}>
              Open the full session
              <ArrowRight aria-hidden />
            </Link>
          </Button>
          <button
            type="button"
            aria-expanded={open}
            aria-controls={detailId}
            onClick={() => setOpen((v) => !v)}
            className="inline-flex min-h-9 items-center gap-1.5 rounded-sm text-sm text-fg-muted hover:text-fg"
          >
            <ChevronDown
              aria-hidden
              className={cn("size-4 transition-transform duration-150", open && "rotate-180")}
            />
            Technical details
          </button>
        </div>
        <Collapse open={open} id={detailId}>
          <Technical story={story} />
        </Collapse>
      </div>
    </Card>
  )
}

export function StoryCardSkeleton() {
  return (
    <div aria-hidden className="h-full space-y-4 rounded-lg border bg-surface p-5">
      <Skeleton className="h-3 w-28" />
      <Skeleton className="h-5 w-11/12" />
      <Skeleton className="h-4 w-3/4" />
      <div className="space-y-3">
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-8 w-2/3" />
        ))}
      </div>
    </div>
  )
}
