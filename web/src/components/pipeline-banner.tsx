import { Info, OctagonAlert, X } from "lucide-react"
import { useEffect, useState } from "react"
import { Link } from "react-router"
import { Button } from "@/components/ui/button"
import { usePipeline } from "@/hooks/use-pipeline"
import {
  dismissParked,
  parkedDismissed,
  parkedSentence,
  stalledSentence,
  type PipelineStatus,
} from "@/lib/pipeline"
import { cn } from "@/lib/utils"

/** Opens smoothly (a grid row animating to full height) so the page below never jumps. */
function Reveal({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  useEffect(() => {
    const id = requestAnimationFrame(() => setOpen(true))
    return () => cancelAnimationFrame(id)
  }, [])
  return (
    <div
      className={cn(
        "grid transition-[grid-template-rows,opacity] duration-300 ease-out motion-reduce:transition-none",
        open ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0",
      )}
    >
      <div className="min-h-0 overflow-hidden">
        <div className="pb-6">{children}</div>
      </div>
    </div>
  )
}

function Stalled({ p }: { p: PipelineStatus }) {
  return (
    <div
      data-testid="pipeline-stalled"
      className="tint-severe flex items-start gap-3 rounded-lg border border-sev-severe/40 px-4 py-3"
    >
      <span role="alert" className="sr-only">
        Events are not being stored.
      </span>
      <OctagonAlert
        aria-hidden
        className="mt-0.5 size-5 shrink-0 text-sev-severe"
        strokeWidth={2}
      />
      <div aria-live="off" className="min-w-0 space-y-1">
        <p className="text-sm font-medium text-pretty text-fg">
          {stalledSentence(p.stalled_for_seconds)}
        </p>
        {p.last_error ? (
          <p className="text-xs break-words text-fg-muted">
            Last error: <span className="font-mono text-fg">{p.last_error}</span>
          </p>
        ) : null}
        <p className="text-xs text-fg-muted">
          Check the ingest service:{" "}
          <code className="font-mono whitespace-nowrap text-fg">docker compose ps ingest</code> and{" "}
          <code className="font-mono whitespace-nowrap text-fg">docker compose logs ingest</code>.
        </p>
      </div>
    </div>
  )
}

function Parked({ count, onDismiss }: { count: number; onDismiss: () => void }) {
  return (
    <div
      role="status"
      className="flex items-center gap-3 rounded-lg border border-dashed px-4 py-2.5 text-sm text-fg-muted"
    >
      <Info aria-hidden className="size-4 shrink-0" />
      <p className="min-w-0 flex-1 text-pretty">
        {parkedSentence(count)}{" "}
        <Link to="/settings" className="font-medium text-fg underline underline-offset-2">
          See Settings
        </Link>
      </p>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        aria-label="Dismiss this notice"
        className="size-8 shrink-0"
        onClick={onDismiss}
      >
        <X aria-hidden className="size-4" />
      </Button>
    </div>
  )
}

/** App-wide: a severe alert when events are not being stored, a quiet notice for set-aside events. */
export function PipelineBanner() {
  const { pipeline } = usePipeline()
  const [dismissed, setDismissed] = useState<number | null>(null)
  const count = pipeline.parked_events

  if (pipeline.status === "stalled")
    return (
      <Reveal>
        <Stalled p={pipeline} />
      </Reveal>
    )
  if (pipeline.status === "ok" && count > 0 && dismissed !== count && !parkedDismissed(count))
    return (
      <Reveal>
        <Parked
          count={count}
          onDismiss={() => {
            dismissParked(count)
            setDismissed(count)
          }}
        />
      </Reveal>
    )
  return null
}
