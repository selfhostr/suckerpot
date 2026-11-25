import { useState } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { FirewallNote, SetupItems } from "@/components/setup-checklist"
import { SkeletonText } from "@/components/skeletons"
import { useSetupStatus } from "@/hooks/use-setup-status"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { describeSetup } from "@/lib/setup"
import { TOUR_STEPS } from "@/lib/tour"
import { cn } from "@/lib/utils"
import { TourIllustration } from "./tour-illustrations"

const LAST = TOUR_STEPS.length - 1

/** The last step: what is set up and what is left. Administrators only. */
function LastStepChecklist({ onNavigate }: { onNavigate: () => void }) {
  const { canWrite } = useAuth()
  const q = useSetupStatus()
  if (!canWrite)
    return (
      <p className="text-sm text-fg-muted">
        An administrator can see what is left to set up in Settings.
      </p>
    )
  return (
    <section aria-label="What is left to set up" className="space-y-2">
      <p className="text-sm font-medium text-fg">
        {q.data
          ? describeSetup(q.data)
          : q.isError
            ? "The setup status is not available right now."
            : "Checking the setup…"}
      </p>
      {q.data ? (
        <SetupItems
          items={q.data}
          onNavigate={onNavigate}
          className="max-h-none overflow-y-auto rounded-lg border sm:max-h-72 [&>li]:px-3"
        />
      ) : q.isPending ? (
        <SkeletonText lines={3} />
      ) : null}
      <Link
        to="/settings"
        onClick={onNavigate}
        className="inline-block rounded-sm text-sm font-medium text-fg underline underline-offset-4 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
      >
        See all in Settings
      </Link>
      <p className="text-xs text-fg-muted">
        <FirewallNote />
      </p>
    </section>
  )
}

/** The welcome tour: seven steps, each a sentence, a few lines and a small picture. */
export function TourDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        showCloseButton={false}
        className="max-h-[calc(100dvh-2rem)] grid-rows-[minmax(0,1fr)] gap-0 overflow-hidden bg-popover p-0 sm:top-[12vh] sm:max-w-xl sm:translate-y-0"
      >
        {/* Remounted on every open, so the tour always starts at step one. */}
        <TourSteps onClose={() => onOpenChange(false)} />
      </DialogContent>
    </Dialog>
  )
}

function TourSteps({ onClose }: { onClose: () => void }) {
  const [index, setIndex] = useState(0)
  const step = TOUR_STEPS[index]
  if (!step) return null
  const last = index === LAST
  return (
    <div
      className="flex min-h-0 min-w-0 flex-col"
      onKeyDown={(e) => {
        if (e.key === "ArrowRight" && !last) setIndex(index + 1)
        if (e.key === "ArrowLeft" && index > 0) setIndex(index - 1)
      }}
    >
      <div className="grid min-h-0 min-w-0 gap-4 overflow-y-auto p-5 sm:p-6">
        <DialogHeader className="gap-1.5 text-left" aria-live="polite">
          <p className="text-xs font-medium text-fg-muted">
            Step {index + 1} of {TOUR_STEPS.length}
          </p>
          <DialogTitle className="text-pretty">{step.title}</DialogTitle>
          <DialogDescription className="text-sm text-pretty">{step.body}</DialogDescription>
        </DialogHeader>

        {/* The last step leaves the room to the checklist on a phone. */}
        <TourIllustration step={step.id} className={last ? "hidden" : undefined} />

        {last ? <LastStepChecklist onNavigate={onClose} /> : null}
      </div>

      <div className="flex flex-col gap-3 border-t px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <ol aria-label="Tour progress" className="flex items-center justify-center gap-1.5">
          {TOUR_STEPS.map((s, i) => (
            <li
              key={s.id}
              aria-current={i === index ? "step" : undefined}
              className={cn(
                "h-1.5 rounded-full transition-all duration-200",
                i === index ? "w-5 bg-fg" : "w-1.5 bg-border-strong",
              )}
            >
              <span className="sr-only">
                Step {i + 1}
                {i === index ? " (current)" : ""}
              </span>
            </li>
          ))}
        </ol>
        <div className="flex items-center justify-end gap-2">
          {!last ? (
            <Button variant="ghost" onClick={onClose} className="mr-auto sm:mr-0">
              Skip tour
            </Button>
          ) : null}
          {index > 0 ? (
            <Button variant="outline" onClick={() => setIndex(index - 1)}>
              Back
            </Button>
          ) : null}
          {last ? (
            <Button onClick={onClose}>Done</Button>
          ) : (
            <Button onClick={() => setIndex(index + 1)} autoFocus>
              Next
            </Button>
          )}
        </div>
      </div>
    </div>
  )
}
