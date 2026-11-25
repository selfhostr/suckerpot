import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowLeft, ArrowRight, Check, Minus } from "lucide-react"
import { useEffect, useRef } from "react"
import { Link, Navigate, useNavigate } from "react-router"
import { useAuth } from "@/app/auth"
import { useTour } from "@/app/tour"
import { PageHeader } from "@/components/page-header"
import { useStepReadiness } from "@/components/setup/readiness"
import {
  AlertsStep,
  DoneStep,
  NetworkStep,
  PortsStep,
  ReportingStep,
  SelfStep,
  SensorsStep,
  VpnStep,
  WelcomeStep,
} from "@/components/setup/steps"
import { SkeletonCard } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { useUrlParam } from "@/hooks/use-url-param"
import {
  AFTER_SETUP,
  firstOpenStep,
  stepIndex,
  WIZARD_STEPS,
  wizardApi,
  wizardKeys,
  type ProgressChange,
  type StepStatus,
  type WizardProgress,
} from "@/lib/setup-wizard"
import { networkApi, networkKeys } from "@/lib/network"
import { cn } from "@/lib/utils"

/** The M29 network step shows only when its status endpoint answers (a 404 hides it). */
function useNetworkAvailable(): boolean {
  const q = useQuery({
    queryKey: networkKeys.status,
    queryFn: networkApi.status,
    retry: false,
    staleTime: 5 * 60_000,
  })
  return q.isSuccess
}

function StepMark({
  id,
  index,
  current,
  progress,
}: {
  id: string
  index: number
  current: boolean
  progress: WizardProgress | undefined
}) {
  const status = progress?.steps[id]
  return (
    <span
      aria-hidden
      className={cn(
        "inline-flex size-5 shrink-0 items-center justify-center rounded-full border text-2xs tabular-nums",
        current && "border-fg bg-fg text-bg",
        !current && status === "done" && "border-status-ok text-status-ok",
        !current && status === "skipped" && "border-dashed text-fg-muted",
      )}
    >
      {status === "done" && !current ? (
        <Check className="size-3" strokeWidth={3} />
      ) : status === "skipped" && !current ? (
        <Minus className="size-3" strokeWidth={3} />
      ) : (
        index + 1
      )}
    </span>
  )
}

/** Two plain answers above the action bar: can this step be skipped, and what comes next. */
function StepGuide({ skip, next }: { skip: string | null; next: string }) {
  return (
    <dl className="grid max-w-4xl gap-x-8 gap-y-3 text-sm sm:grid-cols-2">
      {skip ? (
        <div className="space-y-0.5">
          <dt className="text-xs font-medium text-fg-subtle">Can I skip it?</dt>
          <dd className="text-pretty text-fg-muted">{skip}</dd>
        </div>
      ) : null}
      <div className="space-y-0.5">
        <dt className="text-xs font-medium text-fg-subtle">What happens next</dt>
        <dd className="text-pretty text-fg-muted">{next}</dd>
      </div>
    </dl>
  )
}

export function SetupPage() {
  const { canWrite } = useAuth()
  if (!canWrite) return <Navigate to="/" replace />
  return <Stepper />
}

function Stepper() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const tour = useTour()
  const [stepParam, setStepParam] = useUrlParam("step")
  const network = useNetworkAvailable()
  const steps = WIZARD_STEPS.filter((s) => s.id !== "network" || network)
  const progressQ = useQuery({ queryKey: wizardKeys.progress, queryFn: wizardApi.progress })
  const progress = progressQ.data
  const ready = useStepReadiness()

  const change = useMutation({
    mutationFn: (body: ProgressChange) => wizardApi.change(body),
    onSuccess: (data) => qc.setQueryData(wizardKeys.progress, data),
  })

  const index = stepParam ? stepIndex(stepParam, steps) : firstOpenStep(progress, steps)
  const step = steps[index]
  const last = index === steps.length - 1

  const heading = useRef<HTMLHeadingElement>(null)
  const first = useRef(true)
  useEffect(() => {
    // Move focus to the new step's title, except on arrival, so a screen reader announces it.
    if (first.current) {
      first.current = false
      return
    }
    heading.current?.focus({ preventScroll: true })
  }, [index])

  // On phones the step list scrolls sideways: keep the current step in view.
  useEffect(() => {
    document
      .querySelector<HTMLElement>('[aria-label="Setup steps"] [aria-current="step"]')
      // jsdom (vitest) has no scrollIntoView.
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      ?.scrollIntoView?.({ inline: "center", block: "nearest" })
  }, [index, progress])

  if (!progress || !step)
    return progressQ.isError ? (
      <PageHeader title="Set up SuckerPot" description="The setup is not available right now." />
    ) : (
      <>
        <PageHeader title="Set up SuckerPot" />
        <SkeletonCard />
      </>
    )

  const go = (to: number) =>
    setStepParam(steps[Math.max(0, Math.min(to, steps.length - 1))]?.id ?? null)
  const next = (status: StepStatus) => {
    change.mutate({ step: step.id, status })
    go(index + 1)
  }
  const leave = (body: ProgressChange) =>
    change.mutate(body, { onSuccess: () => void navigate("/") })

  const satisfied = ready[step.id] === true
  const body = (() => {
    switch (step.id) {
      case "welcome":
        return <WelcomeStep />
      case "sensors":
        return <SensorsStep />
      case "ports":
        return <PortsStep />
      case "vpn":
        return <VpnStep />
      case "self":
        return <SelfStep />
      case "reporting":
        return <ReportingStep />
      case "alerts":
        return <AlertsStep />
      case "network":
        return <NetworkStep />
      default:
        return <DoneStep />
    }
  })()

  return (
    <>
      <PageHeader
        help="setup"
        title="Set up SuckerPot"
        description="A few minutes, and every step can be skipped and reopened later from Settings."
        actions={
          <Button
            variant="ghost"
            size="sm"
            disabled={change.isPending}
            onClick={() => leave({ skip: true })}
          >
            Skip setup
          </Button>
        }
      />

      <div className="grid grid-cols-[minmax(0,1fr)] gap-6 lg:grid-cols-[13rem_minmax(0,1fr)] lg:gap-10">
        <nav aria-label="Setup steps" className="min-w-0">
          <ol className="-mx-4 flex gap-1 overflow-x-auto px-4 pb-1 lg:mx-0 lg:flex-col lg:overflow-visible lg:px-0">
            {steps.map((s, i) => {
              const current = i === index
              const status = progress.steps[s.id]
              return (
                <li key={s.id} className="relative shrink-0">
                  <button
                    type="button"
                    onClick={() => go(i)}
                    aria-current={current ? "step" : undefined}
                    className={cn(
                      "flex h-9 w-full items-center gap-2.5 rounded-md px-2.5 text-left text-sm font-medium whitespace-nowrap transition-colors duration-150 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none lg:h-8",
                      current
                        ? "bg-surface-hover text-fg"
                        : "text-fg-muted hover:bg-surface-hover/60 hover:text-fg",
                    )}
                  >
                    <StepMark id={s.id} index={i} current={current} progress={progress} />
                    {s.title}
                    {status && !current ? (
                      <span className="sr-only">
                        {status === "done" ? " (done)" : " (skipped)"}
                      </span>
                    ) : null}
                  </button>
                </li>
              )
            })}
          </ol>
        </nav>

        <section aria-labelledby="step-title" className="min-w-0 space-y-6">
          <header className="space-y-1.5">
            <p className="text-xs font-medium text-fg-muted tabular-nums">
              Step {index + 1} of {steps.length}
            </p>
            <h2
              id="step-title"
              ref={heading}
              tabIndex={-1}
              className="type-section-title text-pretty text-fg outline-none"
            >
              {step.sentence}
            </h2>
          </header>

          {body}

          <StepGuide skip={step.skip} next={steps[index + 1]?.teaser ?? AFTER_SETUP} />

          <div className="sticky bottom-0 z-10 -mx-4 flex items-center gap-2 border-t bg-bg/90 px-4 py-3 backdrop-blur-md sm:-mx-6 sm:px-6 lg:mx-0 lg:px-0">
            {index > 0 ? (
              <Button variant="outline" onClick={() => go(index - 1)}>
                <ArrowLeft aria-hidden />
                Back
              </Button>
            ) : null}
            {last ? (
              <>
                <Button variant="outline" className="ml-auto" onClick={tour.start}>
                  Take the tour
                </Button>
                <Button disabled={change.isPending} onClick={() => leave({ finish: true })}>
                  Go to Today
                  <ArrowRight aria-hidden />
                </Button>
              </>
            ) : (
              <>
                <Button variant="ghost" asChild className="ml-auto">
                  <Link to="/">Finish later</Link>
                </Button>
                {step.optional && !satisfied ? (
                  <Button variant="outline" onClick={() => next("skipped")}>
                    Skip for now
                    <ArrowRight aria-hidden />
                  </Button>
                ) : (
                  <Button onClick={() => next("done")}>
                    Next
                    <ArrowRight aria-hidden />
                  </Button>
                )}
              </>
            )}
          </div>
        </section>
      </div>
    </>
  )
}
