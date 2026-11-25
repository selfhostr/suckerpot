/* eslint-disable react-refresh/only-export-components -- the provider and its hook belong together. */
import {
  Suspense,
  createContext,
  lazy,
  use,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react"
import { useWizardProgress } from "@/hooks/use-wizard-progress"
import { hasSeenTour, markTourSeen } from "@/lib/tour"
import { useAuth } from "./auth"

// Fetched the first time the tour opens, with its illustrations.
const TourDialog = lazy(() =>
  import("@/components/tour/tour-dialog").then((m) => ({ default: m.TourDialog })),
)

interface TourState {
  open: boolean
  /** Opens the tour from its first step. */
  start: () => void
}

const TourContext = createContext<TourState>({ open: false, start: () => undefined })

export function useTour(): TourState {
  return use(TourContext)
}

/**
 * Owns the tour dialog. It opens by itself the first time an account is seen in this browser
 * (the flag is per username), and again whenever someone presses "Take the tour".
 */
export function TourProvider({ children }: { children: React.ReactNode }) {
  const { user } = useAuth()
  const [open, setOpen] = useState(false)
  const [everOpened, setEverOpened] = useState(false)
  if (open && !everOpened) setEverOpened(true)
  const username = user && !user.must_change_password ? user.username : null
  // An administrator with an unfinished setup is offered the tour at the end of the setup instead.
  const { canWrite } = useAuth()
  const wizard = useWizardProgress()
  const holdForSetup = canWrite && (wizard.isPending || wizard.data?.show === true)

  useEffect(() => {
    if (!username || holdForSetup || hasSeenTour(username)) return
    markTourSeen(username)
    // localStorage is the external system here: its answer is only known after mounting.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setOpen(true)
  }, [username, holdForSetup])

  const start = useCallback(() => setOpen(true), [])
  const value = useMemo(() => ({ open, start }), [open, start])
  return (
    <TourContext value={value}>
      {children}
      {everOpened ? (
        <Suspense fallback={null}>
          <TourDialog open={open} onOpenChange={setOpen} />
        </Suspense>
      ) : null}
    </TourContext>
  )
}
