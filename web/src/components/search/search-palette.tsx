import { Search } from "lucide-react"
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
import { searchPlaceholder } from "./search-palette-constants"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"

interface PaletteValue {
  open: boolean
  setOpen: (open: boolean) => void
}

const SearchPaletteDialog = lazy(() => import("./search-palette-dialog"))

const PaletteContext = createContext<PaletteValue>({ open: false, setOpen: () => undefined })

// eslint-disable-next-line react-refresh/only-export-components
export function useSearchPalette(): PaletteValue {
  return use(PaletteContext)
}

/** True on Apple platforms, where the shortcut is Cmd+K. */
// eslint-disable-next-line react-refresh/only-export-components
export function isApplePlatform(): boolean {
  return typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent)
}

/** Ctrl+K (Cmd+K on a Mac) opens the palette from anywhere; Escape closes it. */
function useShortcut(toggle: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "k") {
        e.preventDefault()
        toggle()
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [toggle])
}

export function SearchPaletteProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  // The dialog (cmdk, search results) is fetched on first open and kept mounted afterwards.
  const [everOpened, setEverOpened] = useState(false)
  if (open && !everOpened) setEverOpened(true)
  const toggle = useCallback(() => setOpen((o) => !o), [])
  useShortcut(toggle)
  const value = useMemo(() => ({ open, setOpen }), [open])
  return (
    <PaletteContext value={value}>
      {children}
      {everOpened ? (
        <Suspense fallback={null}>
          <SearchPaletteDialog open={open} onOpenChange={setOpen} />
        </Suspense>
      ) : null}
    </PaletteContext>
  )
}

/** The search box in the header: looks like an input, opens the palette. */
export function SearchTrigger({
  className,
  compact = false,
}: {
  className?: string
  /** Icon only (phones). */
  compact?: boolean
}) {
  const { setOpen } = useSearchPalette()
  const shortcut = isApplePlatform() ? "⌘K" : "Ctrl K"
  if (compact) {
    return (
      <button
        type="button"
        aria-label={t("common_search")}
        onClick={() => setOpen(true)}
        className={cn(
          "inline-flex size-10 items-center justify-center rounded-md text-fg-muted hover:bg-surface-hover hover:text-fg",
          className,
        )}
      >
        <Search aria-hidden className="size-5" />
      </button>
    )
  }
  return (
    <button
      type="button"
      onClick={() => setOpen(true)}
      aria-label={t("common_search")}
      aria-keyshortcuts="Control+K Meta+K"
      className={cn(
        "flex h-9 w-full items-center gap-2.5 rounded-md border bg-surface px-3 text-left text-sm text-fg-muted shadow-xs transition-colors duration-150 hover:border-border-strong hover:bg-surface-hover/60",
        className,
      )}
    >
      <Search aria-hidden className="size-4 shrink-0 text-fg-subtle" />
      <span className="min-w-0 flex-1 truncate">{searchPlaceholder()}</span>
      <kbd className="shrink-0 rounded-xs border px-1.5 font-sans text-2xs text-fg-subtle">
        {shortcut}
      </kbd>
    </button>
  )
}
