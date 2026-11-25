import { useSyncExternalStore } from "react"
import { t } from "@/i18n"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { countryName } from "@/lib/format"
import { cn } from "@/lib/utils"

// The url table is a separate chunk, fetched once on the first flag; until it lands the neutral
// placeholder shows, which has the same size, so nothing shifts.
type FlagLookup = (code: string) => string | null
let lookup: FlagLookup | null = null
const waiting = new Set<() => void>()
let loading = false

function loadFlags() {
  if (lookup || loading) return
  loading = true
  void import("./country-flag-urls").then((m) => {
    lookup = m.flagUrl
    waiting.forEach((notify) => notify())
    waiting.clear()
  })
}

function subscribeFlags(notify: () => void) {
  waiting.add(notify)
  loadFlags()
  return () => {
    waiting.delete(notify)
  }
}

function useFlagUrl(code: string | null | undefined): string | null | undefined {
  const ready = useSyncExternalStore(
    subscribeFlags,
    () => lookup,
    () => null,
  )
  if (!code) return null
  return ready ? ready(code) : undefined // undefined: table still loading
}

interface CountryFlagProps {
  /** ISO 3166-1 alpha-2 code. */
  code: string | null | undefined
  /** Also print the country name next to the flag. */
  showName?: boolean
  /** Just the flag, no tooltip and not focusable: for use inside a link that names the country. */
  decorative?: boolean
  className?: string
}

export function CountryFlag({
  code,
  showName = false,
  decorative = false,
  className,
}: CountryFlagProps) {
  const name = countryName(code)
  const url = useFlagUrl(code)
  const loading = url === undefined
  const label = name ?? (code ? code.toUpperCase() : t("sessions_unknown_country"))

  const flag = loading ? (
    <span
      aria-hidden
      className="inline-block h-3 w-[18px] shrink-0 rounded-[2px] bg-surface-hover"
    />
  ) : url ? (
    <img
      src={url}
      alt=""
      width={18}
      height={12}
      loading="lazy"
      className="h-3 w-[18px] shrink-0 rounded-[2px] object-cover ring-1 ring-fg/10"
    />
  ) : (
    <span
      aria-hidden
      className="inline-flex h-3 w-[18px] shrink-0 items-center justify-center rounded-[2px] bg-surface-hover text-[8px] leading-none font-semibold text-fg-subtle ring-1 ring-border-strong"
    >
      ?
    </span>
  )

  if (decorative) {
    return (
      <span aria-hidden className={cn("inline-flex items-center", className)}>
        {flag}
      </span>
    )
  }

  if (showName) {
    return (
      <span className={cn("inline-flex items-center gap-1.5 text-fg-muted", className)}>
        {flag}
        <span className="truncate">{label}</span>
      </span>
    )
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          role="img"
          aria-label={label}
          tabIndex={0}
          className={cn("inline-flex items-center rounded-[2px]", className)}
        >
          {flag}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top">{label}</TooltipContent>
    </Tooltip>
  )
}
