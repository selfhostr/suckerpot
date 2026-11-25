import { cn } from "@/lib/utils"

/**
 * The SuckerPot mark, the same drawing the public site serves (favicon.svg).
 * The dark tile and the light pupil are fixed so the mark reads the same in
 * both themes. The violet drop is the only brand colour in the app, and it is
 * confined to this mark.
 */
export function Logo({ className, withName = true }: { className?: string; withName?: boolean }) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <svg viewBox="0 0 64 64" aria-hidden className="size-6 shrink-0">
        <rect width="64" height="64" rx="15" fill="#111419" />
        <path d="M32 8c10 12 17 21 17 29a17 17 0 0 1-34 0c0-8 7-17 17-29z" fill="#a78bfa" />
        <ellipse cx="32" cy="37" rx="10.5" ry="7" fill="#111419" />
        <circle cx="32" cy="37" r="3.5" fill="#eceef1" />
      </svg>
      {withName ? (
        <span className="text-base font-semibold tracking-tight text-fg">SuckerPot</span>
      ) : (
        <span className="sr-only">SuckerPot</span>
      )}
    </span>
  )
}
