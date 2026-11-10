const SECTIONS = [
  { id: "reporting-message", label: "Message" },
  { id: "reporting-never", label: "Never in a report" },
  { id: "reporting-sending", label: "Sending" },
  { id: "reporting-replies", label: "Replies" },
] as const

/** Jump links to the sections of Settings, Reporting. Scrolls on small screens, sticks on wide ones. */
export function ReportingNav() {
  return (
    // The sticky band keeps its solid fill; only the links inside fade at a cut edge.
    <div className="sticky top-0 z-10 -mx-1 bg-bg px-1 py-2">
      <nav aria-label="Reporting sections" className="scroll-fade-x flex gap-1 overflow-x-auto">
        {SECTIONS.map((s) => (
          <a
            key={s.id}
            href={`#${s.id}`}
            onClick={(e) => {
              e.preventDefault()
              document.getElementById(s.id)?.scrollIntoView({ behavior: "smooth", block: "start" })
            }}
            className="flex-none rounded-md px-3 py-1.5 text-sm text-fg-muted transition-colors hover:bg-surface-hover hover:text-fg focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            {s.label}
          </a>
        ))}
      </nav>
    </div>
  )
}
