import { cn } from "@/lib/utils"

/* Layout helpers shared by the styleguide page and every feature section. */

export function Section({
  id,
  title,
  description,
  children,
}: {
  id: string
  title: string
  description: string
  children: React.ReactNode
}) {
  return (
    <section
      id={id}
      aria-labelledby={`${id}-title`}
      className="scroll-mt-20 border-t py-10 first:border-t-0 first:pt-2"
    >
      <div className="mb-6 max-w-2xl space-y-1">
        <h2 id={`${id}-title`} className="type-section-title text-fg">
          {title}
        </h2>
        <p className="text-sm text-fg-muted normal-nums">{description}</p>
      </div>
      {children}
    </section>
  )
}

export function Specimen({
  label,
  children,
  className,
}: {
  label: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={cn("rounded-lg border bg-surface shadow-sm", className)}>
      <div className="border-b px-4 py-2 font-mono text-2xs text-fg-subtle">{label}</div>
      <div className="flex flex-wrap items-center gap-3 p-4">{children}</div>
    </div>
  )
}
