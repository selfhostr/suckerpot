import { RelativeTime } from "@/components/relative-time"
import { SeverityBadge } from "@/components/severity-badge"
import { TagBadge } from "@/components/tag-badge"
import { evidenceLine, type GuidanceItem } from "@/lib/defend"

function Checklist({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="space-y-1.5">
      <h5 className="type-eyebrow text-fg-muted">{title}</h5>
      <ul className="list-disc space-y-1 pl-4 text-sm text-fg marker:text-fg-subtle">
        {items.map((item) => (
          <li key={item} className="pl-1 text-pretty">
            {item}
          </li>
        ))}
      </ul>
    </div>
  )
}

/** One behaviour the decoys saw, what it means for your company, and what to check and change. */
export function GuidanceCard({ item }: { item: GuidanceItem }) {
  return (
    <article className="flex flex-col gap-4 rounded-lg border bg-surface p-4 shadow-sm sm:p-5">
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h4 className="type-card-title text-fg">{item.title}</h4>
          <SeverityBadge severity={item.severity} />
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg-muted">
          <TagBadge tag={item.tag} />
          <span>{evidenceLine(item.seen.sessions, item.seen.sources)}</span>
          {item.seen.last_seen ? (
            <span>
              last <RelativeTime iso={item.seen.last_seen} className="text-xs" />
            </span>
          ) : null}
        </div>
      </header>
      <p className="text-sm text-pretty text-fg-muted">{item.what}</p>
      <Checklist title="Look for this in your logs" items={item.look} />
      <Checklist title="Fix" items={item.fix} />
    </article>
  )
}
