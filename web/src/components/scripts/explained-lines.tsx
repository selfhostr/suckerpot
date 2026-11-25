import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { t } from "@/i18n"
import { SeverityBadge } from "@/components/severity-badge"
import { maskIpsInText } from "@/lib/format"
import type { ExplainedLine } from "@/lib/scripts"
import { cn } from "@/lib/utils"

/**
 * The script, one command per row, each with what it does in plain words. Commands are text
 * only (never links); a technique opens the scripts that share it.
 *
 * Layout: a line-number gutter, then the command on a quiet code band (long lines wrap inside
 * the band, so a wrapped line never reads as the next command), then the explanation in prose
 * and one meta row: severity first (warning and severe only; "info" on every line is noise),
 * then the technique. Rows fade in one after another, softly.
 */
export function ExplainedLines({ lines }: { lines: readonly ExplainedLine[] }) {
  const { masked } = useIpMask()
  return (
    <ol aria-label={t("scripts_lines_label")} className="divide-y">
      {lines.map((l, i) => {
        const command = l.raw ?? l.text
        const flagged = l.risk === "warning" || l.risk === "severe" || l.risk === "notice"
        return (
          <li
            key={l.n}
            className="grid animate-fade-in grid-cols-[1.5rem_minmax(0,1fr)] gap-x-2.5 py-4 first:pt-0 last:pb-0 sm:grid-cols-[2rem_minmax(0,1fr)] sm:gap-x-3"
            style={{ animationDelay: `${Math.min(i, 12) * 40}ms` }}
          >
            <span className="py-1.5 text-right font-mono text-xs/5 text-fg-subtle tabular-nums select-none">
              {l.n}
            </span>
            <div className="min-w-0 space-y-2">
              <code className="block rounded-md bg-surface-hover px-2.5 py-1.5 font-mono text-xs/5 [overflow-wrap:anywhere] whitespace-pre-wrap text-fg">
                {masked ? maskIpsInText(command) : command}
              </code>
              <p
                className={cn(
                  "max-w-3xl text-sm text-pretty normal-nums",
                  l.risk ? "text-fg-muted" : "text-fg-subtle italic",
                )}
              >
                {l.explanation}
              </p>
              {flagged || l.technique ? (
                <div className="flex flex-wrap items-center gap-2">
                  {flagged && l.risk ? <SeverityBadge severity={l.risk} /> : null}
                  {l.technique ? (
                    <Link
                      to={`/scripts?technique=${encodeURIComponent(l.technique)}`}
                      className="inline-flex h-(--chip) items-center gap-1.5 rounded-sm border border-border-strong px-2 text-xs text-fg-muted normal-nums transition-colors hover:border-fg-subtle hover:text-fg"
                    >
                      <span className="font-mono">{l.technique}</span>
                      {l.technique_name ? <span>{l.technique_name}</span> : null}
                    </Link>
                  ) : null}
                </div>
              ) : null}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
