import { ChevronDown } from "lucide-react"
import { useId, useState } from "react"
import { t } from "@/i18n"
import { Collapse } from "@/components/collapse"
import { CodeBlock } from "@/components/defend/code-block"
import { SeverityBadge } from "@/components/severity-badge"
import { evidenceLine, RULE_KIND_META, SOURCE_LABELS, type DetectionRule } from "@/lib/defend"
import { cn } from "@/lib/utils"

/** One generated rule. The text stays folded until asked for, and is only ever shown as text. */
export function RuleCard({ rule }: { rule: DetectionRule }) {
  const [open, setOpen] = useState(false)
  const panelId = useId()
  return (
    <li className="rounded-lg border bg-surface shadow-sm">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-start gap-3 rounded-lg px-4 py-3.5 text-left transition-colors duration-150 hover:bg-surface-hover/50 sm:px-5"
      >
        <span className="min-w-0 flex-1 space-y-1.5">
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="text-sm font-medium text-fg">{rule.title}</span>
            <SeverityBadge severity={rule.severity} />
          </span>
          <span className="block text-sm text-pretty text-fg-muted">{rule.rationale}</span>
          <span className="flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-fg-subtle">
            <span>{SOURCE_LABELS[rule.source]}</span>
            <span>{evidenceLine(rule.sessions, rule.sources)}</span>
          </span>
        </span>
        <span className="mt-0.5 inline-flex shrink-0 items-center gap-1 text-xs text-fg-muted">
          <span className="hidden sm:inline">{open ? t("rule_hide") : t("rule_show")}</span>
          <ChevronDown
            aria-hidden
            className={cn("size-4 transition-transform duration-200", open && "rotate-180")}
          />
        </span>
      </button>
      <Collapse open={open} id={panelId} className="border-t px-4 py-4 sm:px-5">
        <CodeBlock
          text={rule.text}
          label={t("rule_code_label", { kind: RULE_KIND_META[rule.kind].label, title: rule.title })}
          caption={t("rule_code_caption", { kind: RULE_KIND_META[rule.kind].label })}
        />
      </Collapse>
    </li>
  )
}
