import { Download, ListOrdered } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
import { t } from "@/i18n"
import { FirewallStepsSheet } from "@/components/defend/firewall-steps-sheet"
import { FindingCard } from "@/components/finding-card"
import { SegmentedControl } from "@/components/segmented-control"
import { Button } from "@/components/ui/button"
import {
  BLOCK_KINDS,
  exportUrl,
  DEFAULT_MIN_SCORE,
  HIGH_SCORE,
  KIND_META,
  kindCount,
  LISTED_SCORE,
  SCORE_OPTIONS,
  scorePreset,
  type BlockKind,
  type DefendSummary,
} from "@/lib/defend"

type Format = "txt" | "alias" | "csv"

/** Download a list, or read how to point a firewall at it. */
export function ExportPanel({
  summary,
  initialKind,
  initialScore = DEFAULT_MIN_SCORE,
}: {
  summary: DefendSummary | undefined
  initialKind: BlockKind
  /** Starts from the list filter, so "High confidence" on the page exports the same thing. */
  initialScore?: number
}) {
  const [kind, setKind] = useState<BlockKind>(initialKind)
  const [format, setFormat] = useState<Format>("txt")
  const [minScore, setMinScore] = useState<number>(initialScore)
  const [stepsOpen, setStepsOpen] = useState(false)

  const effectiveFormat: Format = kind === "ip" ? format : format === "alias" ? "txt" : format
  const href = exportUrl({ kind, format: effectiveFormat, minScore })
  const counts = summary?.kinds.find((k) => k.kind === kind)
  // The summary knows the 50+ and 70+ counts; below 50 only the total is known, so it is a ceiling.
  const count = counts
    ? minScore >= HIGH_SCORE
      ? counts.high
      : minScore >= LISTED_SCORE
        ? counts.listed
        : counts.total
    : null

  const formatOptions: { value: Format; label: string }[] = [
    { value: "txt", label: t("export_format_txt") },
    ...(kind === "ip" ? [{ value: "alias" as const, label: t("export_format_alias") }] : []),
    { value: "csv", label: t("export_format_csv") },
  ]

  return (
    <div id="export" className="scroll-mt-20">
      <FindingCard
        eyebrow={t("export_eyebrow")}
        finding={t("export_finding")}
        detail={t("export_detail")}
      >
        <div className="space-y-4">
          <div className="flex flex-wrap items-end gap-x-5 gap-y-3">
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-fg-muted">{t("export_what")}</p>
              <SegmentedControl
                label={t("export_what_label")}
                value={kind}
                onChange={setKind}
                options={BLOCK_KINDS.map((k) => ({ value: k, label: KIND_META[k].label }))}
                className="flex-wrap"
              />
            </div>
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-fg-muted">{t("export_format")}</p>
              <SegmentedControl
                label={t("export_format_label")}
                value={effectiveFormat}
                onChange={setFormat}
                options={formatOptions}
              />
            </div>
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-fg-muted">{t("export_min_score")}</p>
              <SegmentedControl
                label={t("export_min_score")}
                value={String(minScore)}
                onChange={(v) => setMinScore(Number(v))}
                options={SCORE_OPTIONS}
                className="flex-wrap"
              />
            </div>
          </div>
          <p className="-mt-2 text-xs text-fg-muted">{scorePreset(minScore)?.hint}</p>

          <div className="flex flex-wrap items-center gap-3">
            <Button asChild>
              <a href={href} download>
                <Download aria-hidden />
                {t("export_download", { kinds: KIND_META[kind].label })}
              </a>
            </Button>
            {count !== null ? (
              <p className="text-sm text-fg-muted">
                {t(minScore >= LISTED_SCORE ? "export_count_about" : "export_count_up_to", {
                  items: kindCount(kind, count),
                })}
              </p>
            ) : null}
          </div>

          {/* The firewall how-to is read once: it opens in a side sheet, so the entries below
              stay close to the top of the page. */}
          <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t pt-4">
            <div className="min-w-0">
              <h4 className="type-subtitle text-fg">{t("firewall_sheet_title")}</h4>
              <p className="text-xs text-fg-muted">{t("export_keep_hint")}</p>
            </div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                aria-haspopup="dialog"
                onClick={() => setStepsOpen(true)}
              >
                <ListOrdered aria-hidden />
                {t("export_firewall_steps")}
              </Button>
              <Link
                to="/settings?tab=feeds"
                className="text-sm text-fg underline underline-offset-4 hover:text-fg-muted"
              >
                {t("export_create_token")}
              </Link>
            </div>
          </div>
        </div>
      </FindingCard>
      <FirewallStepsSheet open={stepsOpen} onOpenChange={setStepsOpen} kind={kind} />
    </div>
  )
}
