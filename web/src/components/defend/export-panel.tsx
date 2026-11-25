import { Download, ListOrdered } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
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
  LISTED_SCORE,
  SCORE_OPTIONS,
  scorePreset,
  type BlockKind,
  type DefendSummary,
} from "@/lib/defend"
import { formatNumber } from "@/lib/format"

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
  const countPrefix = minScore >= LISTED_SCORE ? "About" : "Up to"

  const formatOptions: { value: Format; label: string }[] = [
    { value: "txt", label: "Plain list" },
    ...(kind === "ip" ? [{ value: "alias" as const, label: "Firewall alias" }] : []),
    { value: "csv", label: "CSV" },
  ]

  return (
    <div id="export" className="scroll-mt-20">
      <FindingCard
        eyebrow="Export"
        finding="Download a list, or point your firewall at it so it stays current."
        detail="Entries you always allow and research scanners are left out. Demo entries are never exported."
      >
        <div className="space-y-4">
          <div className="flex flex-wrap items-end gap-x-5 gap-y-3">
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-fg-muted">What</p>
              <SegmentedControl
                label="What to export"
                value={kind}
                onChange={setKind}
                options={BLOCK_KINDS.map((k) => ({ value: k, label: KIND_META[k].label }))}
                className="flex-wrap"
              />
            </div>
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-fg-muted">Format</p>
              <SegmentedControl
                label="File format"
                value={effectiveFormat}
                onChange={setFormat}
                options={formatOptions}
              />
            </div>
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-fg-muted">Minimum score</p>
              <SegmentedControl
                label="Minimum score"
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
                Download {KIND_META[kind].label}
              </a>
            </Button>
            {count !== null ? (
              <p className="text-sm text-fg-muted">
                {countPrefix} {formatNumber(count)}{" "}
                {count === 1 ? KIND_META[kind].one : KIND_META[kind].many} at this score.
              </p>
            ) : null}
          </div>

          {/* The firewall how-to is read once: it opens in a side sheet, so the entries below
              stay close to the top of the page. */}
          <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t pt-4">
            <div className="min-w-0">
              <h4 className="text-sm font-medium text-fg">Keep a firewall up to date</h4>
              <p className="text-xs text-fg-muted">
                Point OPNsense or pfSense at a feed instead of downloading again.
              </p>
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
                Firewall steps
              </Button>
              <Link
                to="/settings?tab=feeds"
                className="text-sm text-fg underline underline-offset-4 hover:text-fg-muted"
              >
                Create a feed token
              </Link>
            </div>
          </div>
        </div>
      </FindingCard>
      <FirewallStepsSheet open={stepsOpen} onOpenChange={setStepsOpen} kind={kind} />
    </div>
  )
}
