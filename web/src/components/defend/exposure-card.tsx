import {
  CircleDashed,
  Ellipsis,
  Globe,
  Lock,
  Pencil,
  ShieldCheck,
  Trash2,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react"
import { Link } from "react-router"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { TagBadge } from "@/components/tag-badge"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  EXPOSURE_LABEL,
  previousComparison,
  VERDICT_SENTENCE,
  type ExposureService,
  type InventoryItem,
  type Verdict,
} from "@/lib/defend"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

const VERDICT_ICON: Record<Verdict, { icon: LucideIcon; className: string }> = {
  internet_targeted: { icon: TriangleAlert, className: "text-sev-warning" },
  internet_quiet: { icon: CircleDashed, className: "text-fg-muted" },
  private_targeted: { icon: Lock, className: "text-fg" },
  private_quiet: { icon: ShieldCheck, className: "text-fg-muted" },
}

export function Checks({ checks, title }: { checks: string[]; title?: string }) {
  if (checks.length === 0) return null
  return (
    <div className="space-y-1.5">
      <h5 className="type-eyebrow text-fg-muted">{title ?? t("exposure_checks_title")}</h5>
      <ul className="list-disc space-y-1 pl-4 text-sm text-fg marker:text-fg-subtle">
        {checks.map((c) => (
          <li key={c} className="pl-1 text-pretty">
            {c}
          </li>
        ))}
      </ul>
    </div>
  )
}

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1)
}

function Stat({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1.5">
      <dt className="min-w-0 text-sm text-fg-muted">{label}</dt>
      <dd className="shrink-0 text-sm font-medium text-fg">{children}</dd>
    </div>
  )
}

/** One service from your inventory, set against what the decoys recorded for that kind. */
export function ExposureCard({
  service,
  canWrite,
  onEdit,
  onRemove,
}: {
  service: ExposureService
  canWrite: boolean
  onEdit: (item: InventoryItem) => void
  onRemove: (item: InventoryItem) => void
}) {
  const { item, attacks, verdict } = service
  const v = VERDICT_ICON[verdict]
  const VerdictIcon = v.icon
  const ExposureIcon = item.exposure === "internet" ? Globe : Lock
  const product = [item.product, item.version].filter(Boolean).join(" ")
  return (
    <article className="flex flex-col gap-4 rounded-lg border bg-surface p-4 shadow-sm sm:p-5">
      <header className="flex items-start justify-between gap-3">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="type-card-title text-fg">{item.name}</h3>
            <SensorBadge sensor={item.service} />
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg-muted">
            {product ? <span>{product}</span> : null}
            <span className="inline-flex items-center gap-1">
              <ExposureIcon aria-hidden className="size-3" />
              {EXPOSURE_LABEL[item.exposure]}
            </span>
          </div>
        </div>
        {canWrite ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={t("exposure_card_actions", { name: item.name })}
              >
                <Ellipsis aria-hidden />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={() => onEdit(item)}>
                <Pencil aria-hidden />
                {t("common_edit")}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => onRemove(item)}>
                <Trash2 aria-hidden />
                {t("exposure_card_remove")}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ) : null}
      </header>

      <p className={cn("flex items-start gap-2 text-sm font-medium", v.className)}>
        <VerdictIcon aria-hidden className="mt-0.5 size-4 shrink-0" strokeWidth={2.25} />
        <span className="text-fg">{VERDICT_SENTENCE[verdict]}</span>
      </p>

      {/* Label left, number right: three rows that read like a sentence and always line up. */}
      <div>
        <dl className="divide-y border-y">
          <Stat label={t("exposure_card_attacks")}>
            <Link
              to={`/attacks?sensor=${item.service}`}
              className="font-medium underline-offset-4 hover:underline"
            >
              {t("exposure_card_sessions", { count: attacks.sessions })}
            </Link>
          </Stat>
          <Stat label={t("exposure_card_from")}>
            {t("exposure_card_sources", { count: attacks.sources })}
          </Stat>
          <Stat label={t("exposure_card_deep")}>
            {t("exposure_card_sessions", { count: attacks.deep_sessions })}
          </Stat>
        </dl>
        <p className="mt-2 text-xs text-fg-muted">
          {capitalize(previousComparison(attacks.sessions, attacks.previous_sessions))}
          {attacks.last_attack_at ? (
            <>
              {" · "}
              {tNodes(
                "exposure_card_last_attack",
                {},
                { time: <RelativeTime iso={attacks.last_attack_at} className="text-xs" /> },
              )}
            </>
          ) : null}
        </p>
      </div>

      {service.top_tags.length > 0 ? (
        <div className="space-y-1.5">
          <h5 className="type-eyebrow text-fg-muted">{t("exposure_card_did")}</h5>
          <ul aria-label={t("exposure_card_top_tags")} className="flex flex-wrap gap-1.5">
            {service.top_tags.map((x) => (
              <li key={x.tag} className="inline-flex items-center gap-1.5">
                <TagBadge tag={x.tag} />
                <span className="text-xs text-fg-subtle">{formatNumber(x.sessions)}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {service.cves.length > 0 ? (
        <div className="space-y-1.5">
          <h5 className="type-eyebrow text-fg-muted">{t("exposure_card_flaws")}</h5>
          <ul className="space-y-1.5">
            {service.cves.map((c) => (
              <li key={c.cve_id} className="space-y-0.5">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <Link
                    to={`/cves?cve=${encodeURIComponent(c.cve_id)}`}
                    className="font-mono text-xs text-fg underline underline-offset-4"
                  >
                    {c.cve_id}
                  </Link>
                  {c.cvss_score !== null ? (
                    <span className="text-xs text-fg-muted">
                      {t("exposure_card_cvss", { score: c.cvss_score.toFixed(1) })}
                    </span>
                  ) : null}
                  {c.in_kev ? (
                    <Badge variant="outline" className="text-fg">
                      {t("exposure_card_kev")}
                    </Badge>
                  ) : null}
                </div>
                {c.title ? (
                  <p className="text-xs text-pretty text-fg-muted normal-nums">{c.title}</p>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <Checks checks={service.checks} />

      {item.notes ? <p className="text-xs text-fg-subtle">
          {t("exposure_card_note", { note: item.notes })}
        </p> : null}
    </article>
  )
}
