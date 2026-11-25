import { CircleCheck, CircleDashed, CircleOff, TriangleAlert, type LucideIcon } from "lucide-react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { useSetupStatus } from "@/hooks/use-setup-status"
import { FindingCard } from "@/components/finding-card"
import { SkeletonText } from "@/components/skeletons"
import {
  describeSetup,
  safeHref,
  SETUP_STATE_LABEL,
  setupTitle,
  type SetupItem,
  type SetupState,
} from "@/lib/setup"
import { cn } from "@/lib/utils"

const STATE_STYLE: Record<SetupState, { icon: LucideIcon; className: string }> = {
  ok: { icon: CircleCheck, className: "text-status-ok" },
  todo: { icon: CircleDashed, className: "text-fg" },
  warning: { icon: TriangleAlert, className: "text-sev-warning" },
  off: { icon: CircleOff, className: "text-fg-muted" },
}

export function FirewallNote() {
  return (
    <>
      {tNodes(
        "checklist_firewall_note",
        {},
        { command: <code className="font-mono text-fg">just egress-check</code> },
      )}
    </>
  )
}

/** One row per item: icon and word first, a sentence, and a link to the place that fixes it. */
export function SetupItems({
  items,
  onNavigate,
  className,
}: {
  items: readonly SetupItem[]
  /** Called when a link is followed (the tour closes itself). */
  onNavigate?: () => void
  className?: string
}) {
  return (
    <ul aria-label={t("checklist_title")} className={cn("divide-y border-t", className)}>
      {items.map((item) => {
        const { icon: Icon, className: tone } = STATE_STYLE[item.state]
        const href = safeHref(item.href)
        const title = setupTitle(item.id)
        return (
          <li
            key={item.id}
            className="grid grid-cols-[auto_1fr_auto] items-start gap-x-3 gap-y-0.5 px-4 py-3 sm:px-5"
          >
            <Icon aria-hidden className={cn("mt-0.5 size-4", tone)} strokeWidth={2.25} />
            <div className="min-w-0">
              <p className="text-sm font-medium text-fg">
                {title}
                <span className={cn("ml-2 text-xs font-medium whitespace-nowrap", tone)}>
                  {SETUP_STATE_LABEL[item.state]}
                </span>
              </p>
              <p className="text-xs text-pretty text-fg-muted">{item.detail}</p>
            </div>
            {href ? (
              <Link
                to={href}
                onClick={onNavigate}
                aria-label={t("checklist_open_label", { title })}
                className="rounded-sm text-xs font-medium text-fg-muted underline underline-offset-4 transition-colors hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
              >
                {t("common_open")}
              </Link>
            ) : (
              <span />
            )}
          </li>
        )
      })}
    </ul>
  )
}

/** Settings, General tab: what is set up and what is left. Hidden from viewers. */
export function SetupChecklistCard() {
  const { canWrite } = useAuth()
  const q = useSetupStatus()
  if (!canWrite) return null
  const items = q.data
  return (
    <FindingCard
      eyebrow={t("checklist_title")}
      help="checklist"
      finding={
        items
          ? describeSetup(items)
          : q.isError
            ? t("checklist_unavailable")
            : t("checklist_checking")
      }
      detail={t("checklist_detail")}
      bodyClassName="px-0 sm:px-0 pt-3 pb-0 sm:pb-0"
      footer={<FirewallNote />}
    >
      {items ? (
        <SetupItems items={items} />
      ) : q.isPending ? (
        <div className="border-t px-4 py-3 sm:px-5">
          <SkeletonText lines={4} />
        </div>
      ) : null}
    </FindingCard>
  )
}
