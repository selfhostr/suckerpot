import { useState } from "react"
import { Link } from "react-router"
import { CopyButton } from "@/components/defend/copy-button"
import { t } from "@/i18n"
import { SegmentedControl } from "@/components/segmented-control"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import {
  firewallInstructions,
  FIREWALL_LABEL,
  instructionsText,
  KIND_META,
  type BlockKind,
  type Firewall,
} from "@/lib/defend"

/**
 * How to point a firewall at a feed, in a side sheet: the steps are read once, so they stay out
 * of the way of the export controls and the entries (the Network tab's how-to works the same way).
 */
export function FirewallStepsSheet({
  open,
  onOpenChange,
  kind,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  kind: BlockKind
}) {
  const [firewall, setFirewall] = useState<Firewall>("opnsense")
  const feed = `${window.location.origin}/feeds/<your-token>/${kind}.txt`
  const steps = firewallInstructions(firewall, feed)
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full gap-0 overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>{t("firewall_sheet_title")}</SheetTitle>
          <SheetDescription>
            {t("firewall_sheet_description", { kinds: KIND_META[kind].phrase })}
          </SheetDescription>
        </SheetHeader>
        <div className="space-y-4 px-4 pb-6">
          <SegmentedControl
            label={t("firewall_sheet_firewall")}
            value={firewall}
            onChange={setFirewall}
            options={(["opnsense", "pfsense"] as const).map((f) => ({
              value: f,
              label: FIREWALL_LABEL[f],
            }))}
          />
          <ol
            aria-label={t("firewall_sheet_steps", { firewall: FIREWALL_LABEL[firewall] })}
            className="list-decimal space-y-2 pl-5 text-sm text-pretty text-fg-muted marker:text-fg-subtle"
          >
            {steps.map((s) => (
              <li key={s} className="pl-1 break-words">
                {s}
              </li>
            ))}
          </ol>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <CopyButton
              variant="outline"
              text={instructionsText(firewall, feed)}
              label={t("firewall_sheet_copy")}
            >
              {t("firewall_sheet_copy")}
            </CopyButton>
            <Link
              to="/settings?tab=feeds"
              className="text-sm text-fg underline underline-offset-4 hover:text-fg-muted"
            >
              {t("firewall_sheet_token")}
            </Link>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  )
}
