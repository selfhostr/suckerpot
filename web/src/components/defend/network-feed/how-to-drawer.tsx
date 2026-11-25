import { useState } from "react"
import { t, tk } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { CodeBlock } from "@/components/defend/code-block"
import { SegmentedControl } from "@/components/segmented-control"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { addressFor, usageSteps, type FeedStatus, type FirewallApp } from "@/lib/network-feed"

const APPS = [
  { value: "opnsense", label: "OPNsense" },
  { value: "pfsense", label: "pfSense" },
  { value: "nftables", label: "nftables" },
] as const

const PICK: Record<FirewallApp, string> = {
  opnsense: tk("nfeed_howto_pick_opnsense"),
  pfsense: tk("nfeed_howto_pick_pfsense"),
  nftables: tk("nfeed_howto_pick_nftables"),
}

/** The steps to put the lists in a firewall. The lists are optional, and so is every step. */
export function HowToDrawer({
  open,
  onOpenChange,
  status,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  status: FeedStatus | undefined
}) {
  const [app, setApp] = useState<FirewallApp>("opnsense")
  const url = addressFor(app, status)
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full gap-0 overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>{t("nfeed_howto_title")}</SheetTitle>
          <SheetDescription>
            {t("nfeed_howto_description")}
          </SheetDescription>
        </SheetHeader>
        <div className="space-y-4 px-4 pb-6">
          <SegmentedControl
            label={t("firewall_sheet_firewall")}
            value={app}
            onChange={setApp}
            options={APPS}
          />
          <p className="text-sm text-fg-muted">{t(PICK[app])}</p>
          <CodeBlock
            text={url}
            label={t("nfeed_howto_address", { app })}
            caption={t("nfeed_howto_caption")}
          />
          <ol className="list-decimal space-y-2 pl-5 text-sm text-pretty text-fg-muted marker:text-fg-subtle">
            {usageSteps(app, url).map((step) => (
              <li key={step} className="break-words">
                {step}
              </li>
            ))}
          </ol>
          <p className="text-xs text-fg-muted">
            {tNodes(
              "nfeed_howto_more",
              {},
              { file: <code className="font-mono text-fg">docs/feeds.md</code> },
            )}
          </p>
        </div>
      </SheetContent>
    </Sheet>
  )
}
