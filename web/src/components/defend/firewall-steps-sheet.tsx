import { useState } from "react"
import { Link } from "react-router"
import { CopyButton } from "@/components/defend/copy-button"
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
          <SheetTitle>Keep a firewall up to date</SheetTitle>
          <SheetDescription>
            Your firewall fetches the list of {KIND_META[kind].phrase} once a day from a feed, so it
            stays current without a new download.
          </SheetDescription>
        </SheetHeader>
        <div className="space-y-4 px-4 pb-6">
          <SegmentedControl
            label="Firewall"
            value={firewall}
            onChange={setFirewall}
            options={(["opnsense", "pfsense"] as const).map((f) => ({
              value: f,
              label: FIREWALL_LABEL[f],
            }))}
          />
          <ol
            aria-label={`${FIREWALL_LABEL[firewall]} steps`}
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
              label="Copy firewall instructions"
            >
              Copy firewall instructions
            </CopyButton>
            <Link
              to="/settings?tab=feeds"
              className="text-sm text-fg underline underline-offset-4 hover:text-fg-muted"
            >
              Create a feed token in Settings
            </Link>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  )
}
