import { ListChecks, Rss } from "lucide-react"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { CodeBlock } from "@/components/defend/code-block"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { Term } from "@/components/term"
import { Button } from "@/components/ui/button"
import { MIN_CONFIRMING_SENSORS, type FeedStatus } from "@/lib/network-feed"

/**
 * The tab when the dashboard does not fetch the lists. Firewalls can still fetch them straight
 * from the public address, so the address is shown to copy. No request is made to the list host
 * until the flag is on.
 */
export function FeedOff({ status, onHowTo }: { status: FeedStatus; onHowTo: () => void }) {
  const outbound = status.lists.find((l) => l.id === "outbound")
  const txt = outbound?.files.find((f) => f.format === "txt" && f.tier === "standard")
  return (
    <div className="space-y-4">
      <EmptyState
        icon={Rss}
        title={t("nfeed_off_title")}
        description={t("nfeed_off_description", { min: MIN_CONFIRMING_SENSORS })}
        action={
          <Button variant="outline" size="sm" onClick={onHowTo}>
            <ListChecks aria-hidden />
            {t("nfeed_off_how_to")}
          </Button>
        }
      />
      <FindingCard
        eyebrow={t("nfeed_off_ways")}
        finding={t("nfeed_off_finding")}
        detail={tNodes(
          "nfeed_off_detail",
          {},
          {
            outbound: <Term id="outbound-list">{t("nfeed_term_outbound_list")}</Term>,
            inbound: <Term id="inbound-list">{t("nfeed_term_inbound_list")}</Term>,
          },
        )}
      >
        <div className="space-y-4 text-sm text-fg-muted">
          <div className="space-y-2">
            <p className="font-medium text-fg">{t("nfeed_off_direct")}</p>
            {txt ? (
              <CodeBlock
                text={txt.url}
                label={t("nfeed_off_address_label")}
                caption={t("nfeed_off_address_caption")}
              />
            ) : (
              <p>{t("nfeed_off_no_address")}</p>
            )}
          </div>
          <div className="space-y-2">
            <p className="font-medium text-fg">{t("nfeed_off_fetch")}</p>
            <p>{t("nfeed_off_fetch_hint")}</p>
            <CodeBlock
              text="just set NETWORK_FEED_ENABLED=true"
              label={t("nfeed_off_command_label")}
              caption={t("nfeed_off_command_caption")}
            />
          </div>
        </div>
      </FindingCard>
    </div>
  )
}
