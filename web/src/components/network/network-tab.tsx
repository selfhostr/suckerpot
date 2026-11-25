import { FindingCard } from "@/components/finding-card"
import { SharedExplainer } from "./explainer"
import { JoinCard } from "./join-card"
import { NodeCard } from "./node-card"
import { useNetworkStatus } from "./use-network"
import { isMember } from "@/lib/network"
import { t } from "@/i18n"

/**
 * Settings, Network tab: the place to join and to leave. A member sees their node and the two
 * actions; everyone else sees the offer. The full explanation is always one scroll away.
 */
export function NetworkTab() {
  const q = useNetworkStatus()
  const member = isMember(q.data)
  return (
    <>
      {member && q.data ? <NodeCard status={q.data} /> : <JoinCard />}
      <FindingCard
        eyebrow={t("network_tab_eyebrow")}
        finding={member ? t("network_tab_finding_member") : t("network_tab_finding_guest")}
      >
        <SharedExplainer />
      </FindingCard>
    </>
  )
}
