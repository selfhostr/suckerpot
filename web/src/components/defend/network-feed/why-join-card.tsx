import { Link } from "react-router"
import { t } from "@/i18n"
import { FindingCard } from "@/components/finding-card"
import { Button } from "@/components/ui/button"
import type { FeedStatus } from "@/lib/network-feed"

/** Honest wording: the lists are the same for everyone, joining only helps them grow. */
export function WhyJoinCard({ status }: { status: FeedStatus }) {
  if (status.member) {
    const helped = status.lists.reduce((n, l) => n + (l.helped ?? 0), 0)
    return (
      <FindingCard
        eyebrow={t("nfeed_why_part")}
        finding={
          helped > 0 ? t("nfeed_why_helped", { count: helped }) : t("nfeed_why_member_none")
        }
        detail={t("nfeed_why_member_detail")}
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/network">{t("nfeed_why_open")}</Link>
          </Button>
        }
      />
    )
  }
  return (
    <FindingCard
      eyebrow={t("nfeed_why_join")}
      finding={t("nfeed_why_join_finding")}
      detail={t("nfeed_why_join_detail")}
      action={
        <Button asChild variant="outline" size="sm">
          <Link to="/network">{t("nfeed_why_about")}</Link>
        </Button>
      }
    />
  )
}
