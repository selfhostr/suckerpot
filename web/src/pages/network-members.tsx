import { useQuery } from "@tanstack/react-query"
import { Users, X } from "lucide-react"
import { useMemo } from "react"
import { FindingCard } from "@/components/finding-card"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { SkeletonCard } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { JoinCard } from "@/components/network/join-card"
import { MembersList } from "@/components/network/members-list"
import { useNetworkStatus } from "@/components/network/use-network"
import { useUrlParam } from "@/hooks/use-url-param"
import { intlLocale, t } from "@/i18n"
import { countryName } from "@/lib/format"
import { isMember, memberName, membersFinding, networkApi, networkKeys } from "@/lib/network"

export function NetworkMembersPage() {
  const status = useNetworkStatus()
  const member = isMember(status.data)
  const [country, setCountry] = useUrlParam("country")
  const summary = useQuery({
    queryKey: networkKeys.summary,
    queryFn: networkApi.summary,
    enabled: member,
  })
  const s = summary.data
  const shown = useMemo(() => {
    const all = s?.members ?? []
    const list = country ? all.filter((m) => m.country === country.toUpperCase()) : [...all]
    // Sorted by name, never by activity: the network has no ranking.
    return list.sort((a, b) =>
      memberName(a).localeCompare(memberName(b), intlLocale(), { sensitivity: "base" }),
    )
  }, [s, country])

  return (
    <>
      <PageHeader
        help="network-members"
        title={t("network_members_title")}
        description={t("network_members_description")}
      />
      {status.isPending || (member && summary.isPending) ? (
        <SkeletonCard />
      ) : !member ? (
        <div className="grid grid-cols-1 gap-4">
          <EmptyState
            icon={Users}
            title={t("network_members_guest_title")}
            description={t("network_members_guest_description")}
          />
          <JoinCard />
        </div>
      ) : !s ? (
        <EmptyState
          icon={Users}
          title={t("network_members_waiting_title")}
          description={t("network_members_waiting_description")}
        />
      ) : (
        <FindingCard
          eyebrow={t("network_members_eyebrow")}
          finding={
            country
              ? t("network_members_country_finding", {
                  shown: shown.length,
                  count: s.totals.members,
                  country: countryName(country) ?? country,
                })
              : membersFinding(s.totals)
          }
          detail={t("network_members_detail")}
          action={
            country ? (
              <Button variant="outline" size="sm" onClick={() => setCountry(null)}>
                <X aria-hidden />
                {t("network_members_clear_country")}
              </Button>
            ) : null
          }
          bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0 pt-4"
        >
          {shown.length === 0 ? (
            <div className="border-t p-4 sm:p-5">
              <EmptyState
                variant="bare"
                icon={Users}
                title={t("network_members_none_title")}
                description={t("network_members_none_description")}
              />
            </div>
          ) : (
            <MembersList members={shown} self={status.data?.fingerprint} />
          )}
        </FindingCard>
      )}
    </>
  )
}
