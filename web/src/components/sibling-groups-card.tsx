import { useQuery } from "@tanstack/react-query"
import { FindingCard } from "@/components/finding-card"
import { SessionRow } from "@/components/session-row"
import { api, queryKeys, type Session, type SessionFilters } from "@/lib/api"
import { floodHour } from "@/lib/floods"
import { plural } from "@/lib/format"

/**
 * The other flood groups of the same address in the same UTC hour (same address, another port,
 * another stage or other tags). Nothing is drawn when there are none.
 */
export function SiblingGroupsCard({ group, className }: { group: Session; className?: string }) {
  const filters: SessionFilters = {
    src_ip: group.src_ip,
    kind: "burst",
    ...floodHour(group.started_at),
  }
  const query = useQuery({
    queryKey: queryKeys.sessions(filters),
    queryFn: () => api.sessions(filters, null, 50),
  })
  const others = (query.data?.items ?? []).filter((s) => s.session_id !== group.session_id)
  if (others.length === 0) return null

  return (
    <FindingCard
      className={className}
      eyebrow="Same hour"
      finding={`${plural(others.length, "other flood group")} from this address in the same hour.`}
      bodyClassName="p-0 sm:p-0 pt-4 sm:pt-4"
    >
      <ul aria-label="Flood groups of the same hour" className="border-t">
        {others.map((s, i) => (
          <li key={s.session_id} className={i > 0 ? "border-t" : undefined}>
            <SessionRow session={s} showSource={false} compact />
          </li>
        ))}
      </ul>
    </FindingCard>
  )
}
