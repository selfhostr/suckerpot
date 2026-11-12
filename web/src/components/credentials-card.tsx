import { useQuery } from "@tanstack/react-query"
import { useIpMask } from "@/app/ip-mask"
import { FindingCard } from "@/components/finding-card"
import { TopList, type TopListItem } from "@/components/top-list"
import { api, queryKeys, type CredentialCount } from "@/lib/api"
import { credentialsFinding } from "@/lib/floods"
import { formatNumber, maskIpsInText } from "@/lib/format"

const TOP = 10

/** One credential value as a ranked, clickable row; an empty value is said, not shown blank. */
function toItems(
  values: readonly CredentialCount[],
  param: "username" | "password",
  attempts: number,
  mask: boolean,
): TopListItem[] {
  return values.map((v) => {
    if (v.value === "") {
      return {
        key: `${param}-empty`,
        name: `No ${param} captured`,
        label: <span className="text-fg-muted">(none captured)</span>,
        count: v.count,
        share: attempts ? v.count / attempts : 0,
      }
    }
    const value = mask ? maskIpsInText(v.value) : v.value
    return {
      key: `${param}-${v.value}`,
      name: value,
      label: <span className="font-mono text-xs">{value}</span>,
      count: v.count,
      share: attempts ? v.count / attempts : 0,
      href: `/trends?${param}=${encodeURIComponent(value)}`,
    }
  })
}

/**
 * What a flood group tried to log in with, from `GET /sessions/{id}/credentials`: the finding
 * first, then the most used usernames and passwords, each opening the matching Trends filter.
 */
export function CredentialsCard({
  sessionId,
  className,
}: {
  sessionId: string
  className?: string
}) {
  const { masked } = useIpMask()
  const query = useQuery({
    queryKey: queryKeys.sessionCredentials(sessionId),
    queryFn: () => api.sessionCredentials(sessionId, TOP),
  })
  const c = query.data

  const notes: string[] = []
  if (c) {
    if (c.distinct_usernames > c.usernames.length)
      notes.push(
        `Top ${c.usernames.length} of ${formatNumber(c.distinct_usernames)} different usernames`,
      )
    if (c.distinct_passwords > c.passwords.length)
      notes.push(
        `Top ${c.passwords.length} of ${formatNumber(c.distinct_passwords)} different passwords`,
      )
    if (c.truncated) notes.push("Counted from the first 50,000 attempts")
  }

  return (
    <FindingCard
      className={className}
      eyebrow="Credentials tried"
      finding={
        query.isError
          ? "Could not load the credentials."
          : c
            ? credentialsFinding(c)
            : "Loading the credentials…"
      }
      footer={notes.length ? notes.join(" · ") : undefined}
    >
      {query.isError ? (
        <p className="text-sm text-fg-muted">{query.error.message}</p>
      ) : (
        <div className="grid grid-cols-1 gap-x-8 gap-y-5 sm:grid-cols-2">
          <section aria-label="Usernames tried">
            <h4 className="mb-2 text-xs font-medium text-fg-muted">Usernames</h4>
            <TopList
              loading={!c}
              rows={3}
              items={c ? toItems(c.usernames, "username", c.attempts, masked) : []}
              empty="No usernames."
            />
          </section>
          <section aria-label="Passwords tried">
            <h4 className="mb-2 text-xs font-medium text-fg-muted">Passwords</h4>
            <TopList
              loading={!c}
              rows={3}
              items={c ? toItems(c.passwords, "password", c.attempts, masked) : []}
              empty="No passwords."
            />
          </section>
        </div>
      )}
    </FindingCard>
  )
}
