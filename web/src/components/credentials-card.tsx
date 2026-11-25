import { useQuery } from "@tanstack/react-query"
import { t } from "@/i18n"
import { useIpMask } from "@/app/ip-mask"
import { FindingCard } from "@/components/finding-card"
import { TopList, type TopListItem } from "@/components/top-list"
import { api, queryKeys, type CredentialCount } from "@/lib/api"
import { credentialsFinding } from "@/lib/floods"
import { maskIpsInText } from "@/lib/format"

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
        name: t("creds_none_captured", { field: param }),
        label: <span className="text-fg-muted">{t("creds_none_label")}</span>,
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
        t("creds_top_of", {
          shown: c.usernames.length,
          total: c.distinct_usernames,
          field: "username",
        }),
      )
    if (c.distinct_passwords > c.passwords.length)
      notes.push(
        t("creds_top_of", {
          shown: c.passwords.length,
          total: c.distinct_passwords,
          field: "password",
        }),
      )
    if (c.truncated) notes.push(t("creds_truncated", { limit: 50_000 }))
  }

  return (
    <FindingCard
      className={className}
      eyebrow={t("creds_eyebrow")}
      finding={query.isError ? t("creds_error") : c ? credentialsFinding(c) : t("creds_loading")}
      footer={notes.length ? notes.join(" · ") : undefined}
    >
      {query.isError ? (
        <p className="text-sm text-fg-muted">{query.error.message}</p>
      ) : (
        <div className="grid grid-cols-1 gap-x-8 gap-y-5 sm:grid-cols-2">
          <section aria-label={t("creds_usernames_label")}>
            <h4 className="mb-2 type-eyebrow text-fg-muted">{t("creds_usernames")}</h4>
            <TopList
              loading={!c}
              rows={3}
              scale="total"
              items={c ? toItems(c.usernames, "username", c.attempts, masked) : []}
              empty={t("creds_usernames_empty")}
            />
          </section>
          <section aria-label={t("creds_passwords_label")}>
            <h4 className="mb-2 type-eyebrow text-fg-muted">{t("creds_passwords")}</h4>
            <TopList
              loading={!c}
              rows={3}
              scale="total"
              items={c ? toItems(c.passwords, "password", c.attempts, masked) : []}
              empty={t("creds_passwords_empty")}
            />
          </section>
        </div>
      )}
    </FindingCard>
  )
}
