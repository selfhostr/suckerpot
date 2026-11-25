import { useQuery } from "@tanstack/react-query"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { FindingCard } from "@/components/finding-card"
import { t } from "@/i18n"
import { Button } from "@/components/ui/button"
import {
  abuseApi,
  abuseKeys,
  blockedReasons,
  describeBlockedDrafts,
  describeSettingsIssue,
  type BlockedDrafts,
} from "@/lib/abuse"

const SETTINGS_LINK = "/settings?tab=reporting#reporting-message"

/**
 * The saved reporting texts that block every report today, one sentence per field, with a link
 * to fix them. Administrators only (the settings are theirs); renders nothing when all is well.
 */
export function SettingsCause() {
  const { canWrite } = useAuth()
  const q = useQuery({
    queryKey: abuseKeys.settings,
    queryFn: abuseApi.settings,
    enabled: canWrite,
  })
  const issues = Object.entries(q.data?.field_issues ?? {})
  if (!canWrite || issues.length === 0) return null
  return (
    <div className="space-y-2 text-sm">
      <p className="font-medium text-fg">{t("abuse_blocked_settings_found")}</p>
      <ul className="list-disc space-y-1 pl-5 text-fg-muted">
        {issues.map(([field, codes]) => (
          <li key={field}>{describeSettingsIssue(field, codes)}</li>
        ))}
      </ul>
      <Link
        to={SETTINGS_LINK}
        className="inline-block font-medium text-fg underline underline-offset-4"
      >
        {t("abuse_blocked_settings_fix")}
      </Link>
    </div>
  )
}

/**
 * Above the list of drafts: how many are blocked by the identity check, why (one sentence per
 * reason, with what to do) and, for an administrator, the setting that causes it.
 */
export function BlockedDraftsNotice({ blocked }: { blocked: BlockedDrafts }) {
  const { canWrite } = useAuth()
  if (blocked.count === 0) return null
  return (
    <FindingCard
      eyebrow={t("abuse_blocked_eyebrow")}
      help="blocked"
      finding={describeBlockedDrafts(blocked)}
      detail={t("abuse_blocked_detail")}
      action={
        canWrite ? (
          <Button asChild variant="outline" size="sm">
            <Link to={SETTINGS_LINK}>{t("abuse_blocked_open_settings")}</Link>
          </Button>
        ) : undefined
      }
      className="border-sev-warning/40"
    >
      <div className="space-y-4">
        <SettingsCause />
        <ul className="list-disc space-y-2 pl-5 text-sm">
          {blockedReasons(blocked).map((r) => (
            <li key={r.code}>
              <span className="text-fg">{r.why}</span>{" "}
              <span className="text-fg-muted">
                {t("abuse_blocked_reason_drafts", { count: r.drafts })} {r.fix}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </FindingCard>
  )
}
