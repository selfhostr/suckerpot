import { useQuery } from "@tanstack/react-query"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { FindingCard } from "@/components/finding-card"
import { Button } from "@/components/ui/button"
import {
  abuseApi,
  abuseKeys,
  blockedReasons,
  describeBlockedDrafts,
  describeSettingsIssue,
  type BlockedDrafts,
} from "@/lib/abuse"
import { plural } from "@/lib/format"

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
      <p className="font-medium text-fg">Found in your reporting settings</p>
      <ul className="list-disc space-y-1 pl-5 text-fg-muted">
        {issues.map(([field, codes]) => (
          <li key={field}>{describeSettingsIssue(field, codes)}</li>
        ))}
      </ul>
      <Link
        to={SETTINGS_LINK}
        className="inline-block font-medium text-fg underline underline-offset-4"
      >
        Fix them in the Reporting settings
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
      eyebrow="Blocked drafts"
      finding={describeBlockedDrafts(blocked)}
      detail="The identity check stops any draft that could point back to you or to the project. A blocked draft can never be reviewed or sent."
      action={
        canWrite ? (
          <Button asChild variant="outline" size="sm">
            <Link to={SETTINGS_LINK}>Open Reporting settings</Link>
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
                {plural(r.drafts, "draft")}. {r.fix}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </FindingCard>
  )
}
