import { useQuery } from "@tanstack/react-query"
import { FileJson, LogOut, Pencil, TriangleAlert } from "lucide-react"
import { useState } from "react"
import { useAuth } from "@/app/auth"
import { CountryFlag } from "@/components/country-flag"
import { FindingCard } from "@/components/finding-card"
import { Button } from "@/components/ui/button"
import { formatNumber } from "@/lib/format"
import {
  describeNetworkError,
  eligibilityText,
  formatDay,
  networkApi,
  networkKeys,
  STANDING_TEXT,
  waitingText,
  type NetworkStatus,
} from "@/lib/network"
import { LeaveDialog } from "./leave-dialog"
import { ProfileDialog } from "./profile-dialog"
import { SentDrawer } from "./sent-drawer"
import { t } from "@/i18n"

function Field({
  label,
  children,
  className,
}: {
  label: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={className}>
      <dt className="text-xs text-fg-muted">{label}</dt>
      <dd className="mt-1 text-sm text-fg">{children}</dd>
    </div>
  )
}

/** "Your node": what the network knows about this system, and the two ways to act on it. */
export function NodeCard({ status: s }: { status: NetworkStatus }) {
  const { canWrite } = useAuth()
  const [editing, setEditing] = useState(false)
  const [leaving, setLeaving] = useState(false)
  const [sent, setSent] = useState(false)
  const submissions = useQuery({
    queryKey: networkKeys.submissions,
    queryFn: networkApi.submissions,
    enabled: canWrite,
  })
  const last = submissions.data?.find((x) => x.status === "sent")
  const standing = s.standing ? STANDING_TEXT[s.standing] : null
  const waiting = waitingText(s.waiting)
  const error = describeNetworkError(s.last_error_code)
  return (
    <FindingCard
      eyebrow={t("network_node_eyebrow")}
      finding={
        s.pseudonym
          ? t("network_node_finding_named", { name: s.pseudonym })
          : t("network_node_finding_fingerprint", { fingerprint: s.fingerprint ?? "" })
      }
      detail={t("network_node_detail")}
      action={
        canWrite ? (
          <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
            <Pencil aria-hidden />
            {t("common_edit")}
          </Button>
        ) : null
      }
    >
      <div className="space-y-5">
        {waiting || error ? (
          <p
            role="status"
            className="flex items-start gap-2 rounded-md border bg-bg px-3 py-2 text-sm text-fg-muted"
          >
            <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-sev-warning" />
            <span>{waiting ?? error}</span>
          </p>
        ) : null}
        <dl className="grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label={t("network_node_field_number")}>
            <span className="font-mono text-xs">{s.fingerprint ?? "–"}</span>
          </Field>
          <Field label={t("network_node_field_pseudonym")}>
            {s.pseudonym ?? <span className="text-fg-muted">{t("common_none")}</span>}
          </Field>
          <Field label={t("network_node_field_country")}>
            {s.country ? (
              <span className="inline-flex items-center gap-2">
                <CountryFlag code={s.country} showName />
                <span className="text-xs text-fg-muted">
                  {s.show_country
                    ? t("network_node_country_shown")
                    : t("network_node_country_hidden")}
                </span>
              </span>
            ) : (
              <span className="text-fg-muted">{t("common_none")}</span>
            )}
          </Field>
          <Field label={t("network_node_field_since")}>{formatDay(s.enrolled_day, true)}</Field>
          <Field label={t("network_node_field_eligibility")}>{eligibilityText(s)}</Field>
          <Field label={t("network_node_field_standing")}>
            {standing ? (
              <>
                <span className="font-medium">{standing.label}</span>
                <span className="block text-xs text-fg-muted">{standing.sentence}</span>
              </>
            ) : (
              "–"
            )}
          </Field>
          <Field label={t("network_node_field_last_batch")} className="sm:col-span-2 lg:col-span-3">
            {s.last_submit_day ? (
              <>
                {formatDay(s.last_submit_day, true)}
                {last ? (
                  <span className="text-fg-muted">
                    {" "}
                    ·{" "}
                    {Object.entries(last.counts)
                      .filter(([, n]) => n > 0)
                      .map(([k, n]) => `${formatNumber(n)} ${k}`)
                      .join(", ")}
                  </span>
                ) : null}
              </>
            ) : (
              <span className="text-fg-muted">{t("network_node_nothing_sent")}</span>
            )}
          </Field>
        </dl>
        <div className="flex flex-wrap items-center gap-2 border-t pt-4">
          {canWrite ? (
            <Button variant="outline" size="sm" onClick={() => setSent(true)}>
              <FileJson aria-hidden />
              {t("network_node_see_sent")}
            </Button>
          ) : null}
          {canWrite ? (
            // Outlined, never red: leaving is a normal choice, not a danger.
            <Button
              variant="outline"
              size="sm"
              onClick={() => setLeaving(true)}
              className="ml-auto"
            >
              <LogOut aria-hidden />
              {t("network_leave_button")}
            </Button>
          ) : (
            <p className="text-xs text-fg-muted">{t("network_message_forbidden")}</p>
          )}
        </div>
      </div>
      <ProfileDialog open={editing} onOpenChange={setEditing} status={s} />
      <LeaveDialog open={leaving} onOpenChange={setLeaving} />
      <SentDrawer open={sent} onOpenChange={setSent} />
    </FindingCard>
  )
}
