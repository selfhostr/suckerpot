import { useAuth } from "@/app/auth"
import { t } from "@/i18n"
import { useVersion } from "@/hooks/use-version"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonText } from "@/components/skeletons"
import { describeVersion, hasUpdate, safeReleaseUrl, type VersionInfo } from "@/lib/version"
import { setCommand } from "@/lib/setup-wizard"
import { CommandBox } from "./command-box"

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 space-y-1">
      <dt className="text-xs text-fg-muted">{label}</dt>
      <dd className="text-sm text-fg tabular-nums">{children}</dd>
    </div>
  )
}

function Details({ v }: { v: VersionInfo }) {
  const url = safeReleaseUrl(v.release_url)
  return (
    <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-4">
      <Row label={t("setup_updates_running")}>
        <span className="font-mono text-xs">{v.version}</span>
        <span className="ml-2 text-xs text-fg-muted">
          {v.build === "image" ? t("setup_updates_image") : t("setup_updates_source")}
        </span>
      </Row>
      <Row label={t("setup_updates_latest")}>
        {v.latest ? <span className="font-mono text-xs">{v.latest}</span> : t("setup_updates_not_known")}
      </Row>
      <Row label={t("setup_updates_checked")}>
        {v.checked_at ? <RelativeTime iso={v.checked_at} /> : t("setup_updates_never")}
      </Row>
      <Row label={t("setup_updates_notes")}>
        {url && hasUpdate(v) ? (
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-sm underline underline-offset-4 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
          >
            {t("setup_updates_open")}
          </a>
        ) : (
          t("setup_updates_nothing_new")
        )}
      </Row>
    </dl>
  )
}

/** Settings, General tab: the running version and the update check. Viewers do not get the command. */
export function UpdatesCard() {
  const { canWrite } = useAuth()
  const q = useVersion()
  const v = q.data
  return (
    <FindingCard
      eyebrow={t("setup_updates_title")}
      finding={
        v
          ? describeVersion(v)
          : q.isError
            ? t("setup_updates_unavailable")
            : t("setup_updates_checking")
      }
      detail={t("setup_updates_detail")}
    >
      {v ? (
        <div className="space-y-4">
          <Details v={v} />
          {canWrite && hasUpdate(v) ? (
            <CommandBox
              command="just update"
              label={t("setup_updates_command_label")}
              hint={t("setup_updates_command_hint")}
            />
          ) : null}
          {canWrite && v.check === "off" ? (
            <CommandBox
              command={setCommand("UPDATE_CHECK_ENABLED", "true")}
              label={t("setup_updates_check_label")}
            />
          ) : null}
        </div>
      ) : q.isPending ? (
        <SkeletonText lines={2} />
      ) : null}
    </FindingCard>
  )
}
