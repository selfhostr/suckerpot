import { Link } from "react-router"
import { useVersion } from "@/hooks/use-version"
import { t } from "@/i18n"
import { cn } from "@/lib/utils"
import { hasUpdate } from "@/lib/version"

const MOCK = import.meta.env.VITE_MOCK === "1"

/**
 * The running version, one small line at the foot of every page, right-aligned and in the flow
 * so it never covers content (as in dumbmonit). Discreet on purpose: it is for a bug report, not
 * a headline. It leads to Settings, where the Updates card says more; a dot marks an update. Mock
 * builds say beside it that nothing is real traffic.
 */
export function VersionFooter({ className }: { className?: string }) {
  const version = useVersion().data
  if (!version && !MOCK) return null
  const update = hasUpdate(version)
  return (
    <footer
      className={cn(
        "flex flex-wrap items-center justify-end gap-x-3 gap-y-1 text-2xs text-fg-subtle",
        className,
      )}
    >
      {MOCK ? <span>{t("shell_mock_notice")}</span> : null}
      {version ? (
        <Link
          to="/settings"
          title={
            update
              ? t("shell_version_update_title", {
                  version: version.version,
                  latest: version.latest,
                })
              : version.commit
                ? t("shell_version_commit_title", {
                    version: version.version,
                    commit: version.commit,
                  })
                : t("shell_version_title", { version: version.version })
          }
          className="inline-flex items-center gap-1.5 rounded-sm font-medium tabular-nums transition-colors duration-150 hover:text-fg-muted focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          {update ? <span aria-hidden className="size-1.5 rounded-full bg-primary" /> : null}
          <span>
            <span className="sr-only">SuckerPot </span>
            {version.version}
            {update ? <span className="sr-only">{t("sidebar_update_available_sr")}</span> : null}
          </span>
        </Link>
      ) : null}
    </footer>
  )
}
