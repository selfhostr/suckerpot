/**
 * The running version and the update check (M28, docs/dev/design/m28.md section 7): shape of
 * `GET /api/v1/version` and the words for each check state.
 */
import { t } from "@/i18n"
import { getJson } from "./api"

export type VersionCheck = "ok" | "off" | "no_egress" | "error" | "pending"

export interface VersionInfo {
  version: string
  build: "image" | "source"
  commit: string
  latest: string | null
  update_available: boolean
  checked_at: string | null
  check: VersionCheck
  release_url: string | null
}

export const versionKeys = { current: ["version"] as const }

export const versionApi = {
  get: () => getJson<VersionInfo>("/version"),
}

/** `dev` or a `git describe` string with a `-N-g<sha>` suffix: never claims an update. */
export function isDevBuild(version: string): boolean {
  return version === "dev" || /-\d+-g[0-9a-f]+/.test(version) || version.endsWith("-dirty")
}

/** Update available, and only for a release build. */
export function hasUpdate(v: VersionInfo | undefined): v is VersionInfo & { latest: string } {
  return !!v && v.update_available && !!v.latest && !isDevBuild(v.version)
}

/** A release link is shown only when it is plain https. */
export function safeReleaseUrl(url: string | null | undefined): string | null {
  return url && /^https:\/\/[^\s]+$/.test(url) ? url : null
}

/** One sentence for the Updates card. */
export function describeVersion(v: VersionInfo): string {
  const version = v.version
  if (isDevBuild(version)) return t("page_version_dev_build", { version })
  if (hasUpdate(v)) return t("page_version_update_available", { latest: v.latest, version })
  if (v.check === "off") return t("page_version_checks_off", { version })
  if (v.check === "no_egress") return t("page_version_check_paused", { version })
  if (v.check === "error") return t("page_version_check_failed", { version })
  if (v.check === "pending") return t("page_version_check_pending", { version })
  return t("page_version_up_to_date", { version })
}
