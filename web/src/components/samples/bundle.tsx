import { Download, PackageCheck, PackagePlus, X } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
import { FindingCard } from "@/components/finding-card"
import { Button } from "@/components/ui/button"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import {
  BUNDLE_MAX,
  describeBundle,
  downloadBundle,
  sampleBundle,
  useSampleBundle,
} from "@/lib/sample-bundle"
import { saveBlob, shortHash } from "@/lib/samples"

/**
 * Adds a stored sample to the bundle, or takes it out. `icon` is the compact form for list rows;
 * the state is carried by the icon and the accessible name, never by colour alone.
 */
export function BundleToggle({ sha256, compact = false }: { sha256: string; compact?: boolean }) {
  const list = useSampleBundle()
  const inBundle = list.includes(sha256)
  const full = !inBundle && list.length >= BUNDLE_MAX
  const label = inBundle
    ? t("samples_bundle_remove")
    : full
      ? t("samples_bundle_full_max", { max: BUNDLE_MAX })
      : t("samples_bundle_add")
  const toggle = () => (inBundle ? sampleBundle.remove(sha256) : sampleBundle.add(sha256))
  const Icon = inBundle ? PackageCheck : PackagePlus
  if (compact)
    return (
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        aria-pressed={inBundle}
        aria-label={label}
        title={label}
        disabled={full}
        onClick={toggle}
        className={inBundle ? "bg-surface-hover text-fg" : "text-fg-subtle hover:text-fg"}
      >
        <Icon aria-hidden className="size-4" />
      </Button>
    )
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      aria-pressed={inBundle}
      disabled={full}
      onClick={toggle}
    >
      <Icon aria-hidden className="size-4" />
      {inBundle
        ? t("samples_bundle_in")
        : full
          ? t("samples_bundle_is_full")
          : t("samples_bundle_add")}
    </Button>
  )
}

/**
 * The bundle so far, with the download. Shown only while it holds something. The download asks
 * for the administrator's password again and explains the archive password.
 */
export function BundleCard({ className }: { className?: string }) {
  const list = useSampleBundle()
  const [open, setOpen] = useState(false)
  const [excluded, setExcluded] = useState<string[]>([])
  if (list.length === 0 && excluded.length === 0) return null
  return (
    <FindingCard
      className={className}
      eyebrow={t("samples_bundle_eyebrow")}
      finding={describeBundle(list.length)}
      detail={t("samples_bundle_detail")}
      action={
        list.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => setOpen(true)}>
              <Download aria-hidden className="size-4" />
              {t("samples_bundle_download")}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => sampleBundle.clear()}>
              {t("common_clear")}
            </Button>
          </div>
        ) : undefined
      }
      bodyClassName="px-0 sm:px-0 pb-1 sm:pb-1"
    >
      {excluded.length > 0 ? (
        <p role="status" className="border-t px-4 py-3 text-sm text-fg-muted sm:px-5">
          {tNodes(
            "samples_bundle_excluded",
            { count: excluded.length },
            {
              hashes: (
                <span className="font-mono text-xs text-fg">
                  {excluded.map((s) => `${shortHash(s)}…`).join(", ")}
                </span>
              ),
            },
          )}
        </p>
      ) : null}
      {list.length > 0 ? (
        <ul className="divide-y border-t" aria-label={t("samples_bundle_list_label")}>
          {list.map((sha) => (
            <li key={sha} className="flex items-center justify-between gap-3 px-4 py-2 sm:px-5">
              <Link
                to={`/malware/samples/${sha}`}
                title={sha}
                className="min-w-0 truncate font-mono text-xs text-fg-muted hover:text-fg hover:underline"
              >
                {sha}
              </Link>
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label={t("samples_bundle_remove_one", { hash: shortHash(sha) })}
                onClick={() => sampleBundle.remove(sha)}
              >
                <X aria-hidden />
              </Button>
            </li>
          ))}
        </ul>
      ) : null}
      <AdminActionDialog
        open={open}
        onOpenChange={setOpen}
        title={t("samples_bundle_dialog_title")}
        description={tNodes(
          "samples_bundle_dialog_description",
          { count: list.length },
          {
            password: <code className="font-mono text-fg">infected</code>,
            file: <code className="font-mono text-fg">hashes.csv</code>,
          },
        )}
        hint={t("samples_download_hint")}
        confirmLabel={t("common_download")}
        pendingLabel={t("samples_preparing")}
        run={async (password) => {
          const r = await downloadBundle(list, password)
          saveBlob(r.blob, r.filename)
          setExcluded(r.excluded)
        }}
        onDone={() => undefined}
      />
    </FindingCard>
  )
}
