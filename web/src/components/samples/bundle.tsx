import { Download, PackageCheck, PackagePlus, X } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
import { FindingCard } from "@/components/finding-card"
import { Button } from "@/components/ui/button"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { plural } from "@/lib/format"
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
    ? "Remove from sample bundle"
    : full
      ? `Sample bundle is full (${BUNDLE_MAX})`
      : "Add to sample bundle"
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
      {inBundle ? "In sample bundle" : full ? "Sample bundle is full" : "Add to sample bundle"}
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
      eyebrow="Sample bundle"
      finding={describeBundle(list.length)}
      detail="One encrypted zip for a public malware repository. Nothing is uploaded from here: you upload the file yourself."
      action={
        list.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => setOpen(true)}>
              <Download aria-hidden className="size-4" />
              Download bundle
            </Button>
            <Button variant="ghost" size="sm" onClick={() => sampleBundle.clear()}>
              Clear
            </Button>
          </div>
        ) : undefined
      }
      bodyClassName="px-0 sm:px-0 pb-1 sm:pb-1"
    >
      {excluded.length > 0 ? (
        <p role="status" className="border-t px-4 py-3 text-sm text-fg-muted sm:px-5">
          The identity check left {plural(excluded.length, "sample")} out of the last download,
          because {excluded.length === 1 ? "it contains" : "they contain"} something that points
          back to you:{" "}
          <span className="font-mono text-xs text-fg">
            {excluded.map((s) => `${shortHash(s)}…`).join(", ")}
          </span>
          .
        </p>
      ) : null}
      {list.length > 0 ? (
        <ul className="divide-y border-t" aria-label="Samples in the bundle">
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
                aria-label={`Remove ${shortHash(sha)} from the bundle`}
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
        title="Download the sample bundle"
        description={
          <>
            {plural(list.length, "live malware sample")} in one encrypted zip with the password{" "}
            <code className="font-mono text-fg">infected</code>, the usual convention of public
            malware repositories, so antivirus tools do not open it by accident. A{" "}
            <code className="font-mono text-fg">hashes.csv</code> lists every file. Samples that
            contain something pointing back to you are left out. The download is recorded in the
            audit log.
          </>
        }
        hint="Downloads ask for your own dashboard password again."
        confirmLabel="Download"
        pendingLabel="Preparing…"
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
