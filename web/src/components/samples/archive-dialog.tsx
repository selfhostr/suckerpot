import { Download } from "lucide-react"
import { useState } from "react"
import { t, tNodes } from "@/i18n"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { Button } from "@/components/ui/button"
import { saveBlob, samplesApi } from "@/lib/samples"

/**
 * Admin-only download of a sample as an encrypted zip. The dialog says what the file is and what
 * the archive password is, and asks for the administrator's own password again.
 */
export function ArchiveButton({ sha256 }: { sha256: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        <Download aria-hidden className="size-4" />
        {t("samples_archive_button")}
      </Button>
      <AdminActionDialog
        open={open}
        onOpenChange={setOpen}
        title={t("samples_archive_title")}
        description={
          tNodes(
            "samples_archive_description",
            {},
            { password: <code className="font-mono text-fg">infected</code> },
          )
        }
        hint={t("samples_download_hint")}
        confirmLabel={t("common_download")}
        pendingLabel={t("samples_preparing")}
        run={async (password) => {
          const blob = await samplesApi.archive(sha256, password)
          saveBlob(blob, `${sha256}.zip`)
        }}
        onDone={() => undefined}
      />
    </>
  )
}
