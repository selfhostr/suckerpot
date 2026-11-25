import { useId } from "react"
import { Trash2 } from "lucide-react"
import { networkApi } from "@/lib/network"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { markLeft, useRefreshNetwork } from "./use-network"
import { t } from "@/i18n"

/** Leaving is one click plus the password. The text says what is deleted, and where. */
export function LeaveDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const refresh = useRefreshNetwork()
  return (
    <AdminActionDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t("network_leave_title")}
      description={t("network_leave_description")}
      hint={t("network_leave_password_hint")}
      confirmLabel={t("network_leave_button")}
      pendingLabel={t("network_leave_pending")}
      run={async (password) => {
        await networkApi.leave(password)
      }}
      onDone={() => {
        markLeft()
        void refresh()
      }}
    >
      <div className="grid gap-3 text-sm sm:grid-cols-2">
        <DeletedList
          title={t("network_leave_local_title")}
          items={[
            t("network_leave_local_key"),
            t("network_leave_local_pseudonym"),
            t("network_leave_local_batches"),
            t("network_leave_local_figures"),
          ]}
        />
        <DeletedList
          title={t("network_leave_hub_title")}
          items={[
            t("network_leave_hub_node"),
            t("network_leave_hub_sent"),
            t("network_leave_hub_checks"),
            t("network_leave_hub_entry"),
          ]}
        />
      </div>
      <p className="text-xs text-fg-muted">{t("network_leave_retry_note")}</p>
    </AdminActionDialog>
  )
}

function DeletedList({ title, items }: { title: string; items: readonly string[] }) {
  const id = useId()
  return (
    <div className="rounded-md border p-3">
      <p id={id} className="mb-1.5 text-xs font-medium text-fg">
        {title}
      </p>
      <ul aria-labelledby={id} className="space-y-1 text-xs text-fg-muted">
        {items.map((i) => (
          <li key={i} className="flex items-start gap-2">
            <Trash2 aria-hidden className="mt-0.5 size-3 shrink-0 text-fg-subtle" />
            {i}
          </li>
        ))}
      </ul>
    </div>
  )
}
