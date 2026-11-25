import { Check, Copy, TriangleAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { useCopy } from "@/hooks/use-copy"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"

export interface Reveal {
  username: string
  display_name: string
  temporary: string
  kind: "created" | "reset"
}

/**
 * Shows a temporary password once. It exists only in this component's props: closing the dialog
 * drops it, and the server stores nothing but its hash. Clicking outside or pressing Escape does
 * not close it, so it cannot vanish before it was copied.
 */
export function TemporaryPasswordDialog({
  reveal,
  onClose,
}: {
  reveal: Reveal | null
  onClose: () => void
}) {
  const { copied, copy } = useCopy()
  return (
    <Dialog open={reveal !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        className="min-w-0 bg-popover [&>*]:min-w-0"
        onInteractOutside={(e) => e.preventDefault()}
        onEscapeKeyDown={(e) => e.preventDefault()}
      >
        {reveal ? (
          <>
            <DialogHeader className="min-w-0 text-left">
              <DialogTitle>
                {reveal.kind === "created"
                  ? t("users_temp_created", { name: reveal.display_name })
                  : t("users_temp_reset", { name: reveal.display_name })}
              </DialogTitle>
              <DialogDescription>
                {tNodes(
                  "users_temp_description",
                  {},
                  { username: <code className="font-mono text-fg">{reveal.username}</code> },
                )}
              </DialogDescription>
            </DialogHeader>
            <div className="min-w-0 space-y-3">
              <div className="flex items-center gap-2 rounded-md border bg-bg py-1.5 pr-1.5 pl-3">
                <code
                  data-testid="temporary-password"
                  className="min-w-0 flex-1 font-mono text-base break-all text-fg select-all"
                >
                  {reveal.temporary}
                </code>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => void copy(reveal.temporary)}
                >
                  {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
                  {copied ? t("common_copied") : t("common_copy")}
                </Button>
              </div>
              <p
                role="note"
                className="flex items-start gap-2 rounded-md border border-border-strong bg-surface-raised px-3 py-2 text-sm text-fg"
              >
                <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-sev-warning" />
                <span>
                  <strong className="font-medium">{t("users_temp_once")}</strong>{" "}
                  {t("users_temp_once_detail")}
                </span>
              </p>
            </div>
            <DialogFooter>
              <Button type="button" onClick={onClose}>
                {t("users_temp_done")}
              </Button>
            </DialogFooter>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
