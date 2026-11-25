import { ChangePasswordForm } from "@/components/password-form"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { t } from "@/i18n"

interface ChangePasswordDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  username: string
  onChanged?: () => void
}

export function ChangePasswordDialog({
  open,
  onOpenChange,
  username,
  onChanged,
}: ChangePasswordDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-popover">
        <DialogHeader className="text-left">
          <DialogTitle>{t("pwd_change_title")}</DialogTitle>
          <DialogDescription>{t("pwd_change_description")}</DialogDescription>
        </DialogHeader>
        <ChangePasswordForm
          username={username}
          onCancel={() => onOpenChange(false)}
          onDone={() => {
            onOpenChange(false)
            onChanged?.()
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
