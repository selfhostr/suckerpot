import { useId, useState, type ReactNode, type SyntheticEvent } from "react"
import { Field, FormError } from "@/components/form-parts"
import { t } from "@/i18n"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { describeUserError, UserError } from "@/lib/users"

interface FormProps {
  title: string
  description: ReactNode
  confirmLabel: string
  pendingLabel: string
  /** Hint under the password field. */
  hint?: string
  /** Extra fields above the password (a role picker, say). */
  children?: ReactNode
  /**
   * Focus the password on open (the default). A long form turns it off, so the dialog opens at its
   * top and the reader meets the text before the password.
   */
  focusPassword?: boolean
  /** Runs the change with the administrator's password; resolves when it went through. */
  run: (password: string) => Promise<void>
  /** Checks the extra fields first; a message stops the submit. */
  validate?: () => string | null
  onDone: () => void
  onCancel: () => void
}

/**
 * Every change to a user asks for the administrator's own password again. Lives only while the
 * dialog is open, so the typed password is dropped the moment it closes.
 */
function ActionForm({
  title,
  description,
  confirmLabel,
  pendingLabel,
  hint = t("users_dialog_hint"),
  children,
  focusPassword = true,
  run,
  validate,
  onDone,
  onCancel,
}: FormProps) {
  const [password, setPassword] = useState("")
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { pass: useId(), err: useId() }

  async function submit() {
    if (pending) return
    setPasswordError(null)
    setFormError(null)
    const problem = validate?.()
    if (problem) {
      setFormError(problem)
      return
    }
    if (!password) {
      setPasswordError(t("alerts_msg_password_required"))
      return
    }
    setPending(true)
    try {
      await run(password)
      onDone()
    } catch (e) {
      setPassword("")
      if (e instanceof UserError && e.reason === "wrong-password")
        setPasswordError(describeUserError(e))
      else setFormError(e instanceof UserError && e.detail ? e.detail : describeUserError(e))
    } finally {
      setPending(false)
    }
  }

  return (
    <form
      onSubmit={(event: SyntheticEvent) => {
        event.preventDefault()
        void submit()
      }}
      className="flex flex-col gap-4"
      noValidate
    >
      <DialogHeader className="text-left">
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>{description}</DialogDescription>
      </DialogHeader>
      {children}
      <Field
        id={ids.pass}
        label={t("channels_password")}
        hint={hint}
        error={passwordError ?? undefined}
      >
        <Input
          id={ids.pass}
          name="password"
          type="password"
          autoComplete="current-password"
          autoFocus={focusPassword}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-invalid={passwordError ? true : undefined}
          aria-describedby={passwordError ? `${ids.pass}-error` : `${ids.pass}-hint`}
        />
      </Field>
      <FormError id={ids.err} message={formError} />
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          {t("common_cancel")}
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? pendingLabel : confirmLabel}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function AdminActionDialog({
  open,
  onOpenChange,
  onDone,
  ...form
}: Omit<FormProps, "onCancel" | "onDone"> & {
  open: boolean
  onOpenChange: (open: boolean) => void
  onDone: () => void
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {/* A long form scrolls inside the dialog, so its title and buttons stay reachable. */}
      <DialogContent className="max-h-[90dvh] overflow-y-auto bg-popover">
        <ActionForm
          {...form}
          onCancel={() => onOpenChange(false)}
          onDone={() => {
            onOpenChange(false)
            onDone()
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
