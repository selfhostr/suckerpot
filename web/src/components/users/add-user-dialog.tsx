import { useId, useState, type ReactNode, type SyntheticEvent } from "react"
import { Field, FormError } from "@/components/form-parts"
import { t } from "@/i18n"
import { SegmentedControl } from "@/components/segmented-control"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import type { Role } from "@/lib/auth-api"
import {
  createUser,
  describeUserError,
  ROLE_HINT,
  ROLE_OPTIONS,
  UserError,
  validateNewUser,
  type NewUserField,
} from "@/lib/users"
import type { Reveal } from "./temporary-password-dialog"

function AddUserForm({
  onCreated,
  onCancel,
}: {
  onCreated: (reveal: Reveal) => void
  onCancel: () => void
}) {
  const [username, setUsername] = useState("")
  const [displayName, setDisplayName] = useState("")
  const [role, setRole] = useState<Role>("viewer")
  const [password, setPassword] = useState("")
  const [errors, setErrors] = useState<Partial<Record<NewUserField | "password", string>>>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { user: useId(), name: useId(), pass: useId(), err: useId() }

  async function submit() {
    if (pending) return
    setFormError(null)
    const found: typeof errors = validateNewUser(username, displayName)
    if (!password) found.password = t("alerts_msg_password_required")
    setErrors(found)
    if (Object.keys(found).length > 0) return
    setPending(true)
    try {
      const { temporary } = await createUser({ username, displayName, role }, password)
      onCreated({
        username,
        display_name: displayName.trim(),
        temporary,
        kind: "created",
      })
    } catch (e) {
      setPassword("")
      if (e instanceof UserError && e.reason === "wrong-password")
        setErrors({ password: describeUserError(e) })
      else if (e instanceof UserError && e.reason === "taken")
        setErrors({ username: describeUserError(e) })
      else setFormError(describeUserError(e))
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
      autoComplete="off"
    >
      <DialogHeader className="text-left">
        <DialogTitle>{t("users_add_title")}</DialogTitle>
        <DialogDescription>
          {t("users_add_description")}
        </DialogDescription>
      </DialogHeader>
      <Field
        id={ids.user}
        label={t("users_username")}
        hint={t("users_username_hint")}
        error={errors.username}
      >
        <Input
          id={ids.user}
          name="new-username"
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          autoFocus
          value={username}
          onChange={(e) => setUsername(e.target.value.trim())}
          aria-invalid={errors.username ? true : undefined}
          aria-describedby={errors.username ? `${ids.user}-error` : `${ids.user}-hint`}
          className="font-mono"
        />
      </Field>
      <Field id={ids.name} label={t("channels_name")} error={errors.displayName}>
        <Input
          id={ids.name}
          name="new-display-name"
          autoComplete="off"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          aria-invalid={errors.displayName ? true : undefined}
          aria-describedby={errors.displayName ? `${ids.name}-error` : undefined}
        />
      </Field>
      <div className="flex flex-col gap-1.5">
        <span className="text-sm font-medium text-fg">{t("users_role")}</span>
        <SegmentedControl
          size="form"
          label={t("users_role")}
          value={role}
          onChange={setRole}
          options={ROLE_OPTIONS}
          className="self-start"
        />
        <p className="text-xs text-fg-muted">{ROLE_HINT[role]}</p>
      </div>
      <Field
        id={ids.pass}
        label={t("channels_password")}
        hint={t("users_add_password_hint")}
        error={errors.password}
      >
        <Input
          id={ids.pass}
          name="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-invalid={errors.password ? true : undefined}
          aria-describedby={errors.password ? `${ids.pass}-error` : `${ids.pass}-hint`}
        />
      </Field>
      <FormError id={ids.err} message={formError} />
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          {t("common_cancel")}
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? t("users_creating") : t("users_create")}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function AddUserDialog({
  trigger,
  onCreated,
}: {
  trigger: ReactNode
  onCreated: (reveal: Reveal) => void
}) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="bg-popover">
        <AddUserForm
          onCancel={() => setOpen(false)}
          onCreated={(reveal) => {
            setOpen(false)
            onCreated(reveal)
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
