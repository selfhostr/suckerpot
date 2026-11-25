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
import { Switch } from "@/components/ui/switch"
import {
  AlertError,
  changeChannelTarget,
  createChannel,
  KIND_OPTIONS,
  TARGET_LABEL,
  type AlertChannel,
  type ChannelKind,
} from "@/lib/alerts"

type Errors = Partial<Record<"name" | "target" | "password", string>>

/**
 * Lives only while the dialog is open, so the typed address and password are dropped from memory
 * the moment it closes. Nothing is stored in the URL, in storage or in the query cache.
 */
function AddChannelForm({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [kind, setKind] = useState<ChannelKind>("discord")
  const [name, setName] = useState("")
  const [target, setTarget] = useState("")
  const [maskIps, setMaskIps] = useState(true)
  const [password, setPassword] = useState("")
  const [errors, setErrors] = useState<Errors>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { name: useId(), target: useId(), mask: useId(), pass: useId(), err: useId() }
  const info = TARGET_LABEL[kind]

  async function submit() {
    if (pending) return
    setFormError(null)
    const found: Errors = {}
    if (!name.trim()) found.name = t("channels_error_name")
    if (!target.trim()) found.target = t("channels_error_target", { kind })
    if (!password) found.password = t("alerts_msg_password_required")
    setErrors(found)
    if (Object.keys(found).length > 0) return
    setPending(true)
    try {
      await createChannel({ kind, name, target, maskIps }, password)
      onDone()
    } catch (e) {
      setPassword("")
      const err = e instanceof AlertError ? e : null
      if (err?.reason === "wrong-password") setErrors({ password: err.message })
      else if (err?.reason === "invalid-target") setErrors({ target: err.message })
      else setFormError(err?.message ?? t("channels_error_save"))
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
        <DialogTitle>{t("setup_alerts_add")}</DialogTitle>
        <DialogDescription>{t("channels_add_description")}</DialogDescription>
      </DialogHeader>

      <div className="flex flex-col gap-1.5">
        <span className="text-sm font-medium text-fg">{t("channels_where")}</span>
        <SegmentedControl
          size="form"
          label={t("channels_type_label")}
          value={kind}
          onChange={(next) => {
            setKind(next)
            setErrors({})
          }}
          options={KIND_OPTIONS}
          className="self-start"
        />
      </div>

      <Field
        id={ids.name}
        label={t("channels_name")}
        hint={t("channels_name_hint")}
        error={errors.name}
      >
        <Input
          id={ids.name}
          name="channel-name"
          autoComplete="off"
          maxLength={64}
          value={name}
          onChange={(e) => setName(e.target.value)}
          aria-invalid={errors.name ? true : undefined}
          aria-describedby={errors.name ? `${ids.name}-error` : `${ids.name}-hint`}
        />
      </Field>

      <Field id={ids.target} label={info.label} hint={info.hint} error={errors.target}>
        <Input
          id={ids.target}
          name="channel-target"
          type={kind === "email" ? "email" : "password"}
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          data-1p-ignore
          data-lpignore="true"
          placeholder={info.example}
          value={target}
          onChange={(e) => setTarget(e.target.value.trim())}
          aria-invalid={errors.target ? true : undefined}
          aria-describedby={errors.target ? `${ids.target}-error` : `${ids.target}-hint`}
          className="font-mono"
        />
      </Field>

      <div className="flex items-start gap-3">
        <Switch id={ids.mask} checked={maskIps} onCheckedChange={setMaskIps} className="mt-0.5" />
        <label htmlFor={ids.mask} className="text-sm text-fg">
          {t("channels_mask")}
          <span className="block text-xs text-fg-muted">{t("channels_mask_hint")}</span>
        </label>
      </div>

      <Field
        id={ids.pass}
        label={t("channels_password")}
        hint={t("channels_password_hint")}
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
          {pending ? t("setup_saving") : t("channels_add_submit")}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function AddChannelDialog({ trigger, onDone }: { trigger: ReactNode; onDone: () => void }) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="bg-popover normal-nums">
        <AddChannelForm
          onCancel={() => setOpen(false)}
          onDone={() => {
            setOpen(false)
            onDone()
          }}
        />
      </DialogContent>
    </Dialog>
  )
}

function ChangeTargetForm({
  channel,
  onDone,
  onCancel,
}: {
  channel: AlertChannel
  onDone: () => void
  onCancel: () => void
}) {
  const [target, setTarget] = useState("")
  const [password, setPassword] = useState("")
  const [errors, setErrors] = useState<Errors>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { target: useId(), pass: useId(), err: useId() }
  const info = TARGET_LABEL[channel.kind]

  async function submit() {
    if (pending) return
    setFormError(null)
    const found: Errors = {}
    if (!target.trim()) found.target = t("channels_error_new_target", { kind: channel.kind })
    if (!password) found.password = t("alerts_msg_password_required")
    setErrors(found)
    if (Object.keys(found).length > 0) return
    setPending(true)
    try {
      await changeChannelTarget(channel.id, target, password)
      onDone()
    } catch (e) {
      setPassword("")
      const err = e instanceof AlertError ? e : null
      if (err?.reason === "wrong-password") setErrors({ password: err.message })
      else if (err?.reason === "invalid-target") setErrors({ target: err.message })
      else setFormError(err?.message ?? t("channels_error_save_address"))
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
        <DialogTitle>{t("channels_change_title", { name: channel.name })}</DialogTitle>
        <DialogDescription>
          {t("channels_change_description", { hint: channel.target_hint })}
        </DialogDescription>
      </DialogHeader>
      <Field
        id={ids.target}
        label={t("channels_new_target", { kind: channel.kind })}
        hint={info.hint}
        error={errors.target}
      >
        <Input
          id={ids.target}
          name="channel-target"
          type={channel.kind === "email" ? "email" : "password"}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          autoFocus
          data-1p-ignore
          data-lpignore="true"
          placeholder={info.example}
          value={target}
          onChange={(e) => setTarget(e.target.value.trim())}
          aria-invalid={errors.target ? true : undefined}
          aria-describedby={errors.target ? `${ids.target}-error` : `${ids.target}-hint`}
          className="font-mono"
        />
      </Field>
      <Field id={ids.pass} label={t("channels_password")} error={errors.password}>
        <Input
          id={ids.pass}
          name="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-invalid={errors.password ? true : undefined}
          aria-describedby={errors.password ? `${ids.pass}-error` : undefined}
        />
      </Field>
      <FormError id={ids.err} message={formError} />
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          {t("common_cancel")}
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? t("setup_saving") : t("channels_save_address")}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function ChangeTargetDialog({
  channel,
  open,
  onOpenChange,
  onDone,
}: {
  channel: AlertChannel
  open: boolean
  onOpenChange: (open: boolean) => void
  onDone: () => void
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-popover normal-nums">
        <ChangeTargetForm
          channel={channel}
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
