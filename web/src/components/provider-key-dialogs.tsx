import { useId, useRef, useState, type ReactNode, type SyntheticEvent } from "react"
import { Field, FormError } from "@/components/form-parts"
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
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import {
  describeKeyError,
  KEY_MESSAGES,
  KeyError,
  PROVIDER_NAMES,
  removeProviderKey,
  setProviderKey,
  validateKeyInput,
  type KeyField,
} from "@/lib/provider-keys"
import type { ProviderId } from "@/lib/settings"

interface FormProps {
  provider: ProviderId
  onDone: () => void
  onCancel: () => void
}

/**
 * Lives only while the dialog is open, so the typed key and password are dropped from memory
 * the moment it closes. Nothing is stored in the URL, in storage or in the query cache.
 */
function SetKeyForm({ provider, onDone, onCancel, replacing }: FormProps & { replacing: boolean }) {
  const name = PROVIDER_NAMES[provider]
  const [accountId, setAccountId] = useState("")
  const [key, setKey] = useState("")
  const [password, setPassword] = useState("")
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<KeyField, string>>>({})
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { account: useId(), key: useId(), pass: useId(), err: useId() }
  const passRef = useRef<HTMLInputElement>(null)

  async function submit() {
    if (pending) return
    const errors = validateKeyInput(provider, { key, accountId })
    setFieldErrors(errors)
    setFormError(null)
    setPasswordError(null)
    if (Object.keys(errors).length > 0) return
    if (!password) {
      setPasswordError(t("alerts_msg_password_required"))
      passRef.current?.focus()
      return
    }
    setPending(true)
    try {
      await setProviderKey(provider, { key, accountId }, password)
      onDone()
    } catch (e) {
      setPassword("")
      if (e instanceof KeyError && e.reason === "wrong-password") {
        setPasswordError(KEY_MESSAGES["wrong-password"])
        passRef.current?.focus()
      } else if (e instanceof KeyError && e.reason === "invalid-key") {
        setFieldErrors({ key: describeKeyError(e) })
      } else {
        setFormError(describeKeyError(e))
      }
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
        <DialogTitle>
          {replacing
            ? t("providerkeys_dialog_replace_title", { name })
            : t("providerkeys_dialog_set_title", { name })}
        </DialogTitle>
        <DialogDescription>
          {t("providerkeys_dialog_description", { replacing: replacing ? "yes" : "no" })}
        </DialogDescription>
      </DialogHeader>

      {provider === "maxmind" ? (
        <Field
          id={ids.account}
          label={t("providerkeys_account_id")}
          hint={t("providerkeys_account_id_hint")}
          error={fieldErrors.accountId}
        >
          <Input
            id={ids.account}
            name="maxmind-account-id"
            inputMode="numeric"
            autoComplete="off"
            autoFocus
            spellCheck={false}
            value={accountId}
            onChange={(e) => setAccountId(e.target.value.trim())}
            aria-invalid={fieldErrors.accountId ? true : undefined}
            aria-describedby={
              fieldErrors.accountId ? `${ids.account}-error` : `${ids.account}-hint`
            }
            className="font-mono"
          />
        </Field>
      ) : null}

      <Field
        id={ids.key}
        label={provider === "maxmind" ? t("providerkeys_licence_key") : t("providerkeys_api_key")}
        error={fieldErrors.key}
      >
        <Input
          id={ids.key}
          name="provider-secret"
          type="password"
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          data-1p-ignore
          data-lpignore="true"
          autoFocus={provider !== "maxmind"}
          value={key}
          onChange={(e) => setKey(e.target.value.trim())}
          aria-invalid={fieldErrors.key ? true : undefined}
          aria-describedby={fieldErrors.key ? `${ids.key}-error` : undefined}
          className="font-mono"
        />
      </Field>

      <Field
        id={ids.pass}
        label={t("channels_password")}
        hint={t("providerkeys_password_hint")}
        error={passwordError ?? undefined}
      >
        <Input
          id={ids.pass}
          ref={passRef}
          name="password"
          type="password"
          autoComplete="current-password"
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
          {pending ? t("setup_saving") : t("providerkeys_save")}
        </Button>
      </DialogFooter>
    </form>
  )
}

function RemoveKeyForm({ provider, onDone, onCancel }: FormProps) {
  const name = PROVIDER_NAMES[provider]
  const [password, setPassword] = useState("")
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { pass: useId(), err: useId() }

  async function submit() {
    if (pending) return
    setPasswordError(null)
    setFormError(null)
    if (!password) {
      setPasswordError(t("alerts_msg_password_required"))
      return
    }
    setPending(true)
    try {
      await removeProviderKey(provider, password)
      onDone()
    } catch (e) {
      setPassword("")
      if (e instanceof KeyError && e.reason === "wrong-password")
        setPasswordError(KEY_MESSAGES["wrong-password"])
      else setFormError(describeKeyError(e))
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
        <DialogTitle>{t("providerkeys_remove_title", { name })}</DialogTitle>
        <DialogDescription>
          {tNodes(
            "providerkeys_remove_description",
            { name },
            { env: <code className="font-mono">.env</code> },
          )}
        </DialogDescription>
      </DialogHeader>
      <Field
        id={ids.pass}
        label={t("channels_password")}
        hint={t("providerkeys_password_hint")}
        error={passwordError ?? undefined}
      >
        <Input
          id={ids.pass}
          name="password"
          type="password"
          autoComplete="current-password"
          autoFocus
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
          {pending ? t("vpn_removing") : t("providerkeys_remove")}
        </Button>
      </DialogFooter>
    </form>
  )
}

interface DialogProps {
  provider: ProviderId
  trigger: ReactNode
  onDone: () => void
}

export function SetKeyDialog({
  provider,
  trigger,
  onDone,
  replacing,
}: DialogProps & { replacing: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="bg-popover">
        <SetKeyForm
          provider={provider}
          replacing={replacing}
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

export function RemoveKeyDialog({ provider, trigger, onDone }: DialogProps) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="bg-popover">
        <RemoveKeyForm
          provider={provider}
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
