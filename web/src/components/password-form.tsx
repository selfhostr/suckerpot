import { useId, useRef, useState, type SyntheticEvent } from "react"
import { Field, FormError } from "@/components/form-parts"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { t } from "@/i18n"
import {
  changePasswordRequest,
  describePasswordError,
  MIN_PASSWORD_LENGTH,
  PasswordError,
  validateNewPassword,
} from "@/lib/auth-api"

interface ChangePasswordFormProps {
  username: string
  /** "Current password", or "Temporary password" on the first sign-in. */
  currentLabel?: string
  submitLabel?: string
  /** Buttons are laid out by the caller: a dialog footer or a full-width login-style button. */
  layout?: "dialog" | "page"
  onDone: () => void
  onCancel?: () => void
}

/**
 * Current password, new password twice. Lives only while its dialog or page is open, so nothing
 * typed is kept afterwards. The server applies the same rules again and also refuses passwords
 * that are too common.
 */
export function ChangePasswordForm({
  username,
  currentLabel = t("pwd_current"),
  submitLabel = t("pwd_change"),
  layout = "dialog",
  onDone,
  onCancel,
}: ChangePasswordFormProps) {
  const [current, setCurrent] = useState("")
  const [next, setNext] = useState("")
  const [again, setAgain] = useState("")
  const [errors, setErrors] = useState<{ current?: string; next?: string; again?: string }>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { current: useId(), next: useId(), again: useId(), err: useId() }
  const currentRef = useRef<HTMLInputElement>(null)
  const nextRef = useRef<HTMLInputElement>(null)

  async function submit() {
    if (pending) return
    setFormError(null)
    const found: typeof errors = {}
    if (!current) found.current = t("pwd_enter_current")
    const weak = validateNewPassword(next, username, current)
    if (weak) found.next = weak
    else if (again !== next) found.again = t("pwd_mismatch")
    setErrors(found)
    if (found.current) return currentRef.current?.focus()
    if (found.next) return nextRef.current?.focus()
    if (found.again) return
    setPending(true)
    try {
      await changePasswordRequest(current, next)
      onDone()
    } catch (e) {
      setCurrent("")
      if (e instanceof PasswordError && e.reason === "wrong-password") {
        setErrors({ current: describePasswordError(e) })
        currentRef.current?.focus()
      } else if (e instanceof PasswordError && e.reason === "weak") {
        setErrors({ next: describePasswordError(e) })
        nextRef.current?.focus()
      } else setFormError(describePasswordError(e))
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
      <Field id={ids.current} label={currentLabel} error={errors.current}>
        <Input
          id={ids.current}
          ref={currentRef}
          name="current-password"
          type="password"
          autoComplete="current-password"
          autoFocus
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          aria-invalid={errors.current ? true : undefined}
          aria-describedby={errors.current ? `${ids.current}-error` : undefined}
        />
      </Field>
      <Field
        id={ids.next}
        label={t("pwd_new")}
        hint={t("pwd_new_hint", { count: MIN_PASSWORD_LENGTH })}
        error={errors.next}
      >
        <Input
          id={ids.next}
          ref={nextRef}
          name="new-password"
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          aria-invalid={errors.next ? true : undefined}
          aria-describedby={errors.next ? `${ids.next}-error` : `${ids.next}-hint`}
        />
      </Field>
      <Field id={ids.again} label={t("pwd_repeat")} error={errors.again}>
        <Input
          id={ids.again}
          name="repeat-password"
          type="password"
          autoComplete="new-password"
          value={again}
          onChange={(e) => setAgain(e.target.value)}
          aria-invalid={errors.again ? true : undefined}
          aria-describedby={errors.again ? `${ids.again}-error` : undefined}
        />
      </Field>
      <FormError id={ids.err} message={formError} />
      {layout === "page" ? (
        <Button type="submit" size="lg" disabled={pending}>
          {pending ? t("pwd_saving") : submitLabel}
        </Button>
      ) : (
        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          {onCancel ? (
            <Button type="button" variant="outline" onClick={onCancel}>
              {t("common_cancel")}
            </Button>
          ) : null}
          <Button type="submit" disabled={pending}>
            {pending ? t("pwd_saving") : submitLabel}
          </Button>
        </div>
      )}
    </form>
  )
}
