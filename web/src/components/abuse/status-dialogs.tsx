import { useId, useState, type SyntheticEvent } from "react"
import { Field, FormError } from "@/components/form-parts"
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
import { t } from "@/i18n"

/** `datetime-local` wants "YYYY-MM-DDTHH:mm" in the browser's own time zone. */
function localInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

interface DialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Resolves when done; a rejection is shown in the dialog. */
  run: (arg: string) => Promise<void>
  describe: (e: unknown) => string
}

/** "Mark as sent": when did you send it? Defaults to now, can be earlier, never later. */
export function MarkSentDialog({ open, onOpenChange, run, describe }: DialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        {open ? <SentForm {...{ onOpenChange, run, describe }} /> : null}
      </DialogContent>
    </Dialog>
  )
}

function SentForm({ onOpenChange, run, describe }: Omit<DialogProps, "open">) {
  const id = useId()
  const [now] = useState(() => new Date())
  const [value, setValue] = useState(localInput(now))
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function submit() {
    const when = new Date(value)
    if (Number.isNaN(when.getTime()) || when.getTime() > Date.now() + 60_000) {
      setError(t("abuse_dialog_sent_time_error"))
      return
    }
    setPending(true)
    setError(null)
    try {
      await run(when.toISOString())
      onOpenChange(false)
    } catch (e) {
      setError(describe(e))
    } finally {
      setPending(false)
    }
  }

  return (
    <form
      noValidate
      className="flex flex-col gap-4"
      onSubmit={(e: SyntheticEvent) => {
        e.preventDefault()
        void submit()
      }}
    >
      <DialogHeader className="text-left">
        <DialogTitle>{t("abuse_dialog_sent_title")}</DialogTitle>
        <DialogDescription>
          {t("abuse_dialog_sent_description")}
        </DialogDescription>
      </DialogHeader>
      <Field id={id} label={t("abuse_dialog_sent_at")} hint={t("abuse_dialog_sent_at_hint")}>
        <Input
          id={id}
          type="datetime-local"
          value={value}
          max={localInput(now)}
          onChange={(e) => setValue(e.target.value)}
        />
      </Field>
      <FormError id={`${id}-err`} message={error} />
      <DialogFooter>
        <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
          {t("common_cancel")}
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? t("abuse_dialog_saving") : t("abuse_dialog_mark_sent")}
        </Button>
      </DialogFooter>
    </form>
  )
}

interface ConfirmProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: string
  confirmLabel: string
  run: () => Promise<void>
  describe: (e: unknown) => string
  /** Extra content under the description, e.g. the list of what is about to be sent. */
  children?: React.ReactNode
}

/** A plain confirmation for a step that is hard to undo (discard). */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  run,
  describe,
  children,
}: ConfirmProps) {
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const errId = useId()
  async function go() {
    setPending(true)
    setError(null)
    try {
      await run()
      onOpenChange(false)
    } catch (e) {
      setError(describe(e))
    } finally {
      setPending(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader className="text-left">
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        {children}
        <FormError id={errId} message={error} />
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common_cancel")}
          </Button>
          <Button disabled={pending} onClick={() => void go()}>
            {pending ? t("abuse_dialog_working") : confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
