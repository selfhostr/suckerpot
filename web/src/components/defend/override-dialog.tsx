import { useQueryClient } from "@tanstack/react-query"
import { useId, useState, type SyntheticEvent } from "react"
import { t } from "@/i18n"
import { Field, FormError } from "@/components/form-parts"
import { SegmentedControl } from "@/components/segmented-control"
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
import {
  BLOCK_KINDS,
  classifyFailure,
  createOverride,
  describeDefendError,
  KIND_META,
  type BlockKind,
  type OverrideAction,
} from "@/lib/defend"

export interface OverrideTarget {
  kind: BlockKind
  value: string
}

const EXPIRY = [
  {
    value: "0",
    get label() {
      return t("defend_expiry_never")
    },
  },
  {
    value: "30",
    get label() {
      return t("defend_expiry_days", { count: 30 })
    },
  },
  {
    value: "90",
    get label() {
      return t("defend_expiry_days", { count: 90 })
    },
  },
  {
    value: "365",
    get label() {
      return t("defend_expiry_year")
    },
  },
] as const

function OverrideForm({
  target,
  action: initialAction,
  onDone,
  onCancel,
}: {
  /** Null: the person types the value themselves. */
  target: OverrideTarget | null
  action: OverrideAction
  onDone: () => void
  onCancel: () => void
}) {
  const queryClient = useQueryClient()
  const [kind, setKind] = useState<BlockKind>(target?.kind ?? "ip")
  const [value, setValue] = useState(target?.value ?? "")
  const [action, setAction] = useState<OverrideAction>(initialAction)
  const [note, setNote] = useState("")
  const [expiry, setExpiry] = useState("0")
  const [password, setPassword] = useState("")
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [valueError, setValueError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { value: useId(), note: useId(), pass: useId(), err: useId() }
  const allow = action === "allow"

  async function submit() {
    if (pending) return
    setError(null)
    setValueError(null)
    setPasswordError(null)
    if (!password) {
      setPasswordError(t("override_password_required"))
      return
    }
    if (!value.trim()) {
      setValueError(t(allow ? "override_value_required_allow" : "override_value_required_block"))
      return
    }
    setPending(true)
    try {
      await createOverride({
        kind,
        value: value.trim(),
        action,
        note,
        expiresInDays: Number(expiry) || null,
        password,
      })
      await queryClient.invalidateQueries({ queryKey: ["defend"] })
      onDone()
    } catch (e) {
      // A refused value (private address, shared host) belongs to the value field.
      const failure = classifyFailure(e)
      if (failure === "invalid") setValueError(describeDefendError(e))
      else if (failure === "wrong-password") setPasswordError(describeDefendError(e))
      else setError(describeDefendError(e))
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
        <DialogTitle>{allow ? t("override_action_allow") : t("override_action_block")}</DialogTitle>
        <DialogDescription>
          {allow ? t("override_dialog_allow_description") : t("override_dialog_block_description")}
        </DialogDescription>
      </DialogHeader>

      {target ? null : (
        <>
          <SegmentedControl
            size="form"
            label={t("override_what_to_list")}
            value={kind}
            onChange={setKind}
            options={BLOCK_KINDS.map((k) => ({ value: k, label: KIND_META[k].label }))}
            className="flex-wrap self-start"
          />
          <SegmentedControl
            size="form"
            label={t("override_rule")}
            value={action}
            onChange={setAction}
            options={[
              { value: "allow", label: t("override_action_allow") },
              { value: "block", label: t("override_action_block") },
            ]}
            className="self-start"
          />
        </>
      )}

      <Field id={ids.value} label={KIND_META[kind].singular} error={valueError ?? undefined}>
        {target ? (
          <p className="rounded-md border bg-bg px-3 py-2 font-mono text-xs break-all text-fg">
            {value}
          </p>
        ) : (
          <Input
            id={ids.value}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            autoFocus
            autoComplete="off"
            spellCheck={false}
            maxLength={2048}
            aria-invalid={valueError ? true : undefined}
            aria-describedby={valueError ? `${ids.value}-error` : undefined}
            className="font-mono"
          />
        )}
      </Field>

      <Field id={ids.note} label={t("override_note")} hint={t("override_note_hint")}>
        <Input
          id={ids.note}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          maxLength={200}
          autoComplete="off"
          autoFocus={Boolean(target)}
          aria-describedby={`${ids.note}-hint`}
        />
      </Field>

      <div className="flex flex-col gap-1.5">
        <span className="text-sm font-medium text-fg">{t("override_lasts")}</span>
        <SegmentedControl
          size="form"
          label={t("override_lasts")}
          value={expiry}
          onChange={setExpiry}
          options={EXPIRY}
          className="self-start"
        />
      </div>

      <Field
        id={ids.pass}
        label={t("override_password")}
        hint={t("override_password_hint")}
        error={passwordError ?? undefined}
      >
        <Input
          id={ids.pass}
          name="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-invalid={passwordError ? true : undefined}
          aria-describedby={passwordError ? `${ids.pass}-error` : `${ids.pass}-hint`}
        />
      </Field>

      <FormError id={ids.err} message={error} />

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          {t("common_cancel")}
        </Button>
        <Button type="submit" disabled={pending}>
          {pending
            ? t("inventory_saving")
            : allow
              ? t("override_action_allow")
              : t("override_action_block")}
        </Button>
      </DialogFooter>
    </form>
  )
}

/** Opens for one listed value, or (target null) for a value typed by hand. */
export function OverrideDialog({
  open,
  onOpenChange,
  target,
  action,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  target: OverrideTarget | null
  action: OverrideAction
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-popover">
        <OverrideForm
          target={target}
          action={action}
          onCancel={() => onOpenChange(false)}
          onDone={() => onOpenChange(false)}
        />
      </DialogContent>
    </Dialog>
  )
}
