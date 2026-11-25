import { useQueryClient } from "@tanstack/react-query"
import { useId, useRef, useState, type SyntheticEvent } from "react"
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
import { Switch } from "@/components/ui/switch"
import { cn } from "@/lib/utils"
import {
  classifyFailure,
  createFeedToken,
  describeDefendError,
  EXPIRY_OPTIONS,
  DEFAULT_MIN_SCORE,
  SCORE_OPTIONS,
  scorePreset,
  TOKEN_KIND_META,
  TOKEN_KINDS,
  type FeedToken,
  type TokenKind,
} from "@/lib/defend"

export interface CreatedToken {
  token: string
  item: FeedToken
}

function CreateForm({
  onCreated,
  onCancel,
}: {
  onCreated: (created: CreatedToken) => void
  onCancel: () => void
}) {
  const queryClient = useQueryClient()
  const [name, setName] = useState("")
  const [kinds, setKinds] = useState<TokenKind[]>(["ip"])
  const [minScore, setMinScore] = useState<number>(DEFAULT_MIN_SCORE)
  const [includeBenign, setIncludeBenign] = useState(false)
  const [expiry, setExpiry] = useState("none")
  const [password, setPassword] = useState("")
  const [errors, setErrors] = useState<{ name?: string; kinds?: string; password?: string }>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const passRef = useRef<HTMLInputElement>(null)
  const ids = {
    name: useId(),
    kinds: useId(),
    score: useId(),
    benign: useId(),
    pass: useId(),
    err: useId(),
  }

  const toggle = (k: TokenKind, on: boolean) =>
    setKinds((prev) => (on ? [...prev, k] : prev.filter((x) => x !== k)))

  async function submit() {
    if (pending) return
    setFormError(null)
    const found: typeof errors = {}
    if (!name.trim()) found.name = "Give the token a name, for example the firewall it is for."
    else if (name.trim().length > 64) found.name = "Use at most 64 characters."
    if (kinds.length === 0) found.kinds = "Choose at least one list."
    if (!password) found.password = "Enter your password to confirm."
    setErrors(found)
    if (Object.keys(found).length > 0) return
    setPending(true)
    try {
      const created = await createFeedToken(
        {
          name,
          kinds: TOKEN_KINDS.filter((k) => kinds.includes(k)),
          minScore,
          includeBenign,
          expiresInDays: EXPIRY_OPTIONS.find((o) => o.value === expiry)?.days ?? null,
        },
        password,
      )
      await queryClient.invalidateQueries({ queryKey: ["defend", "feed-tokens"] })
      onCreated(created)
    } catch (e) {
      setPassword("")
      if (classifyFailure(e) === "wrong-password") {
        setErrors({ password: describeDefendError(e) })
        passRef.current?.focus()
      } else setFormError(describeDefendError(e))
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
        <DialogTitle>Create a feed token</DialogTitle>
        <DialogDescription>
          The token is shown once, right after you create it. It is stored only as a hash, so it
          cannot be shown again.
        </DialogDescription>
      </DialogHeader>

      <Field id={ids.name} label="Name" error={errors.name}>
        <Input
          id={ids.name}
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus
          autoComplete="off"
          maxLength={64}
          placeholder="Edge firewall"
          aria-invalid={errors.name ? true : undefined}
          aria-describedby={errors.name ? `${ids.name}-error` : undefined}
        />
      </Field>

      <fieldset className="flex flex-col gap-1.5" aria-describedby={`${ids.kinds}-error`}>
        <legend className="mb-1.5 text-sm font-medium text-fg">Lists it can read</legend>
        <div className="grid grid-cols-2 gap-2">
          {TOKEN_KINDS.map((k) => (
            <label
              key={k}
              className={cn(
                "flex h-9 cursor-pointer items-center gap-2 rounded-md border px-3 text-sm text-fg has-[:checked]:border-border-strong has-[:checked]:bg-surface-raised",
                k === "network" && "col-span-2",
              )}
            >
              <input
                type="checkbox"
                checked={kinds.includes(k)}
                onChange={(e) => toggle(k, e.target.checked)}
                className="size-4 accent-[var(--fg)]"
              />
              {TOKEN_KIND_META[k].label}
            </label>
          ))}
        </div>
        {errors.kinds ? (
          <p id={`${ids.kinds}-error`} className="text-xs text-fg">
            {errors.kinds}
          </p>
        ) : null}
      </fieldset>

      <div className="flex flex-col gap-1.5">
        <span className="text-sm font-medium text-fg">Minimum score</span>
        <SegmentedControl
          size="form"
          label="Minimum score"
          value={String(minScore)}
          onChange={(v) => setMinScore(Number(v))}
          options={SCORE_OPTIONS}
          className="flex-wrap self-start"
        />
        <p id={ids.score} className="text-xs text-fg-muted">
          {scorePreset(minScore)?.hint}
        </p>
      </div>

      <div className="flex items-start gap-3">
        <Switch
          id={ids.benign}
          checked={includeBenign}
          onCheckedChange={setIncludeBenign}
          className="mt-0.5"
        />
        <label htmlFor={ids.benign} className="space-y-0.5 text-sm text-fg">
          Include research scanners
          <span className="block text-xs text-fg-muted">
            Off by default: they probe everyone and are rarely worth blocking.
          </span>
        </label>
      </div>

      <div className="flex flex-col gap-1.5">
        <span className="text-sm font-medium text-fg">Expires</span>
        <SegmentedControl
          size="form"
          label="Expires"
          value={expiry}
          onChange={setExpiry}
          options={EXPIRY_OPTIONS.map((o) => ({ value: o.value, label: o.label }))}
          className="self-start"
        />
      </div>

      <Field
        id={ids.pass}
        label="Your password"
        hint="Creating a token asks for your dashboard password again."
        error={errors.password}
      >
        <Input
          id={ids.pass}
          ref={passRef}
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
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? "Creating…" : "Create token"}
        </Button>
      </DialogFooter>
    </form>
  )
}

/** Lives only while open, so the typed password is dropped the moment it closes. */
export function CreateTokenDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: (created: CreatedToken) => void
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90dvh] overflow-y-auto bg-popover">
        <CreateForm
          onCancel={() => onOpenChange(false)}
          onCreated={(created) => {
            onOpenChange(false)
            onCreated(created)
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
