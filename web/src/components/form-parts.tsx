import { CircleAlert } from "lucide-react"
import type { ReactNode } from "react"
import { t } from "@/i18n"

/** A labelled form field with a hint, or an error that replaces the hint. */
export function Field({
  id,
  label,
  hint,
  error,
  optional = false,
  children,
}: {
  id: string
  label: string
  hint?: string
  error?: string | undefined
  /** Marks the field "Optional" next to its label. */
  optional?: boolean
  children: ReactNode
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-fg">
        {label}
        {optional ? (
          <span className="ml-1.5 text-xs font-normal text-fg-muted">{t("ui_optional")}</span>
        ) : null}
      </label>
      {children}
      {error ? (
        <p id={`${id}-error`} className="flex items-start gap-1.5 text-xs text-fg">
          <CircleAlert aria-hidden className="mt-0.5 size-3 shrink-0 text-fg-muted" />
          {error}
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="text-xs text-fg-muted">
          {hint}
        </p>
      ) : null}
    </div>
  )
}

export function FormError({ id, message }: { id: string; message: string | null }) {
  return (
    <div id={id} role="alert" aria-live="assertive" className="empty:hidden">
      {message ? (
        <p className="flex items-start gap-2 rounded-md border border-border-strong bg-surface-raised px-3 py-2 text-sm text-fg">
          <CircleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
          {message}
        </p>
      ) : null}
    </div>
  )
}

/**
 * "Unsaved changes", next to a section's Save button while its fields differ from what was saved.
 * A neutral dot plus words: it is a reminder, not a warning.
 */
export function UnsavedHint({ show }: { show: boolean }) {
  if (!show) return null
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-fg-muted">
      <span aria-hidden className="size-1.5 rounded-full bg-fg" />
      {t("ui_unsaved_changes")}
    </span>
  )
}
