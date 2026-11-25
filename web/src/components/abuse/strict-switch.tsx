import { useMutation } from "@tanstack/react-query"
import { useId, useState } from "react"
import { useAuth } from "@/app/auth"
import { Switch } from "@/components/ui/switch"
import { t } from "@/i18n"
import { abuseApi, describeAbuseError, type Recipient } from "@/lib/abuse"

/**
 * The recipient's "One mail per source (strict X-ARF)" switch (M38). Off by default: a provider
 * gets one daily digest with one X-ARF file per source. On sends spec-shaped mails, one per
 * source, for a desk whose parser takes only one report per mail. Administrators only.
 */
export function StrictSwitch({
  recipient,
  onChanged,
}: {
  recipient: Recipient
  onChanged: () => void
}) {
  const { canWrite } = useAuth()
  const id = useId()
  const [error, setError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: (on: boolean) => abuseApi.setStrict(recipient.id, on),
    onSuccess: () => {
      setError(null)
      onChanged()
    },
    onError: (e) => setError(describeAbuseError(e)),
  })
  if (!canWrite || !recipient.mailbox) return null
  const on = save.isPending ? save.variables : (recipient.xarf_strict ?? false)
  return (
    <div className="flex items-start gap-3 text-sm">
      <Switch
        id={id}
        checked={on}
        disabled={save.isPending}
        onCheckedChange={(v) => save.mutate(v)}
        className="mt-0.5"
      />
      <label htmlFor={id} className="text-fg">
        {t("abuse_strict_label")}
        <span className="block text-xs text-fg-muted">{t("abuse_strict_cost")}</span>
        {error ? <span className="block text-xs text-fg">{error}</span> : null}
      </label>
    </div>
  )
}
