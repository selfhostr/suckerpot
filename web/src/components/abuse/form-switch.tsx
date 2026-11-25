import { useMutation } from "@tanstack/react-query"
import { useState } from "react"
import { useAuth } from "@/app/auth"
import { Button } from "@/components/ui/button"
import { t } from "@/i18n"
import { describeAbuseError, type Recipient } from "@/lib/abuse"
import { formsApi } from "@/lib/abuse-forms"

/**
 * Send a desk to the form queue by hand (M38): its sources then go into a weekly form report and
 * no automatic mail goes there. "Clear this flag" on the desk notice undoes it. Administrators only.
 */
export function FormSwitch({
  recipient,
  onChanged,
}: {
  recipient: Recipient
  onChanged: () => void
}) {
  const { canWrite } = useAuth()
  const [error, setError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => formsApi.setFormOnly(recipient.id, true),
    onSuccess: () => {
      setError(null)
      onChanged()
    },
    onError: (e) => setError(describeAbuseError(e)),
  })
  if (!canWrite || !recipient.mailbox || recipient.form_only) return null
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
      <Button size="sm" variant="outline" disabled={save.isPending} onClick={() => save.mutate()}>
        {t("abuse_form_switch_button")}
      </Button>
      <span className="text-xs text-fg-muted">{t("abuse_form_switch_hint")}</span>
      {error ? <span className="block w-full text-xs text-fg">{error}</span> : null}
    </div>
  )
}
