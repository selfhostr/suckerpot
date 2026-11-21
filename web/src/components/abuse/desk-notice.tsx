import { useMutation } from "@tanstack/react-query"
import { ExternalLink } from "lucide-react"
import { useState } from "react"
import { useAuth } from "@/app/auth"
import { Button } from "@/components/ui/button"
import { abuseApi, describeAbuseError, safeFormUrl, type Recipient } from "@/lib/abuse"

/**
 * What the replies taught the node about this desk: it takes only its web form, or its address
 * bounced for good. Automatic sending skips both; the owner can clear a flag.
 */
export function DeskNotice({
  recipient,
  onChanged,
}: {
  recipient: Recipient
  onChanged: () => void
}) {
  const { canWrite } = useAuth()
  const [error, setError] = useState<string | null>(null)
  const clear = useMutation({
    mutationFn: (flag: "form_only" | "undeliverable") => abuseApi.clearDesk(recipient.id, flag),
    onSuccess: () => {
      setError(null)
      onChanged()
    },
    onError: (e) => setError(describeAbuseError(e)),
  })
  const form = recipient.form_only ?? false
  const dead = recipient.undeliverable ?? false
  if (!form && !dead) return null
  const link = safeFormUrl(recipient.form_url)
  return (
    <div
      role="note"
      className="space-y-2 rounded-md border border-border-strong bg-surface-raised px-3 py-2 text-sm text-fg"
    >
      {form ? (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span>This desk only accepts its web form. Automatic sending skips it.</span>
          {link ? (
            <a
              href={link}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 underline underline-offset-2"
            >
              Open the form
              <ExternalLink aria-hidden className="size-3.5" />
            </a>
          ) : null}
          {link ? (
            <span className="font-mono text-xs text-fg-muted">({new URL(link).host})</span>
          ) : null}
          {canWrite ? (
            <Button
              size="sm"
              variant="outline"
              disabled={clear.isPending}
              onClick={() => clear.mutate("form_only")}
            >
              Clear this flag
            </Button>
          ) : null}
        </p>
      ) : null}
      {dead ? (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span>
            Mail to this address bounced for good. Automatic sending skips it. Type another address,
            or clear the flag if the address works again.
          </span>
          {canWrite ? (
            <Button
              size="sm"
              variant="outline"
              disabled={clear.isPending}
              onClick={() => clear.mutate("undeliverable")}
            >
              Clear this flag
            </Button>
          ) : null}
        </p>
      ) : null}
      {error ? <p className="text-destructive">{error}</p> : null}
    </div>
  )
}
