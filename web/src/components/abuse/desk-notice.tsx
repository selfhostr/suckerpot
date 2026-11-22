import { useMutation } from "@tanstack/react-query"
import { ExternalLink } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { CopyField } from "@/components/abuse/copy-field"
import { Button } from "@/components/ui/button"
import { abuseApi, describeAbuseError, safeFormUrl, type Recipient } from "@/lib/abuse"
import { SUGGEST_URL, suggestionText } from "@/lib/abuse-forms"

const FORM_SOURCE: Record<string, string> = {
  reply: "A reply from the desk said so.",
  directory: "The shared directory of abuse forms says so.",
  manual: "You chose it.",
}

/**
 * The text to post as an issue for the shared directory of abuse forms (D12), for a form link
 * learned from a verified reply. Posting is by hand, from the owner's own account.
 */
function Suggest({ recipient, asns, url }: { recipient: Recipient; asns: number[]; url: string }) {
  const text = suggestionText({
    provider: recipient.name,
    mailbox: recipient.mailbox,
    asns,
    formUrl: url,
  })
  return (
    <details className="group rounded-md border px-3 py-2">
      <summary className="cursor-pointer text-fg-muted hover:text-fg">
        Suggest for the shared directory
      </summary>
      <div className="mt-2 space-y-2">
        <p className="text-xs text-fg-muted">
          Other nodes can use this form once a maintainer has checked it on the provider&apos;s own
          website. Copy the text and post it as an issue. Posting from your personal account links
          that account to reporting this provider.
        </p>
        <CopyField label="Suggestion" value={text} multiline />
        <a
          href={SUGGEST_URL}
          target="_blank"
          rel="noopener noreferrer"
          referrerPolicy="no-referrer"
          className="inline-flex items-center gap-1 text-xs underline underline-offset-2"
        >
          Open a new issue
          <ExternalLink aria-hidden className="size-3" />
        </a>
      </div>
    </details>
  )
}

/**
 * What the replies taught the node about this desk: it takes only its web form, or its address
 * bounced for good. Automatic sending skips both; the owner can clear a flag.
 */
export function DeskNotice({
  recipient,
  onChanged,
  asns = [],
}: {
  recipient: Recipient
  onChanged: () => void
  asns?: number[]
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
          <span>
            This desk only accepts its web form. Automatic sending skips it, and its reports wait in{" "}
            <Link to="/defend/abuse?status=forms" className="underline underline-offset-2">
              To submit by form
            </Link>
            . {FORM_SOURCE[recipient.form_source ?? "reply"] ?? ""}
          </span>
          {link ? (
            <a
              href={link}
              target="_blank"
              rel="noopener noreferrer"
              referrerPolicy="no-referrer"
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
      {form && link && canWrite && recipient.form_source === "reply" ? (
        <Suggest recipient={recipient} asns={asns} url={link} />
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
