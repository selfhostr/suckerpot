import { useMutation } from "@tanstack/react-query"
import { ExternalLink } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { CopyField } from "@/components/abuse/copy-field"
import { Button } from "@/components/ui/button"
import { abuseApi, describeAbuseError, safeFormUrl, type Recipient } from "@/lib/abuse"
import { reducedFormUrl, SUGGEST_URL, suggestionText } from "@/lib/abuse-forms"

const FORM_SOURCE: Record<string, string> = {
  reply: "A reply from the desk said so.",
  directory: "The shared directory of abuse forms says so.",
  manual: "You chose it.",
}

/**
 * The text to post as an issue for the shared directory of abuse forms (D12), for a form link
 * learned from a verified reply. Posting is by hand, from the owner's own account.
 */
function Suggest({
  recipient,
  asns,
  url,
  shortened,
}: {
  recipient: Recipient
  asns: number[]
  url: string
  shortened: boolean
}) {
  const text = suggestionText({
    provider: recipient.name,
    mailbox: recipient.mailbox,
    asns,
    formUrl: url,
    shortened,
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
        {shortened ? (
          <p className="text-xs text-fg">
            Only the provider&apos;s site is in the text: the link from the reply could hold a
            ticket number, a token or your address. Find the form page on the provider&apos;s own
            site and add its address to the issue yourself.
          </p>
        ) : null}
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
  // A desk that reads mail but suggests its form: a hint, shown only when it is not form-only.
  const preferred = !form && (recipient.form_preferred ?? false)
  if (!form && !dead && !preferred) return null
  // A link only when the server says so (https on the provider's own domain, no port, no query):
  // the same rule as the copy kit. Anything else is shown as text.
  const link = recipient.form_url_clickable ? safeFormUrl(recipient.form_url) : null
  const plain = !link && recipient.form_url ? recipient.form_url : null
  const suggested = link ?? reducedFormUrl(recipient.form_url)
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
          {plain ? (
            <span className="block w-full text-xs text-fg-muted">
              Form address from the reply, not opened as a link (check it before you use it):{" "}
              <span className="font-mono break-all">{plain}</span>
            </span>
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
      {form && suggested && canWrite && recipient.form_source === "reply" ? (
        <Suggest recipient={recipient} asns={asns} url={suggested} shortened={!link} />
      ) : null}
      {preferred ? (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span>This provider also has a web form; mail still works.</span>
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
          {plain ? (
            <span className="block w-full text-xs text-fg-muted">
              Form address from the reply, not opened as a link (check it before you use it):{" "}
              <span className="font-mono break-all">{plain}</span>
            </span>
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
