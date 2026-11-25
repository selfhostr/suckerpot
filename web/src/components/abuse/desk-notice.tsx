import { useMutation } from "@tanstack/react-query"
import { ExternalLink } from "lucide-react"
import { useState } from "react"
import { Link } from "react-router"
import { useAuth } from "@/app/auth"
import { CopyField } from "@/components/abuse/copy-field"
import { Button } from "@/components/ui/button"
import { t, tk } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { abuseApi, describeAbuseError, safeFormUrl, type Recipient } from "@/lib/abuse"
import { reducedFormUrl, SUGGEST_URL, suggestionText } from "@/lib/abuse-forms"

const FORM_SOURCE: Record<string, string> = {
  reply: tk("abuse_desk_source_reply"),
  directory: tk("abuse_desk_source_directory"),
  manual: tk("abuse_desk_source_manual"),
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
        {t("abuse_desk_suggest_summary")}
      </summary>
      <div className="mt-2 space-y-2">
        <p className="text-xs text-fg-muted">{t("abuse_desk_suggest_explain")}</p>
        {shortened ? <p className="text-xs text-fg">{t("abuse_desk_suggest_shortened")}</p> : null}
        <CopyField label={t("abuse_desk_suggestion")} value={text} multiline />
        <a
          href={SUGGEST_URL}
          target="_blank"
          rel="noopener noreferrer"
          referrerPolicy="no-referrer"
          className="inline-flex items-center gap-1 text-xs underline underline-offset-2"
        >
          {t("abuse_desk_new_issue")}
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
  const formSource = FORM_SOURCE[recipient.form_source ?? "reply"]
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
            {tNodes(
              "abuse_desk_form_only",
              {},
              {
                queue: (
                  <Link to="/defend/abuse?status=forms" className="underline underline-offset-2">
                    {t("abuse_desk_queue_link")}
                  </Link>
                ),
              },
            )}{" "}
            {formSource ? t(formSource) : null}
          </span>
          {link ? (
            <a
              href={link}
              target="_blank"
              rel="noopener noreferrer"
              referrerPolicy="no-referrer"
              className="inline-flex items-center gap-1 underline underline-offset-2"
            >
              {t("abuse_desk_open_form")}
              <ExternalLink aria-hidden className="size-3.5" />
            </a>
          ) : null}
          {link ? (
            <span className="font-mono text-xs text-fg-muted">({new URL(link).host})</span>
          ) : null}
          {plain ? (
            <span className="block w-full text-xs text-fg-muted">
              {tNodes(
                "abuse_desk_form_address",
                {},
                { address: <span className="font-mono break-all">{plain}</span> },
              )}
            </span>
          ) : null}
          {canWrite ? (
            <Button
              size="sm"
              variant="outline"
              disabled={clear.isPending}
              onClick={() => clear.mutate("form_only")}
            >
              {t("abuse_desk_clear_flag")}
            </Button>
          ) : null}
        </p>
      ) : null}
      {form && suggested && canWrite && recipient.form_source === "reply" ? (
        <Suggest recipient={recipient} asns={asns} url={suggested} shortened={!link} />
      ) : null}
      {preferred ? (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span>{t("abuse_desk_preferred")}</span>
          {link ? (
            <a
              href={link}
              target="_blank"
              rel="noopener noreferrer"
              referrerPolicy="no-referrer"
              className="inline-flex items-center gap-1 underline underline-offset-2"
            >
              {t("abuse_desk_open_form")}
              <ExternalLink aria-hidden className="size-3.5" />
            </a>
          ) : null}
          {link ? (
            <span className="font-mono text-xs text-fg-muted">({new URL(link).host})</span>
          ) : null}
          {plain ? (
            <span className="block w-full text-xs text-fg-muted">
              {tNodes(
                "abuse_desk_form_address",
                {},
                { address: <span className="font-mono break-all">{plain}</span> },
              )}
            </span>
          ) : null}
        </p>
      ) : null}
      {dead ? (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span>{t("abuse_desk_bounced")}</span>
          {canWrite ? (
            <Button
              size="sm"
              variant="outline"
              disabled={clear.isPending}
              onClick={() => clear.mutate("undeliverable")}
            >
              {t("abuse_desk_clear_flag")}
            </Button>
          ) : null}
        </p>
      ) : null}
      {error ? <p className="text-destructive">{error}</p> : null}
    </div>
  )
}
