import { KeyRound, X } from "lucide-react"
import { CopyButton } from "@/components/defend/copy-button"
import { Button } from "@/components/ui/button"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import {
  feedCurl,
  feedUrl,
  isBlockKind,
  kindsPhrase,
  networkFeedCurl,
  networkFeedUrl,
} from "@/lib/defend"
import type { CreatedToken } from "./create-token-dialog"

function Snippet({ label, copyLabel, text }: { label: string; copyLabel: string; text: string }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <h4 className="type-eyebrow text-fg-muted">{label}</h4>
        <CopyButton text={text} label={copyLabel} variant="outline" size="sm">
          {t("common_copy")}
        </CopyButton>
      </div>
      <pre
        tabIndex={0}
        aria-label={label}
        className="overflow-x-auto rounded-md border bg-bg px-3 py-2.5 font-mono text-xs leading-5 whitespace-pre text-fg select-all"
      >
        <code>{text}</code>
      </pre>
    </div>
  )
}

/** Shown once, right after creation. The secret lives only in this component's props. */
export function TokenReveal({
  created,
  onDismiss,
}: {
  created: CreatedToken
  onDismiss: () => void
}) {
  const origin = window.location.origin
  const { token, item } = created
  const blocks = item.kinds.filter(isBlockKind)
  const first = blocks[0] ?? "ip"
  const mirrorOnly = blocks.length === 0 && item.kinds.includes("network")
  return (
    <section
      aria-labelledby="token-reveal-title"
      className="animate-fade-in rounded-lg border border-border-strong bg-surface-raised p-4 shadow-sm sm:p-5"
    >
      <header className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <KeyRound aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
          <div className="space-y-1">
            <h3 id="token-reveal-title" className="type-card-title text-fg">
              {t("feeds_reveal_title", { name: item.name })}
            </h3>
            <p className="text-sm text-fg-muted">
              {t("feeds_reveal_description", { kinds: kindsPhrase(item.kinds) })}
            </p>
          </div>
        </div>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label={t("feeds_reveal_hide")}
          onClick={onDismiss}
        >
          <X aria-hidden />
        </Button>
      </header>

      <div className="mt-4 space-y-4">
        <Snippet
          label={t("feeds_reveal_token")}
          copyLabel={t("feeds_reveal_copy_token")}
          text={token}
        />
        {mirrorOnly ? (
          <>
            <Snippet
              label={t("feeds_reveal_url_form")}
              copyLabel={t("feeds_reveal_copy_url_form")}
              text={networkFeedUrl(origin, token)}
            />
            <p className="-mt-2 text-xs text-fg-muted">
              {tNodes(
                "feeds_reveal_mirror_note",
                {},
                {
                  current: <code className="font-mono">outbound.txt</code>,
                  a: <code className="font-mono">outbound-high.txt</code>,
                  b: <code className="font-mono">outbound-domains.txt</code>,
                  c: <code className="font-mono">inbound.txt</code>,
                  d: <code className="font-mono">inbound-high.txt</code>,
                },
              )}
            </p>
            <Snippet
              label={t("feeds_reveal_header_form")}
              copyLabel={t("feeds_reveal_copy_header_form")}
              text={networkFeedCurl(origin, token)}
            />
          </>
        ) : (
          <>
            <Snippet
              label={t("feeds_reveal_url_form")}
              copyLabel={t("feeds_reveal_copy_url_form")}
              text={feedUrl(origin, token, first)}
            />
            <p className="-mt-2 text-xs text-fg-muted">
              {tNodes(
                "feeds_reveal_url_note",
                {
                  others:
                    blocks
                      .filter((k) => k !== first)
                      .map((k) => `${k}.txt`)
                      .join(", ") || t("feeds_reveal_another_list"),
                },
                {
                  first: <code className="font-mono">{first}.txt</code>,
                  csv: <code className="font-mono">.csv</code>,
                },
              )}
            </p>
            <Snippet
              label={t("feeds_reveal_header_form")}
              copyLabel={t("feeds_reveal_copy_header_form")}
              text={feedCurl(origin, token, first)}
            />
          </>
        )}
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t pt-4">
        <p className="text-xs text-fg-muted">
          {tNodes(
            "feeds_reveal_access_note",
            {},
            { path: <code className="font-mono">/feeds/*</code> },
          )}
        </p>
        <Button variant="outline" size="sm" onClick={onDismiss}>
          {t("feeds_reveal_saved")}
        </Button>
      </div>
    </section>
  )
}
