import { KeyRound, X } from "lucide-react"
import { CopyButton } from "@/components/defend/copy-button"
import { Button } from "@/components/ui/button"
import {
  feedCurl,
  feedUrl,
  isBlockKind,
  kindsPhrase,
  networkFeedCurl,
  networkFeedUrl,
} from "@/lib/defend"
import type { CreatedToken } from "./create-token-dialog"

function Snippet({ label, text }: { label: string; text: string }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <h4 className="type-eyebrow text-fg-muted">{label}</h4>
        <CopyButton
          text={text}
          label={`Copy the ${label.toLowerCase()}`}
          variant="outline"
          size="sm"
        >
          Copy
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
              Copy your token now: “{item.name}”
            </h3>
            <p className="text-sm text-fg-muted">
              This is the only time it is shown. It cannot be shown again, so store it somewhere
              safe. Anyone who has the URL can read the lists it covers ({kindsPhrase(item.kinds)}),
              so revoke the token if it ever leaks.
            </p>
          </div>
        </div>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label="I have saved it, hide the token"
          onClick={onDismiss}
        >
          <X aria-hidden />
        </Button>
      </header>

      <div className="mt-4 space-y-4">
        <Snippet label="Token" text={token} />
        {mirrorOnly ? (
          <>
            <Snippet
              label="URL form, for OPNsense and pfSense URL tables"
              text={networkFeedUrl(origin, token)}
            />
            <p className="-mt-2 text-xs text-fg-muted">
              This is the verified copy of the community outbound list. For the others replace{" "}
              <code className="font-mono">outbound.txt</code> with{" "}
              <code className="font-mono">outbound-high.txt</code>,{" "}
              <code className="font-mono">outbound-domains.txt</code>,{" "}
              <code className="font-mono">inbound.txt</code> or{" "}
              <code className="font-mono">inbound-high.txt</code>.
            </p>
            <Snippet
              label="Header form, for scripts and proxies"
              text={networkFeedCurl(origin, token)}
            />
          </>
        ) : (
          <>
            <Snippet
              label="URL form, for OPNsense and pfSense URL tables"
              text={feedUrl(origin, token, first)}
            />
            <p className="-mt-2 text-xs text-fg-muted">
              Firewalls cannot send headers, so the token is part of the URL. For the other lists
              replace <code className="font-mono">{first}.txt</code> with{" "}
              {blocks
                .filter((k) => k !== first)
                .map((k) => `${k}.txt`)
                .join(", ") || "another list"}
              , or use <code className="font-mono">.csv</code> for a file with a header line.
            </p>
            <Snippet
              label="Header form, for scripts and proxies"
              text={feedCurl(origin, token, first)}
            />
          </>
        )}
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t pt-4">
        <p className="text-xs text-fg-muted">
          Behind Cloudflare Access? Add a bypass policy for{" "}
          <code className="font-mono">/feeds/*</code>, or the firewall will be turned away at the
          login page.
        </p>
        <Button variant="outline" size="sm" onClick={onDismiss}>
          I have saved it
        </Button>
      </div>
    </section>
  )
}
