import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Check, Download, ExternalLink, ShieldAlert, TriangleAlert } from "lucide-react"
import { useMemo, useState } from "react"
import { CopyField } from "@/components/abuse/copy-field"
import { SkeletonList } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { abuseKeys, describeAbuseError, guardReason, guardReasonsOf } from "@/lib/abuse"
import {
  BROWSER_WARNING,
  formKeys,
  formLinkHref,
  formsApi,
  keyOf,
  linkLabel,
  refsOf,
  saveText,
  type FormLink,
  type FormQueueItem,
  type Kit,
} from "@/lib/abuse-forms"
import { plural } from "@/lib/format"
import { todayKeys } from "@/lib/today"

/** The field name, and the form's own label when the shared directory knows it. */
function labelOf(kit: Kit, key: string, ours: string): string {
  const theirs = kit.labels[key]
  return theirs && theirs !== ours ? `${ours} (the form says “${theirs}”)` : ours
}

function LinkRow({ link }: { link: FormLink }) {
  const href = formLinkHref(link)
  return (
    <li className="space-y-0.5">
      <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
        {href ? (
          // Never opened by itself, never with the dashboard address in a Referer.
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            referrerPolicy="no-referrer"
            className="inline-flex items-center gap-1 font-medium underline underline-offset-2"
          >
            Open the form
            <ExternalLink aria-hidden className="size-3.5" />
          </a>
        ) : (
          <span className="font-medium">Not opened as a link</span>
        )}
        <span className="font-mono text-xs text-fg-muted">{link.host}</span>
      </span>
      <span className="block text-xs text-fg-muted">{linkLabel(link)}</span>
      {href ? null : (
        <span className="block font-mono text-xs break-all text-fg-muted">{link.url}</span>
      )}
    </li>
  )
}

/**
 * The copy kit of one form report: the browser warning, the form link with its host, every field
 * with its own copy button, the evidence file, the addresses to tick, and "Submitted". Every field
 * passed the identity guard on the server; a blocked kit shows why and has no copy button.
 */
export function FormKit({ item, onDone }: { item: FormQueueItem; onDone: () => void }) {
  const qc = useQueryClient()
  const q = useQuery({
    queryKey: formKeys.kit(item.public_id, item.revision),
    queryFn: () => formsApi.kit(item.public_id),
    retry: false,
  })
  const kit = q.data
  const all = useMemo(() => new Set((kit?.sources ?? []).map(keyOf)), [kit])
  const [ticked, setTicked] = useState<Set<string> | null>(null)
  // Everything is ticked at first, unless the form takes one address at a time.
  const chosen = ticked ?? (kit?.one_ip_per_submission ? new Set<string>() : all)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (q.isPending) return <SkeletonList rows={3} />
  if (q.isError || !kit) {
    const reasons = guardReasonsOf(q.error)
    return (
      <div role="alert" className="space-y-2 rounded-md border border-border-strong px-3 py-2.5">
        <p className="flex items-center gap-2 text-sm font-medium text-fg">
          <ShieldAlert aria-hidden className="size-4" />
          {reasons ? "The identity check blocked this kit" : "The kit is not available"}
        </p>
        {reasons ? (
          <ul className="list-disc space-y-1 pl-5 text-sm text-fg-muted">
            {reasons.map((r) => (
              <li key={r}>{guardReason(r)}</li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-fg-muted">{describeAbuseError(q.error)}</p>
        )}
      </div>
    )
  }

  const toggle = (key: string) =>
    setTicked(() => {
      const next = new Set(chosen)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })

  const submit = async () => {
    if (chosen.size === 0 || busy) return
    setBusy(true)
    setError(null)
    try {
      const everything = chosen.size === all.size
      await formsApi.submitted(
        kit.public_id,
        kit.revision,
        everything ? undefined : refsOf(kit.sources, chosen),
      )
      await qc.invalidateQueries({ queryKey: abuseKeys.all })
      // The reminder on Today counts the same queue.
      void qc.invalidateQueries({ queryKey: todayKeys.today })
      onDone()
    } catch (e) {
      setError(describeAbuseError(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <p
        role="note"
        className="flex items-start gap-2.5 rounded-md border border-border-strong bg-surface-raised px-3 py-2.5 text-sm font-medium text-fg"
      >
        <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
        {kit.warning || BROWSER_WARNING}
      </p>

      <section aria-label="Form link" className="space-y-2 text-sm">
        {kit.links.length > 0 ? (
          <ul className="space-y-2">
            {kit.links.map((l) => (
              <LinkRow key={`${l.origin}-${l.url}`} link={l} />
            ))}
          </ul>
        ) : (
          <p className="text-fg-muted">
            No form link is known. Find the form on the provider&apos;s own website.
          </p>
        )}
        {kit.links_differ ? (
          <p role="alert" className="text-fg">
            The shared directory and a reply point at different forms. Prefer the directory link,
            and check the host before you open either.
          </p>
        ) : null}
      </section>

      <div className="grid gap-4 md:grid-cols-2">
        <CopyField label={labelOf(kit, "email", "Your email")} value={kit.email} />
        <div className="space-y-1">
          <CopyField label={labelOf(kit, "name", "Your name")} value={kit.name} />
          {kit.name ? null : (
            <p className="text-xs text-fg-muted">
              Empty. Set a name in Settings, Reporting, if the form asks for one.
            </p>
          )}
        </div>
        <CopyField label={labelOf(kit, "abuse_type", "Abuse type")} value={kit.abuse_type} />
        <div className="grid grid-cols-2 gap-4">
          <CopyField label={labelOf(kit, "first_seen", "First seen")} value={kit.first_seen} />
          <CopyField label={labelOf(kit, "last_seen", "Last seen")} value={kit.last_seen} />
        </div>
      </div>
      <CopyField label={labelOf(kit, "addresses", "Addresses")} value={kit.addresses} multiline />
      <div className="space-y-1">
        <CopyField
          label={labelOf(kit, "description", "Description")}
          value={kit.description}
          multiline
        />
        <p className="text-xs text-fg-muted">
          At most {kit.max_chars.toLocaleString("en-GB")} characters. Keep the last line: it lets a
          reply find this report.
        </p>
      </div>
      <CopyField
        label={labelOf(kit, "log_excerpt", "Log excerpt")}
        value={kit.log_excerpt}
        multiline
      />
      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          variant="outline"
          onClick={() => saveText(kit.evidence.name, kit.evidence.media_type, kit.evidence.content)}
        >
          <Download aria-hidden /> Download {kit.evidence.name}
        </Button>
        <span className="text-xs text-fg-muted">
          {labelOf(kit, "evidence", "Evidence file")}, for a form that takes an attachment.
        </span>
      </div>

      <fieldset className="space-y-2">
        <legend className="text-sm font-medium text-fg">
          {kit.one_ip_per_submission
            ? "This form takes one address at a time. Tick each address you submitted."
            : "Addresses in this submission"}
        </legend>
        <ul className="divide-y rounded-md border">
          {kit.sources.map((s) => {
            const key = keyOf(s)
            const id = `tick-${key}`
            return (
              <li key={key} className="space-y-3 px-3 py-2.5">
                <label htmlFor={id} className="flex items-center gap-2 text-sm">
                  <input
                    id={id}
                    type="checkbox"
                    checked={chosen.has(key)}
                    onChange={() => toggle(key)}
                    className="size-4 accent-current"
                  />
                  <span className="font-mono text-xs">{s.value}</span>
                  <span className="text-xs text-fg-muted">{s.abuse_type}</span>
                  {s.stale ? (
                    <span className="text-xs text-fg-muted">older than 7 days</span>
                  ) : null}
                </label>
                {kit.one_ip_per_submission ? (
                  <div className="grid gap-3 md:grid-cols-2">
                    <CopyField label="Address" value={s.value} />
                    <CopyField label="Abuse type" value={s.abuse_type} />
                    <CopyField label="Description" value={s.description} multiline />
                    <CopyField label="Log excerpt" value={s.log_excerpt} multiline />
                  </div>
                ) : null}
              </li>
            )
          })}
        </ul>
      </fieldset>

      <div className="flex flex-wrap items-center gap-3">
        <Button size="sm" disabled={busy || chosen.size === 0} onClick={() => void submit()}>
          <Check aria-hidden /> {busy ? "Saving…" : "Submitted"}
        </Button>
        <span className="text-xs text-fg-muted">
          {chosen.size === 0
            ? "Tick at least one address."
            : chosen.size === all.size
              ? `Records ${plural(chosen.size, "address", "addresses")} as sent.`
              : `Records ${plural(chosen.size, "address", "addresses")} as sent. The others wait for the next form report.`}
        </span>
      </div>
      <p role="alert" className="text-sm text-fg empty:hidden">
        {error}
      </p>
    </div>
  )
}
