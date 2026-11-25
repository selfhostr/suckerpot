import { useQuery } from "@tanstack/react-query"
import { ExternalLink, Info } from "lucide-react"
import { useRef } from "react"
import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { CountryFlag } from "@/components/country-flag"
import { IntelBadge } from "@/components/infrastructure/intel-badge"
import { IPChip } from "@/components/ip-chip"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { CopyDefanged } from "@/components/trends/copy-defanged"
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import { api, queryKeys } from "@/lib/api"
import { formatNumber, plural } from "@/lib/format"
import {
  maskDefanged,
  ROLE_LABELS,
  safeReference,
  SOURCE_LABELS,
  TYPE_LABELS,
  type IntelAnswer,
} from "@/lib/infrastructure"

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <dt className="type-column text-fg-subtle">{label}</dt>
      <dd className="text-sm text-fg tabular-nums">{children}</dd>
    </div>
  )
}

function Answer({ a }: { a: IntelAnswer }) {
  const link = safeReference(a.reference)
  return (
    <li className="space-y-1.5 py-3 first:pt-0 last:pb-0">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium text-fg">{SOURCE_LABELS[a.source]}</span>
        <IntelBadge item={{ checked: true, known: a.known }} />
      </div>
      {a.known ? (
        <p className="text-sm text-fg-muted">
          {[a.family, a.threat_type?.replaceAll("_", " ")].filter(Boolean).join(" · ") ||
            "Listed, with no family named."}
        </p>
      ) : (
        <p className="text-sm text-fg-muted">The service has no record of it.</p>
      )}
      {a.tags.length > 0 ? (
        <p className="flex flex-wrap gap-1">
          {a.tags.map((t) => (
            <span
              key={t}
              className="inline-flex h-(--chip) items-center rounded-sm border border-border-strong px-2 font-mono text-2xs text-fg-muted"
            >
              {t}
            </span>
          ))}
        </p>
      ) : null}
      <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg-muted">
        {a.first_seen_ext ? (
          <span>
            First reported <RelativeTime iso={a.first_seen_ext} className="text-xs" />
          </span>
        ) : null}
        <span>
          Checked <RelativeTime iso={a.checked_at} className="text-xs" />
        </span>
        {link ? (
          <a
            href={link}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-fg underline underline-offset-4"
          >
            Open at {SOURCE_LABELS[a.source]}
            <ExternalLink aria-hidden className="size-3" />
          </a>
        ) : null}
      </p>
    </li>
  )
}

interface IndicatorDrawerProps {
  id: number | null
  onClose: () => void
  onSelect: (id: number) => void
}

/** Detail for one indicator. Its id lives in `?indicator=`, so the view is shareable. */
export function IndicatorDrawer({ id, onClose, onSelect }: IndicatorDrawerProps) {
  const headerRef = useRef<HTMLDivElement>(null)
  const { masked } = useIpMask()
  const q = useQuery({
    queryKey: queryKeys.indicator(id ?? 0),
    queryFn: () => api.indicator(id ?? 0),
    enabled: id !== null,
  })
  const d = q.data
  const item = d?.indicator
  const shown = (s: string) => (masked ? maskDefanged(s) : s)

  return (
    <Sheet open={id !== null} onOpenChange={(o) => (o ? undefined : onClose())}>
      <SheetContent
        className="w-full gap-0 overflow-y-auto p-0 sm:max-w-xl"
        onOpenAutoFocus={(e) => {
          e.preventDefault()
          headerRef.current?.focus()
        }}
      >
        <div
          ref={headerRef}
          tabIndex={-1}
          className="space-y-2 border-b px-5 pt-5 pr-12 pb-4 outline-none"
        >
          <SheetTitle className="text-fg">{item ? TYPE_LABELS[item.type] : "Indicator"}</SheetTitle>
          <SheetDescription className="sr-only">
            Where it was seen, what threat intelligence says about it, and the addresses that used
            it.
          </SheetDescription>
          {item ? (
            <div className="flex items-center gap-2">
              <p className="min-w-0 flex-1 font-mono text-xs break-all text-fg">
                {shown(item.defanged)}
              </p>
              <CopyDefanged url={item.defanged} />
            </div>
          ) : null}
          <p className="text-xs text-fg-muted">
            Shown defanged, as text on purpose: it was only ever observed, never contacted, and
            nothing here opens it.
          </p>
        </div>

        <div className="space-y-6 px-5 py-5">
          {q.isPending ? (
            <div role="status" aria-label="Loading" className="space-y-3">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-32 w-full" />
            </div>
          ) : q.isError || !d || !item ? (
            <p className="text-sm text-fg-muted">
              Could not load this indicator{q.error ? `: ${q.error.message}` : ""}.
            </p>
          ) : (
            <>
              <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3">
                <Fact label="Role">{ROLE_LABELS[item.role]}</Fact>
                <Fact label="Family">
                  {item.family ? (
                    <Link
                      to={`/infrastructure?family=${encodeURIComponent(item.family)}`}
                      className="text-fg underline decoration-fg-subtle underline-offset-4"
                      aria-label={`Show indicators of family ${item.family}`}
                    >
                      {item.family}
                    </Link>
                  ) : (
                    <span className="text-fg-subtle">None named</span>
                  )}
                </Fact>
                <Fact label="Addresses">{formatNumber(item.ips)}</Fact>
                <Fact label="Sightings">{formatNumber(item.sightings)}</Fact>
                <Fact label="First seen">
                  <RelativeTime iso={item.first_seen} className="text-sm text-fg" />
                </Fact>
                <Fact label="Last seen">
                  <RelativeTime iso={item.last_seen} className="text-sm text-fg" />
                </Fact>
                <Fact label="Sensors">
                  <span className="flex flex-wrap gap-2">
                    {item.sensors.map((s) => (
                      <SensorBadge key={s} sensor={s} />
                    ))}
                  </span>
                </Fact>
              </dl>

              <section aria-label="Threat intelligence">
                <h3 className="mb-2 type-subtitle text-fg">Threat intelligence</h3>
                {d.intel.length > 0 ? (
                  <ul className="divide-y rounded-md border bg-surface-hover/40 p-4">
                    {d.intel.map((a) => (
                      <Answer key={a.source} a={a} />
                    ))}
                  </ul>
                ) : (
                  <p className="flex items-start gap-2.5 rounded-md border bg-surface-hover/40 p-4 text-sm text-fg-muted">
                    <Info aria-hidden className="mt-0.5 size-4 shrink-0" />
                    <span>
                      {d.not_checked ? (
                        "Not looked up: this is a private, reserved or example value, so nothing was sent to any service."
                      ) : (
                        <>
                          No answer yet. Lookups need an abuse.ch key (and a VirusTotal key for
                          hashes): add one in{" "}
                          <Link to="/settings" className="text-fg underline underline-offset-4">
                            Settings
                          </Link>
                          .
                        </>
                      )}
                    </span>
                  </p>
                )}
              </section>

              <section aria-label="Addresses">
                <h3 className="mb-2 type-subtitle text-fg">
                  Addresses that used it ({formatNumber(d.source_ips.length)}
                  {d.links_truncated ? "+" : ""})
                </h3>
                {d.source_ips.length === 0 ? (
                  <p className="text-sm text-fg-muted">No addresses to show.</p>
                ) : (
                  <ul className="-mx-5 divide-y border-y">
                    {d.source_ips.map((s) => (
                      <li key={s.ip} className="flex items-center gap-3 px-5 py-2.5">
                        <IPChip ip={s.ip} variant="ghost" />
                        <CountryFlag code={s.country} />
                        <span className="min-w-0 flex-1 truncate text-xs text-fg-muted">
                          {s.org ?? ""}
                        </span>
                        <span className="text-xs text-fg-muted tabular-nums">
                          {plural(s.sessions, "session")} ·{" "}
                          <RelativeTime iso={s.last_seen} className="text-xs" />
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              {d.related.length > 0 ? (
                <section aria-label="Seen together">
                  <h3 className="mb-2 type-subtitle text-fg">Seen in the same sessions</h3>
                  <ul className="-mx-5 divide-y border-y">
                    {d.related.map((r) => (
                      <li key={r.id}>
                        <button
                          type="button"
                          onClick={() => onSelect(r.id)}
                          className="flex w-full items-center gap-3 px-5 py-2.5 text-left transition-colors duration-150 hover:bg-surface-hover/50"
                        >
                          <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg">
                            {shown(r.defanged)}
                          </span>
                          <span className="text-xs text-fg-muted">{TYPE_LABELS[r.type]}</span>
                          <span className="text-xs text-fg-muted tabular-nums">
                            {plural(r.sessions, "session")}
                          </span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </section>
              ) : null}

              <section aria-label="Recent sessions">
                <h3 className="mb-2 type-subtitle text-fg">Recent sessions</h3>
                {d.sessions.length === 0 ? (
                  <p className="text-sm text-fg-muted">No sessions to show.</p>
                ) : (
                  <ul className="-mx-5 divide-y border-y">
                    {d.sessions.slice(0, 10).map((s) => (
                      <li key={s.session_id}>
                        <Link
                          to={`/attacks/${encodeURIComponent(s.session_id)}`}
                          className="flex items-center gap-3 px-5 py-2.5 transition-colors duration-150 hover:bg-surface-hover/50"
                        >
                          <SensorBadge sensor={s.sensor} variant="dot" />
                          <span className="min-w-0 flex-1 truncate text-xs text-fg-muted">
                            {s.tags.slice(0, 3).join(" · ")}
                          </span>
                          <RelativeTime iso={s.seen_at} className="text-xs" />
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
