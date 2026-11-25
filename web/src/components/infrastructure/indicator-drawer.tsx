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
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { formatNumber } from "@/lib/format"
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
            t("infra_drawer_listed_no_family")}
        </p>
      ) : (
        <p className="text-sm text-fg-muted">{t("infra_drawer_no_record")}</p>
      )}
      {a.tags.length > 0 ? (
        <p className="flex flex-wrap gap-1">
          {a.tags.map((tag) => (
            <span
              key={tag}
              className="inline-flex h-(--chip) items-center rounded-sm border border-border-strong px-2 font-mono text-2xs text-fg-muted"
            >
              {tag}
            </span>
          ))}
        </p>
      ) : null}
      <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg-muted">
        {a.first_seen_ext ? (
          <span>
            {tNodes(
              "infra_drawer_first_reported",
              {},
              { time: <RelativeTime iso={a.first_seen_ext} className="text-xs" /> },
            )}
          </span>
        ) : null}
        <span>
          {tNodes(
            "infra_drawer_checked",
            {},
            { time: <RelativeTime iso={a.checked_at} className="text-xs" /> },
          )}
        </span>
        {link ? (
          <a
            href={link}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-fg underline underline-offset-4"
          >
            {t("infra_drawer_open_at", { source: SOURCE_LABELS[a.source] })}
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
          <SheetTitle className="text-fg">{item ? TYPE_LABELS[item.type] : t("infra_drawer_title")}</SheetTitle>
          <SheetDescription className="sr-only">
            {t("infra_drawer_description")}
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
            {t("infra_drawer_defanged_note")}
          </p>
        </div>

        <div className="space-y-6 px-5 py-5">
          {q.isPending ? (
            <div role="status" aria-label={t("common_loading")} className="space-y-3">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-32 w-full" />
            </div>
          ) : q.isError || !d || !item ? (
            <p className="text-sm text-fg-muted">
              {t("infra_drawer_error", {
                hasError: q.error ? "yes" : "no",
                error: q.error?.message ?? "",
              })}
            </p>
          ) : (
            <>
              <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3">
                <Fact label={t("infra_drawer_role")}>{ROLE_LABELS[item.role]}</Fact>
                <Fact label={t("infra_drawer_family")}>
                  {item.family ? (
                    <Link
                      to={`/infrastructure?family=${encodeURIComponent(item.family)}`}
                      className="text-fg underline decoration-fg-subtle underline-offset-4"
                      aria-label={t("infra_family_show", { name: item.family })}
                    >
                      {item.family}
                    </Link>
                  ) : (
                    <span className="text-fg-subtle">{t("infra_drawer_none_named")}</span>
                  )}
                </Fact>
                <Fact label={t("infra_col_addresses")}>{formatNumber(item.ips)}</Fact>
                <Fact label={t("infra_col_sightings")}>{formatNumber(item.sightings)}</Fact>
                <Fact label={t("infra_drawer_first_seen")}>
                  <RelativeTime iso={item.first_seen} className="text-sm text-fg" />
                </Fact>
                <Fact label={t("infra_col_last_seen")}>
                  <RelativeTime iso={item.last_seen} className="text-sm text-fg" />
                </Fact>
                <Fact label={t("infra_drawer_sensors")}>
                  <span className="flex flex-wrap gap-2">
                    {item.sensors.map((s) => (
                      <SensorBadge key={s} sensor={s} />
                    ))}
                  </span>
                </Fact>
              </dl>

              <section aria-label={t("infra_col_intel")}>
                <h3 className="mb-2 type-subtitle text-fg">{t("infra_col_intel")}</h3>
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
                        t("infra_drawer_not_looked_up")
                      ) : (
                        tNodes(
                          "infra_drawer_no_answer",
                          {},
                          {
                            settings: (
                              <Link
                                to="/settings"
                                className="text-fg underline underline-offset-4"
                              >
                                {t("infra_drawer_settings")}
                              </Link>
                            ),
                          },
                        )
                      )}
                    </span>
                  </p>
                )}
              </section>

              <section aria-label={t("infra_col_addresses")}>
                <h3 className="mb-2 type-subtitle text-fg">
                  {t("infra_drawer_addresses_title", {
                    count: d.source_ips.length,
                    truncated: d.links_truncated ? "yes" : "no",
                  })}
                </h3>
                {d.source_ips.length === 0 ? (
                  <p className="text-sm text-fg-muted">{t("infra_drawer_no_addresses")}</p>
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
                          {tNodes(
                            "infra_drawer_ip_sessions",
                            { count: s.sessions },
                            { time: <RelativeTime iso={s.last_seen} className="text-xs" /> },
                          )}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              {d.related.length > 0 ? (
                <section aria-label={t("infra_drawer_related_label")}>
                  <h3 className="mb-2 type-subtitle text-fg">{t("infra_drawer_related_title")}</h3>
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
                            {t("infra_sessions", { count: r.sessions })}
                          </span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </section>
              ) : null}

              <section aria-label={t("infra_drawer_recent")}>
                <h3 className="mb-2 type-subtitle text-fg">{t("infra_drawer_recent")}</h3>
                {d.sessions.length === 0 ? (
                  <p className="text-sm text-fg-muted">{t("infra_drawer_no_sessions")}</p>
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
