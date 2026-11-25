import { useQuery } from "@tanstack/react-query"
import {
  CircleCheck,
  CircleDashed,
  Info,
  OctagonAlert,
  SwatchBook,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react"
import { Link } from "react-router"
import { t, tk } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { ReportingCard } from "@/components/abuse/reporting-card"
import { ReportingNav } from "@/components/abuse/reporting-nav"
import { ImapCard } from "@/components/abuse/imap-card"
import { DigestCard } from "@/components/abuse/digest-card"
import { SendingCard } from "@/components/abuse/sending-card"
import { AlertsPanel } from "@/components/alerts/alerts-panel"
import { ChannelsCard } from "@/components/alerts/channels-card"
import { TourButton } from "@/components/tour/tour-button"
import { Button } from "@/components/ui/button"
import { LanguageCard } from "@/components/language-card"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useUrlParam } from "@/hooks/use-url-param"
import { EgressCard } from "@/components/egress-card"
import { PipelineCard } from "@/components/pipeline-card"
import { FeedsTab } from "@/components/feeds/feeds-tab"
import { FindingCard } from "@/components/finding-card"
import { Meter } from "@/components/meter"
import { PageHeader } from "@/components/page-header"
import { PortsCard } from "@/components/setup/ports-table"
import { SetupResumeCard } from "@/components/setup/resume-card"
import { UpdatesCard } from "@/components/setup/updates-card"
import { SetupChecklistCard } from "@/components/setup-checklist"
import { NetworkTab } from "@/components/network/network-tab"
import { VpnTab } from "@/components/vpn/vpn-tab"
import { ProviderKeys } from "@/components/provider-keys"
import { AuditCard } from "@/components/users/audit-card"
import { UsersCard } from "@/components/users/users-card"
import { useAuth } from "@/app/auth"
import { ALERTS_SETTINGS } from "@/app/nav"
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { SkeletonText } from "@/components/skeletons"
import { api, queryKeys } from "@/lib/api"
import { settingsHelpId } from "@/lib/help"
import { formatAbsolute, formatBytes, formatNumber } from "@/lib/format"
import {
  enrichmentFinding,
  geoAgeDays,
  keyInFlight,
  retentionFinding,
  sensorsFinding,
  storageFinding,
  usageTone,
  type DiskGuard,
  type SensorState,
  type SystemSettings,
} from "@/lib/settings"
import { cn } from "@/lib/utils"

/* --- Small pieces ------------------------------------------------------- */

const SENSOR_STATE: Record<SensorState, { labelKey: string; icon: LucideIcon; className: string }> =
  {
    active: {
      labelKey: tk("settings_sensor_active"),
      icon: CircleCheck,
      className: "text-status-ok",
    },
    quiet: {
      labelKey: tk("settings_sensor_quiet"),
      icon: CircleDashed,
      className: "text-fg-muted",
    },
    silent: {
      labelKey: tk("settings_sensor_silent"),
      icon: TriangleAlert,
      className: "text-sev-warning",
    },
  }

function StateLabel({
  icon: Icon,
  label,
  className,
}: {
  icon: LucideIcon
  label: string
  className: string
}) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium", className)}>
      <Icon aria-hidden className="size-3.5" strokeWidth={2.25} />
      {label}
    </span>
  )
}

function Field({
  label,
  children,
  className,
}: {
  label: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={cn("min-w-0 space-y-1", className)}>
      <dt className="text-xs text-fg-muted">{label}</dt>
      <dd className="text-sm text-fg">{children}</dd>
    </div>
  )
}

function Loading() {
  return <SkeletonText lines={4} className="py-1" />
}

function Failed() {
  return <p className="text-sm text-fg-muted">{t("settings_status_unavailable")}</p>
}

/* --- Sensors ------------------------------------------------------------ */

function SensorsCard({ data, loading }: { data?: SystemSettings; loading: boolean }) {
  return (
    <FindingCard
      eyebrow={t("settings_sensors_title")}
      help="sensors"
      finding={data ? sensorsFinding(data.sensors) : t("settings_sensors_checking")}
      detail={t("settings_sensors_detail")}
      bodyClassName="px-0 sm:px-0 pt-3 pb-1 sm:pb-1"
    >
      {loading ? (
        <div className="px-4 sm:px-5">
          <Loading />
        </div>
      ) : !data ? (
        <div className="px-4 sm:px-5">
          <Failed />
        </div>
      ) : (
        // Two columns from 1280 px: twelve sensors take six rows instead of twelve. Each row draws its
        // own top rule (none on the first row), and the left column a rule on its right. From 1760 px
        // the card is one column of the General tab, so the list goes back to one column.
        <ul
          aria-label={t("settings_sensors_title")}
          className="grid grid-cols-1 border-t min-[1280px]:grid-cols-2 min-[1760px]:grid-cols-1"
        >
          {data.sensors.map((s) => {
            const state = SENSOR_STATE[s.status]
            return (
              <li
                key={s.sensor}
                className="grid grid-cols-[5.5rem_1fr_auto] items-center gap-x-3 gap-y-1 border-t px-4 py-3 first:border-t-0 min-[1280px]:odd:border-r min-[1760px]:odd:border-r-0 sm:grid-cols-[6rem_7rem_1fr_auto] sm:px-5 min-[1280px]:[&:nth-child(2)]:border-t-0 min-[1760px]:[&:nth-child(2)]:border-t"
              >
                <SensorBadge sensor={s.sensor} className="justify-self-start" />
                <StateLabel
                  label={t(state.labelKey)}
                  icon={state.icon}
                  className={state.className}
                />
                <span className="col-span-3 row-start-2 text-xs text-fg-muted sm:col-span-1 sm:col-start-3 sm:row-start-1">
                  {s.last_event_at
                    ? tNodes(
                        "settings_sensor_last_event",
                        {},
                        { time: <RelativeTime iso={s.last_event_at} className="text-xs" /> },
                      )
                    : t("settings_sensor_no_event")}
                </span>
                <Link
                  to={`/attacks?sensor=${s.sensor}`}
                  className="col-start-3 row-start-1 justify-self-end text-right text-xs text-fg-muted transition-colors hover:text-fg sm:col-start-4"
                >
                  {tNodes(
                    "settings_sensor_last_hour",
                    {},
                    {
                      count: (
                        <span className="text-sm font-medium text-fg">
                          {formatNumber(s.events_last_hour)}
                        </span>
                      ),
                    },
                  )}
                </Link>
              </li>
            )
          })}
        </ul>
      )}
    </FindingCard>
  )
}

/* --- Enrichment --------------------------------------------------------- */

function EnrichmentCard() {
  const q = useQuery({
    queryKey: queryKeys.enrichmentSettings,
    queryFn: api.enrichmentSettings,
    // While a saved key or a test is still going through ingest, look again every few seconds.
    refetchInterval: (query) => {
      const d = query.state.data
      return d &&
        [d.abuseipdb, d.greynoise, d.maxmind, d.nvd, d.github, d.abusech, d.virustotal].some((k) =>
          keyInFlight(k),
        )
        ? 3_000
        : false
    },
  })
  const e = q.data
  const age = e ? geoAgeDays(e) : null
  const provider =
    e?.geoip.provider === "maxmind"
      ? "MaxMind GeoLite2"
      : e?.geoip.provider === "dbip"
        ? "DB-IP Lite"
        : t("common_off")
  return (
    <FindingCard
      eyebrow={t("settings_enrichment_title")}
      finding={e ? enrichmentFinding(e) : t("settings_enrichment_checking")}
    >
      {q.isPending ? (
        <Loading />
      ) : !e ? (
        <Failed />
      ) : (
        <div className="space-y-5">
          <dl className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Field label={t("settings_geo_database")}>{provider}</Field>
            <Field label={t("settings_geo_age")}>
              {age !== null ? t("settings_days", { count: Math.round(age) }) : "–"}
              {e.geoip.refresh_days ? (
                <span className="text-fg-muted">
                  {" "}
                  · {t("settings_geo_refreshed", { count: e.geoip.refresh_days })}
                </span>
              ) : null}
            </Field>
            {Object.entries(e.geoip.files).map(([kind, f]) => (
              <Field
                key={kind}
                label={t("settings_geo_file", { kind: kind.toUpperCase() })}
                className="col-span-2 sm:col-span-1"
              >
                <span className="block truncate font-mono text-xs">{f.file}</span>
                <span className="text-xs text-fg-muted">{formatBytes(f.bytes)}</span>
              </Field>
            ))}
          </dl>
          {e.geoip.last_error ? (
            <p className="text-xs text-sev-warning">{e.geoip.last_error}</p>
          ) : null}
          {e.geoip.attribution ? (
            <p className="rounded-md border bg-bg px-3 py-2 text-xs text-fg-muted">
              {e.geoip.attribution}
            </p>
          ) : null}
          <div className="border-t pt-5">
            <ProviderKeys e={e} />
          </div>
        </div>
      )}
    </FindingCard>
  )
}

/* --- Storage and retention --------------------------------------------- */

function guardState(g: DiskGuard): { label: string; icon: LucideIcon; className: string } {
  if (g.state === "critical")
    return { label: t("settings_guard_critical"), icon: OctagonAlert, className: "text-sev-severe" }
  if (g.state === "trimmed")
    return {
      label: t("settings_guard_trimmed"),
      icon: TriangleAlert,
      className: "text-sev-warning",
    }
  return { label: t("settings_guard_ok"), icon: CircleCheck, className: "text-status-ok" }
}

function StorageCard({ data, loading }: { data?: SystemSettings; loading: boolean }) {
  const size = data?.database.size_bytes ?? null
  const max = data?.database.max_bytes ?? data?.disk_guard?.max_bytes ?? null
  const g = data?.disk_guard ?? null
  const ing = data?.ingest_disk ?? null
  return (
    <FindingCard
      eyebrow={t("settings_storage_title")}
      help="storage"
      finding={data ? storageFinding(data) : t("settings_storage_checking")}
    >
      {loading ? (
        <Loading />
      ) : !data ? (
        <Failed />
      ) : (
        <div className="space-y-5">
          {size !== null && max ? (
            <div className="space-y-2">
              <div className="flex items-baseline justify-between gap-3 text-sm">
                <span className="text-fg">{t("settings_storage_database")}</span>
                <span className="text-xs text-fg-muted">
                  {tNodes(
                    "settings_storage_of",
                    { max: formatBytes(max) },
                    {
                      size: (
                        <span className="text-sm font-medium text-fg">{formatBytes(size)}</span>
                      ),
                    },
                  )}
                </span>
              </div>
              <Meter
                value={size}
                max={max}
                label={t("settings_storage_meter")}
                valueText={t("settings_storage_of", {
                  size: formatBytes(size),
                  max: formatBytes(max),
                })}
                tone={g?.state === "critical" ? "severe" : usageTone(size / max)}
              />
            </div>
          ) : null}
          <dl className="grid grid-cols-2 gap-4">
            <Field label={t("settings_storage_guard")}>
              {g ? (
                <StateLabel {...guardState(g)} />
              ) : (
                <span className="text-fg-muted">{t("settings_storage_not_reported")}</span>
              )}
            </Field>
            <Field label={t("settings_storage_last_trim")}>
              {g?.last_trim_at ? (
                <>
                  <RelativeTime iso={g.last_trim_at} className="text-sm" />
                  {g.last_trim_chunks ? (
                    <span className="text-fg-muted">
                      {" "}
                      · {t("settings_chunks", { count: g.last_trim_chunks })}
                    </span>
                  ) : null}
                </>
              ) : (
                <span className="text-fg-muted">{t("settings_storage_never_trimmed")}</span>
              )}
            </Field>
            {ing ? (
              <Field label={t("settings_storage_spool")} className="col-span-2">
                <span>
                  {formatBytes(ing.size_bytes)} of {formatBytes(ing.max_bytes)}
                </span>
                {ing.degraded ? (
                  <span className="text-sev-warning">
                    {" "}
                    · {t("settings_storage_degraded", { count: ing.degraded_writes })}
                  </span>
                ) : (
                  <span className="text-fg-muted"> · {t("settings_storage_healthy")}</span>
                )}
              </Field>
            ) : null}
          </dl>
        </div>
      )}
    </FindingCard>
  )
}

function RetentionCard({ data, loading }: { data?: SystemSettings; loading: boolean }) {
  const r = data?.retention
  return (
    <FindingCard
      eyebrow={t("settings_retention_title")}
      help="storage"
      finding={r ? retentionFinding(r, data.disk_guard) : t("settings_retention_checking")}
    >
      {loading ? (
        <Loading />
      ) : !r ? (
        <Failed />
      ) : (
        <dl className="grid grid-cols-2 gap-4">
          <Field label={t("settings_retention_raw")}>
            {r.raw_days
              ? t("settings_days", { count: r.raw_days })
              : t("settings_retention_until_trimmed")}
          </Field>
          <Field label={t("settings_retention_compressed")}>
            {r.compression_after_days
              ? t("settings_days", { count: r.compression_after_days })
              : "–"}
          </Field>
          <Field label={t("settings_retention_oldest")} className="col-span-2">
            {r.oldest_event_at ? formatAbsolute(r.oldest_event_at) : "–"}
          </Field>
          <Field label={t("settings_retention_aggregates")} className="col-span-2">
            <span className="mt-1 flex flex-wrap gap-1.5">
              {r.aggregates.map((a) => (
                <code
                  key={a}
                  className="rounded-sm border px-1.5 py-0.5 font-mono text-2xs text-fg-muted"
                >
                  {a}
                </code>
              ))}
            </span>
          </Field>
        </dl>
      )}
    </FindingCard>
  )
}

/* --- Page --------------------------------------------------------------- */

// The styleguide ships with development and mock builds only (see the route table).
const SHOW_STYLEGUIDE = import.meta.env.DEV || import.meta.env.VITE_MOCK === "1"

/** The guided tour and, where it ships, the styleguide: help about the app itself. */
function SettingsActions() {
  return (
    <>
      <TourButton />
      {SHOW_STYLEGUIDE ? (
        <Button asChild variant="outline" size="sm" className="text-fg-muted hover:text-fg">
          <Link to="/styleguide">
            <SwatchBook aria-hidden className="size-4" strokeWidth={1.85} />
            {t("settings_styleguide")}
          </Link>
        </Button>
      ) : null}
    </>
  )
}

const TABS = [
  { id: "general", labelKey: tk("settings_tab_general"), adminOnly: false },
  { id: "keys", labelKey: tk("settings_tab_keys"), adminOnly: false },
  { id: "users", labelKey: tk("settings_tab_users"), adminOnly: true },
  { id: "audit", labelKey: tk("settings_tab_audit"), adminOnly: true },
  { id: "ports", labelKey: tk("settings_tab_ports"), adminOnly: true },
  { id: "alert-rules", labelKey: tk("settings_tab_alert_rules"), adminOnly: false },
  { id: "alerts", labelKey: tk("settings_tab_alert_channels"), adminOnly: false },
  { id: "feeds", labelKey: tk("settings_tab_feeds"), adminOnly: true },
  { id: "reporting", labelKey: tk("settings_tab_reporting"), adminOnly: true },
  { id: "vpn", labelKey: tk("settings_tab_vpn"), adminOnly: true },
  { id: "network", labelKey: tk("settings_tab_network"), adminOnly: false },
] as const

export function SettingsPage() {
  const { canWrite } = useAuth()
  const tabs = TABS.filter((item) => canWrite || !item.adminOnly)
  const [tabParam, setTabParam] = useUrlParam("tab")
  const tab = tabs.find((x) => x.id === tabParam)?.id ?? "general"
  // The tab lives in the URL, so a section can be linked; "general" is the default and stays bare.
  const setTab = (next: string) => setTabParam(next === "general" ? null : next)
  const q = useQuery({
    queryKey: queryKeys.systemSettings,
    queryFn: api.systemSettings,
    refetchInterval: 60_000,
  })
  return (
    <>
      <PageHeader
        help={settingsHelpId(tab)}
        title={t("settings_title")}
        description={canWrite ? t("settings_description_admin") : t("settings_description_viewer")}
        actions={<SettingsActions />}
      />

      <div className="mb-6 flex items-start gap-2.5 rounded-lg border border-dashed px-4 py-3 text-sm text-fg-muted">
        <Info aria-hidden className="mt-0.5 size-4 shrink-0" />
        {canWrite && tab === "reporting" ? (
          <p>
            {tNodes(
              "settings_note_reporting",
              {},
              {
                flag: <code className="font-mono text-fg">ABUSE_REPORTS_ENABLED</code>,
                env: <code className="font-mono text-fg">.env</code>,
              },
            )}
          </p>
        ) : canWrite ? (
          <p>
            {tNodes(
              "settings_note_admin",
              {},
              {
                env: <code className="font-mono text-fg">.env</code>,
                command: <code className="font-mono text-fg">docker compose up -d</code>,
                example: <code className="font-mono">.env.example</code>,
              },
            )}
          </p>
        ) : (
          <p>
            {tNodes("settings_note_viewer", {}, { env: <code className="font-mono">.env</code> })}
          </p>
        )}
      </div>

      {/*
       * The sections: a list down the left from `lg`, a select on a phone and a tablet. Eleven
       * tabs never fit one row, and a strip that scrolls sideways hides the ones at its end.
       */}
      <Tabs
        value={tab}
        onValueChange={setTab}
        orientation="vertical"
        className="gap-4 max-lg:flex-col lg:flex-row lg:items-start lg:gap-8"
      >
        <div className="lg:hidden">
          <Select value={tab} onValueChange={setTab}>
            <SelectTrigger aria-label={t("settings_tabs_label")} className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {tabs.map((item) => (
                <SelectItem key={item.id} value={item.id}>
                  {t(item.labelKey)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <TabsList
          variant="line"
          aria-label={t("settings_tabs_label")}
          className="hidden w-52 shrink-0 gap-0.5 p-0 lg:sticky lg:top-20 lg:flex lg:flex-col lg:items-stretch"
        >
          {tabs.map((item) => (
            <TabsTrigger
              key={item.id}
              value={item.id}
              className="h-8 flex-none justify-start rounded-md px-3 after:hidden group-data-[variant=line]/tabs-list:data-[state=active]:bg-surface-hover dark:group-data-[variant=line]/tabs-list:data-[state=active]:bg-surface-hover"
            >
              {t(item.labelKey)}
            </TabsTrigger>
          ))}
        </TabsList>

        <div className="min-w-0 flex-1">
          {/* Wide screens: setup and sensors on the left, the system's health stacked on the right.
            Each column is its own stack, so a short card never leaves a hole beside a tall one. */}
          <TabsContent value="general" className="grid grid-cols-1 gap-4">
            <SetupResumeCard />
            <div className="grid grid-cols-1 gap-4 min-[1760px]:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] min-[1760px]:items-start">
              <div className="grid grid-cols-1 gap-4">
                <SetupChecklistCard />
                <SensorsCard data={q.data} loading={q.isPending} />
              </div>
              <div className="grid grid-cols-1 gap-4 min-[1360px]:grid-cols-2 min-[1760px]:grid-cols-1">
                <LanguageCard />
                <UpdatesCard />
                <PipelineCard />
                <StorageCard data={q.data} loading={q.isPending} />
                <RetentionCard data={q.data} loading={q.isPending} />
                <div className="min-[1360px]:col-span-2 min-[1760px]:col-span-1">
                  <EgressCard />
                </div>
              </div>
            </div>
          </TabsContent>
          <TabsContent value="keys" className="grid grid-cols-1 gap-4">
            <EnrichmentCard />
          </TabsContent>
          {canWrite ? (
            <>
              <TabsContent value="users" className="grid grid-cols-1 gap-4">
                <UsersCard />
              </TabsContent>
              <TabsContent value="audit" className="grid grid-cols-1 gap-4">
                <AuditCard />
              </TabsContent>
            </>
          ) : null}
          {canWrite ? (
            <TabsContent value="ports" className="grid grid-cols-1 gap-4">
              <PortsCard />
            </TabsContent>
          ) : null}
          <TabsContent value="alert-rules">
            <AlertsPanel />
          </TabsContent>
          <TabsContent value="alerts" className="grid grid-cols-1 gap-4">
            <ChannelsCard />
            <p className="text-sm text-fg-muted">
              {tNodes(
                "settings_alerts_note",
                {},
                {
                  link: (
                    <Link to={ALERTS_SETTINGS} className="text-fg underline underline-offset-4">
                      {t("settings_alerts_note_link")}
                    </Link>
                  ),
                },
              )}
            </p>
          </TabsContent>
          {canWrite ? (
            <TabsContent value="feeds">
              <FeedsTab />
            </TabsContent>
          ) : null}
          {canWrite ? (
            <TabsContent value="reporting" className="grid grid-cols-1 gap-4">
              <ReportingNav />
              {/* Wide screens: what a report says on the left, how it travels on the right. */}
              <div className="grid grid-cols-1 gap-4 min-[1760px]:grid-cols-2 min-[1760px]:items-start">
                <div className="grid grid-cols-1 gap-4">
                  <ReportingCard />
                </div>
                <div className="grid grid-cols-1 gap-4">
                  <section id="reporting-sending" className="scroll-mt-16">
                    <SendingCard />
                  </section>
                  <section id="reporting-digest" className="scroll-mt-16">
                    <DigestCard />
                  </section>
                  <section id="reporting-replies" className="scroll-mt-16">
                    <ImapCard />
                  </section>
                </div>
              </div>
            </TabsContent>
          ) : null}
          {canWrite ? (
            <TabsContent value="vpn">
              <VpnTab />
            </TabsContent>
          ) : null}
          <TabsContent value="network" className="grid grid-cols-1 gap-4">
            <NetworkTab />
            <p className="text-sm text-fg-muted">
              {tNodes(
                "settings_network_note",
                {},
                {
                  link: (
                    <Link to="/network" className="text-fg underline underline-offset-4">
                      {t("settings_network_note_link")}
                    </Link>
                  ),
                },
              )}
            </p>
          </TabsContent>
        </div>
      </Tabs>
    </>
  )
}
