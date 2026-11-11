import { useQuery } from "@tanstack/react-query"
import {
  CircleCheck,
  CircleDashed,
  Info,
  OctagonAlert,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react"
import { useEffect, useRef } from "react"
import { Link } from "react-router"
import { ReportingCard } from "@/components/abuse/reporting-card"
import { ReportingNav } from "@/components/abuse/reporting-nav"
import { ImapCard } from "@/components/abuse/imap-card"
import { SendingCard } from "@/components/abuse/sending-card"
import { ChannelsCard } from "@/components/alerts/channels-card"
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
import { RelativeTime } from "@/components/relative-time"
import { SensorBadge } from "@/components/sensor-badge"
import { SkeletonText } from "@/components/skeletons"
import { api, queryKeys } from "@/lib/api"
import { settingsHelpId } from "@/lib/help"
import { formatAbsolute, formatBytes, formatNumber, plural } from "@/lib/format"
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

const SENSOR_STATE: Record<SensorState, { label: string; icon: LucideIcon; className: string }> = {
  active: { label: "Active", icon: CircleCheck, className: "text-status-ok" },
  quiet: { label: "Quiet", icon: CircleDashed, className: "text-fg-muted" },
  silent: { label: "Silent", icon: TriangleAlert, className: "text-sev-warning" },
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
  return <p className="text-sm text-fg-muted">This status is not available right now.</p>
}

/* --- Sensors ------------------------------------------------------------ */

function SensorsCard({ data, loading }: { data?: SystemSettings; loading: boolean }) {
  return (
    <FindingCard
      eyebrow="Sensors"
      finding={data ? sensorsFinding(data.sensors) : "Checking the sensors…"}
      detail="Active: an event in the last 15 minutes. Quiet: in the last 24 hours. Silent: nothing for longer."
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
        <ul aria-label="Sensors" className="divide-y border-t">
          {data.sensors.map((s) => {
            const state = SENSOR_STATE[s.status]
            return (
              <li
                key={s.sensor}
                className="grid grid-cols-[5.5rem_1fr_auto] items-center gap-x-3 gap-y-1 px-4 py-3 sm:grid-cols-[6rem_7rem_1fr_auto] sm:px-5"
              >
                <SensorBadge sensor={s.sensor} className="justify-self-start" />
                <StateLabel {...state} />
                <span className="col-span-3 row-start-2 text-xs text-fg-muted sm:col-span-1 sm:col-start-3 sm:row-start-1">
                  {s.last_event_at ? (
                    <>
                      Last event <RelativeTime iso={s.last_event_at} className="text-xs" />
                    </>
                  ) : (
                    "No event recorded yet"
                  )}
                </span>
                <Link
                  to={`/attacks?sensor=${s.sensor}`}
                  className="col-start-3 row-start-1 justify-self-end text-right text-xs text-fg-muted transition-colors hover:text-fg sm:col-start-4"
                >
                  <span className="text-sm font-medium text-fg">
                    {formatNumber(s.events_last_hour)}
                  </span>{" "}
                  in the last hour
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
        : "Off"
  return (
    <FindingCard eyebrow="Enrichment" finding={e ? enrichmentFinding(e) : "Checking enrichment…"}>
      {q.isPending ? (
        <Loading />
      ) : !e ? (
        <Failed />
      ) : (
        <div className="space-y-5">
          <dl className="grid grid-cols-2 gap-4">
            <Field label="GeoIP database">{provider}</Field>
            <Field label="Age">
              {age !== null ? plural(Math.round(age), "day") : "–"}
              {e.geoip.refresh_days ? (
                <span className="text-fg-muted">
                  {" "}
                  · refreshed every {e.geoip.refresh_days} days
                </span>
              ) : null}
            </Field>
            {Object.entries(e.geoip.files).map(([kind, f]) => (
              <Field
                key={kind}
                label={`${kind.toUpperCase()} file`}
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
    return { label: "Critical", icon: OctagonAlert, className: "text-sev-severe" }
  if (g.state === "trimmed")
    return { label: "Trimmed old data", icon: TriangleAlert, className: "text-sev-warning" }
  return { label: "OK", icon: CircleCheck, className: "text-status-ok" }
}

function StorageCard({ data, loading }: { data?: SystemSettings; loading: boolean }) {
  const size = data?.database.size_bytes ?? null
  const max = data?.database.max_bytes ?? data?.disk_guard?.max_bytes ?? null
  const g = data?.disk_guard ?? null
  const ing = data?.ingest_disk ?? null
  return (
    <FindingCard eyebrow="Storage" finding={data ? storageFinding(data) : "Checking storage…"}>
      {loading ? (
        <Loading />
      ) : !data ? (
        <Failed />
      ) : (
        <div className="space-y-5">
          {size !== null && max ? (
            <div className="space-y-2">
              <div className="flex items-baseline justify-between gap-3 text-sm">
                <span className="text-fg">Database</span>
                <span className="text-xs text-fg-muted">
                  <span className="text-sm font-medium text-fg">{formatBytes(size)}</span> of{" "}
                  {formatBytes(max)}
                </span>
              </div>
              <Meter
                value={size}
                max={max}
                label="Database size against its ceiling"
                valueText={`${formatBytes(size)} of ${formatBytes(max)}`}
                tone={g?.state === "critical" ? "severe" : usageTone(size / max)}
              />
            </div>
          ) : null}
          <dl className="grid grid-cols-2 gap-4">
            <Field label="Disk guard">
              {g ? (
                <StateLabel {...guardState(g)} />
              ) : (
                <span className="text-fg-muted">Not reported</span>
              )}
            </Field>
            <Field label="Last trim">
              {g?.last_trim_at ? (
                <>
                  <RelativeTime iso={g.last_trim_at} className="text-sm" />
                  {g.last_trim_chunks ? (
                    <span className="text-fg-muted"> · {plural(g.last_trim_chunks, "chunk")}</span>
                  ) : null}
                </>
              ) : (
                <span className="text-fg-muted">Never needed</span>
              )}
            </Field>
            {ing ? (
              <Field label="Ingest spool" className="col-span-2">
                <span>
                  {formatBytes(ing.size_bytes)} of {formatBytes(ing.max_bytes)}
                </span>
                {ing.degraded ? (
                  <span className="text-sev-warning">
                    {" "}
                    · degraded, {plural(ing.degraded_writes, "write")} held back
                  </span>
                ) : (
                  <span className="text-fg-muted"> · healthy</span>
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
      eyebrow="Data retention"
      finding={r ? retentionFinding(r, data.disk_guard) : "Checking retention…"}
    >
      {loading ? (
        <Loading />
      ) : !r ? (
        <Failed />
      ) : (
        <dl className="grid grid-cols-2 gap-4">
          <Field label="Raw events">
            {r.raw_days ? plural(r.raw_days, "day") : "Until trimmed"}
          </Field>
          <Field label="Compressed after">
            {r.compression_after_days ? plural(r.compression_after_days, "day") : "–"}
          </Field>
          <Field label="Oldest stored event" className="col-span-2">
            {r.oldest_event_at ? formatAbsolute(r.oldest_event_at) : "–"}
          </Field>
          <Field label="Aggregates, kept forever" className="col-span-2">
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

const TABS = [
  { id: "general", label: "General", adminOnly: false },
  { id: "keys", label: "Keys", adminOnly: false },
  { id: "users", label: "Users", adminOnly: true },
  { id: "audit", label: "Audit", adminOnly: true },
  { id: "ports", label: "Sensors & ports", adminOnly: true },
  { id: "alerts", label: "Alert channels", adminOnly: false },
  { id: "feeds", label: "Feeds", adminOnly: true },
  { id: "reporting", label: "Reporting", adminOnly: true },
  { id: "vpn", label: "VPN", adminOnly: true },
  { id: "network", label: "Network", adminOnly: false },
] as const

export function SettingsPage() {
  const { canWrite } = useAuth()
  const tabs = TABS.filter((t) => canWrite || !t.adminOnly)
  const [tabParam, setTabParam] = useUrlParam("tab")
  const tab = tabs.find((t) => t.id === tabParam)?.id ?? "general"
  // The tab lives in the URL, so a section can be linked; "general" is the default and stays bare.
  const setTab = (next: string) => setTabParam(next === "general" ? null : next)
  // On phones the tab strip scrolls sideways: keep the open tab in view (e.g. ?tab=feeds).
  const tabsRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const list = tabsRef.current
    const active = list?.querySelector<HTMLElement>('[data-state="active"]')
    if (!list || !active) return
    const a = active.getBoundingClientRect()
    const l = list.getBoundingClientRect()
    if (a.left < l.left || a.right > l.right) list.scrollLeft += a.left - l.left - 16
  }, [tab])
  const q = useQuery({
    queryKey: queryKeys.systemSettings,
    queryFn: api.systemSettings,
    refetchInterval: 60_000,
  })
  return (
    <>
      <PageHeader
        help={settingsHelpId(tab)}
        title="Settings"
        description={
          canWrite
            ? "Sensor health, enrichment keys, users, retention and storage, one tab each."
            : "Sensor health, enrichment, retention and storage."
        }
      />

      <div className="mb-6 flex items-start gap-2.5 rounded-lg border border-dashed px-4 py-3 text-sm text-fg-muted">
        <Info aria-hidden className="mt-0.5 size-4 shrink-0" />
        {canWrite && tab === "reporting" ? (
          <p>
            Reporting settings are saved here. Only the server switches, such as{" "}
            <code className="font-mono text-fg">ABUSE_REPORTS_ENABLED</code>, live in{" "}
            <code className="font-mono text-fg">.env</code>.
          </p>
        ) : canWrite ? (
          <p>
            The enrichment API keys, the users and the alert channels can be edited below.
            Everything else lives in <code className="font-mono text-fg">.env</code>: change it
            there and restart with <code className="font-mono text-fg">docker compose up -d</code>.
            Every option is documented in <code className="font-mono">.env.example</code>.
          </p>
        ) : (
          <p>
            You have read-only access: you can look at everything here, and an administrator changes
            it. The server settings live in <code className="font-mono">.env</code>.
          </p>
        )}
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList
          ref={tabsRef}
          variant="line"
          aria-label="Settings sections"
          className="scroll-fade-x mb-2 max-w-full justify-start overflow-x-auto"
        >
          {tabs.map((t) => (
            <TabsTrigger key={t.id} value={t.id} className="flex-none px-3">
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="general" className="grid grid-cols-1 gap-4">
          <SetupResumeCard />
          <SetupChecklistCard />
          <UpdatesCard />
          <SensorsCard data={q.data} loading={q.isPending} />
          <PipelineCard />
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <StorageCard data={q.data} loading={q.isPending} />
            <RetentionCard data={q.data} loading={q.isPending} />
          </div>
          <EgressCard />
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
        <TabsContent value="alerts" className="grid grid-cols-1 gap-4">
          <ChannelsCard />
        </TabsContent>
        {canWrite ? (
          <TabsContent value="feeds">
            <FeedsTab />
          </TabsContent>
        ) : null}
        {canWrite ? (
          <TabsContent value="reporting" className="grid grid-cols-1 gap-4">
            <ReportingNav />
            <ReportingCard />
            <section id="reporting-sending" className="scroll-mt-16">
              <SendingCard />
            </section>
            <section id="reporting-replies" className="scroll-mt-16">
              <ImapCard />
            </section>
          </TabsContent>
        ) : null}
        {canWrite ? (
          <TabsContent value="vpn">
            <VpnTab />
          </TabsContent>
        ) : null}
        <TabsContent value="network" className="grid grid-cols-1 gap-4">
          <NetworkTab />
        </TabsContent>
      </Tabs>
    </>
  )
}
