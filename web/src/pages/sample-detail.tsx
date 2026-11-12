import { useQuery } from "@tanstack/react-query"
import { ArrowLeft, Check, Copy, ExternalLink, FileSearch } from "lucide-react"
import { Link, useParams } from "react-router"
import { useAuth } from "@/app/auth"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { IPChip } from "@/components/ip-chip"
import { PageHeader } from "@/components/page-header"
import { RelativeTime } from "@/components/relative-time"
import { ArchiveButton } from "@/components/samples/archive-dialog"
import { BundleCard, BundleToggle } from "@/components/samples/bundle"
import { ChainSteps } from "@/components/samples/chain-steps"
import { StringsList } from "@/components/samples/strings-list"
import { SensorBadge } from "@/components/sensor-badge"
import { SessionRow } from "@/components/session-row"
import { SeverityBadge } from "@/components/severity-badge"
import { SkeletonCard } from "@/components/skeletons"
import { TagBadge } from "@/components/tag-badge"
import { Button } from "@/components/ui/button"
import { useCopy } from "@/hooks/use-copy"
import { ApiError } from "@/lib/api"
import { formatBytes, formatNumber, plural } from "@/lib/format"
import {
  describeChain,
  describeKind,
  describeSample,
  describeYara,
  familyLabel,
  LINK_KIND_LABEL,
  linkLabel,
  sampleKeys,
  samplesApi,
  type SampleDetail,
} from "@/lib/samples"

const SHA256 = /^[0-9a-f]{64}$/

function HashLine({ label, value }: { label: string; value: string }) {
  const { copied, copy } = useCopy()
  return (
    <div className="grid grid-cols-[4.5rem_minmax(0,1fr)_auto] items-center gap-x-3 py-1.5">
      <dt className="text-xs whitespace-nowrap text-fg-muted">{label}</dt>
      <dd className="font-mono text-xs break-all text-fg">{value}</dd>
      <button
        type="button"
        onClick={() => void copy(value)}
        aria-label={copied ? `${label} copied` : `Copy ${label}`}
        className="inline-flex size-7 items-center justify-center rounded-sm text-fg-subtle transition-colors hover:bg-surface-hover hover:text-fg"
      >
        {copied ? (
          <Check aria-hidden className="size-3.5" />
        ) : (
          <Copy aria-hidden className="size-3.5" />
        )}
      </button>
    </div>
  )
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <dt className="text-2xs font-medium tracking-wide text-fg-subtle uppercase">{label}</dt>
      <dd className="text-sm text-fg tabular-nums">{children}</dd>
    </div>
  )
}

function Chain({ sha256 }: { sha256: string }) {
  const q = useQuery({
    queryKey: sampleKeys.chain(sha256),
    queryFn: () => samplesApi.chain(sha256),
  })
  return (
    <FindingCard
      eyebrow="The chain"
      className="normal-nums"
      finding={
        q.isPending
          ? "Following the chain…"
          : q.isError || q.data.nodes.length === 0
            ? "The chain around this file is not available."
            : describeChain(q.data)
      }
      detail="From the session that asked for it, to the file, to the servers it talks to."
    >
      {q.isSuccess && q.data.nodes.length > 0 ? (
        <ChainSteps chain={q.data} current={sha256} />
      ) : null}
    </FindingCard>
  )
}

function Origin({ d }: { d: SampleDetail }) {
  const ips = [...new Set(d.recent_sessions.map((s) => s.src_ip))]
  return (
    <FindingCard
      eyebrow="Where it came from"
      className="normal-nums"
      finding={`Served by ${plural(d.sources.length, "URL")} to ${plural(d.item.sessions, "session")}.`}
      bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
    >
      <ul aria-label="Download URLs" className="divide-y border-t">
        {d.sources.map((s) => (
          <li
            key={s.url}
            className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1.5 px-4 py-3 sm:px-5"
          >
            <div className="min-w-0 space-y-1">
              <Link
                to={`/malware?url=${encodeURIComponent(s.url)}`}
                className="block font-mono text-xs break-all text-fg underline-offset-4 hover:underline"
              >
                {s.url}
              </Link>
              <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg-muted">
                <span>
                  {formatNumber(s.sessions)} sessions · {formatNumber(s.ips)} addresses
                </span>
                {s.sensors.map((x) => (
                  <Link key={x} to={`/attacks?sensor=${x}`} className="rounded-sm hover:opacity-80">
                    <SensorBadge sensor={x} variant="dot" />
                  </Link>
                ))}
              </p>
            </div>
            <p className="text-xs text-fg-muted">
              First fetched <RelativeTime iso={s.first_fetched} className="text-xs" /> · last{" "}
              <RelativeTime iso={s.last_fetched} className="text-xs" />
            </p>
          </li>
        ))}
      </ul>
      {ips.length > 0 ? (
        <div className="border-t px-4 py-3 sm:px-5">
          <p className="mb-2 text-xs text-fg-muted">Addresses behind the latest sessions</p>
          <ul aria-label="Addresses" className="flex flex-wrap gap-2">
            {ips.map((ip) => (
              <li key={ip}>
                <IPChip ip={ip} />
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {d.recent_sessions.length > 0 ? (
        <div
          role="list"
          aria-label="Latest sessions that fetched this file"
          className="divide-y border-t"
        >
          {d.recent_sessions.map((s) => (
            <div key={s.session_id} role="listitem">
              <SessionRow session={s} />
            </div>
          ))}
        </div>
      ) : null}
    </FindingCard>
  )
}

export function SampleDetailPage() {
  const { sha256: raw } = useParams()
  const sha256 = raw ?? ""
  const valid = SHA256.test(sha256)
  const { canWrite } = useAuth()
  const query = useQuery({
    queryKey: sampleKeys.detail(sha256),
    queryFn: () => samplesApi.detail(sha256),
    enabled: valid,
    // While the analysis is still queued, look again every few seconds.
    refetchInterval: (q) => (q.state.data?.item.analysis_status === "pending" ? 4000 : false),
    retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 2,
  })
  const back = (
    <Link to="/malware?view=samples" className="inline-flex items-center gap-1 hover:text-fg">
      <ArrowLeft aria-hidden className="size-3.5" />
      All samples
    </Link>
  )

  if (!valid || (query.isError && query.error instanceof ApiError && query.error.status === 404)) {
    return (
      <>
        <PageHeader help="sample" title="Sample" eyebrow={back} />
        <EmptyState
          icon={FileSearch}
          title="This sample is not in the collection"
          description="It may have been removed by the retention job, or the link is wrong."
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/malware?view=samples">Back to the samples</Link>
            </Button>
          }
        />
      </>
    )
  }
  if (query.isPending) {
    return (
      <>
        <PageHeader help="sample" title="Sample" eyebrow={back} />
        <div className="space-y-4" aria-busy>
          <SkeletonCard />
          <SkeletonCard />
        </div>
      </>
    )
  }
  if (query.isError) {
    return (
      <>
        <PageHeader help="sample" title="Sample" eyebrow={back} />
        <EmptyState
          icon={FileSearch}
          title="Could not load this sample"
          description={query.error.message}
          action={
            <Button variant="outline" size="sm" onClick={() => void query.refetch()}>
              Try again
            </Button>
          }
        />
      </>
    )
  }

  const d = query.data
  const item = d.item
  const a = d.analysis
  return (
    <>
      <PageHeader
        help="sample"
        title={familyLabel(item.family, item.kind)}
        eyebrow={back}
        description={<span className="normal-nums">{describeSample(d)}</span>}
        actions={
          item.stored && canWrite ? (
            <>
              <BundleToggle sha256={sha256} />
              <ArchiveButton sha256={sha256} />
            </>
          ) : undefined
        }
      />

      <div className="space-y-4">
        {canWrite ? <BundleCard /> : null}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-xs text-fg-muted">
          <SeverityBadge severity={item.severity} />
          <span>{describeKind(item)}</span>
          <a
            href={d.virustotal_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-fg underline underline-offset-4"
          >
            Look it up on VirusTotal
            <ExternalLink aria-hidden className="size-3" />
            <span className="sr-only">(opens in a new tab)</span>
          </a>
        </div>

        <FindingCard
          eyebrow="Hashes"
          finding="Fingerprints of the file, for lookups and blocklists."
        >
          <dl className="divide-y">
            <HashLine label="SHA-256" value={item.sha256} />
            <HashLine label="SHA-1" value={d.sha1} />
            <HashLine label="MD5" value={d.md5} />
            {d.tlsh ? <HashLine label="TLSH" value={d.tlsh} /> : null}
          </dl>
          <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-4 border-t pt-4 sm:grid-cols-4">
            <Fact label="Size">{formatBytes(item.size)}</Fact>
            <Fact label="First seen">
              <RelativeTime iso={item.first_seen} className="text-sm text-fg" />
            </Fact>
            <Fact label="Last seen">
              <RelativeTime iso={item.last_seen} className="text-sm text-fg" />
            </Fact>
            <Fact label="Sessions">{formatNumber(item.sessions)}</Fact>
            {d.packer ? <Fact label="Packer">{d.packer}</Fact> : null}
            {d.linking ? <Fact label="Linking">{d.linking}</Fact> : null}
            {d.endian ? <Fact label="Byte order">{d.endian}</Fact> : null}
          </dl>
        </FindingCard>

        <Origin d={d} />

        <Chain sha256={sha256} />

        <FindingCard
          eyebrow="What it matched"
          finding={describeYara(a?.yara ?? [], item.analysis_status)}
          detail="Detection rules read the file's bytes. The file is never run."
        >
          {a && a.yara.length > 0 ? (
            <ul aria-label="Detection rules" className="space-y-2">
              {a.yara.map((h) => (
                <li key={`${h.namespace}/${h.rule}`} className="flex flex-wrap items-center gap-2">
                  <TagBadge
                    tag={h.rule}
                    href={`/malware?view=samples&yara=${encodeURIComponent(h.rule)}`}
                  />
                  {h.meta.description ? (
                    <span className="text-xs text-fg-muted">{h.meta.description}</span>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : null}
          {a && a.errors.length > 0 ? (
            <ul className="mt-3 space-y-1 text-xs text-fg-muted">
              {a.errors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          ) : null}
          {d.links.length > 0 ? (
            <div className="mt-4 border-t pt-4">
              <p className="mb-2 text-xs text-fg-muted">Addresses found inside the file</p>
              <ul aria-label="Links found in the file" className="space-y-1.5">
                {d.links.map((l) => (
                  <li
                    key={`${l.kind}:${l.value}`}
                    className="flex flex-wrap items-baseline gap-x-3 text-xs"
                  >
                    <span className="w-44 shrink-0 text-fg-muted">{LINK_KIND_LABEL[l.kind]}</span>
                    <Link
                      to={`/infrastructure?q=${encodeURIComponent(l.value)}`}
                      className="font-mono break-all text-fg underline-offset-4 hover:underline"
                    >
                      {linkLabel(l)}
                    </Link>
                    <span className="text-fg-subtle">{l.confidence} confidence</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </FindingCard>

        {a?.deobfuscated ? (
          <FindingCard
            eyebrow="Deobfuscated script"
            finding={
              a.deob_steps.length > 0
                ? `The script hid its commands in ${plural(a.deob_steps.length, "layer")}; this is what is underneath.`
                : "The readable form of the script."
            }
            detail="Shown as plain text. It was decoded statically and never run."
          >
            {a.deob_steps.length > 0 ? (
              <ol
                aria-label="Decoding steps"
                className="mb-3 list-decimal space-y-0.5 pl-5 text-xs text-fg-muted"
              >
                {a.deob_steps.map((s, i) => (
                  <li key={i}>
                    {s.step}
                    {s.detail ? <span className="text-fg-subtle"> · {s.detail}</span> : null}
                  </li>
                ))}
              </ol>
            ) : null}
            <pre
              tabIndex={0}
              aria-label="Deobfuscated script"
              className="max-h-96 overflow-auto rounded-md border bg-bg p-3 font-mono text-xs break-all whitespace-pre-wrap text-fg focus-visible:ring-2 focus-visible:ring-ring"
            >
              {a.deobfuscated}
            </pre>
          </FindingCard>
        ) : null}

        {a && a.strings.length > 0 ? (
          <FindingCard
            eyebrow="Strings"
            className="normal-nums"
            finding={`${plural(a.strings.length, "readable string")} found in the file.`}
            detail="Text the file carries, in file order. Useful to spot addresses, paths and tool names."
          >
            <StringsList strings={a.strings} />
          </FindingCard>
        ) : null}
      </div>
    </>
  )
}
