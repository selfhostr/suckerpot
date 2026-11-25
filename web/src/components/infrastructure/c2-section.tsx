import { useInfiniteQuery } from "@tanstack/react-query"
import { LoadMore } from "@/components/load-more"
import { Check, ChevronRight, Copy, ExternalLink, Radio, SearchX } from "lucide-react"
import { useIpMask } from "@/app/ip-mask"
import { EmptyState } from "@/components/empty-state"
import { Explain } from "@/components/explain"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonList } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useCopy } from "@/hooks/use-copy"
import { api, queryKeys } from "@/lib/api"
import {
  c2References,
  C2_CONFIDENCE_LABELS,
  describeC2,
  referenceLabel,
  type C2Address,
} from "@/lib/c2"
import { formatAbsolute, formatNumber, plural } from "@/lib/format"
import { maskDefanged } from "@/lib/infrastructure"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 10

/** Copies the defanged form, so the address never becomes a live link in a ticket. */
function CopyAddress({ text }: { text: string }) {
  const { copied, copy } = useCopy()
  const { masked } = useIpMask()
  if (masked) return null
  const label = copied ? "Copied" : "Copy defanged address"
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={() => void copy(text)}
          aria-label={label}
          className="inline-flex size-7 shrink-0 items-center justify-center rounded-sm text-fg-subtle transition-colors duration-150 hover:bg-surface-raised hover:text-fg"
        >
          {copied ? (
            <Check aria-hidden className="size-3.5" />
          ) : (
            <Copy aria-hidden className="size-3.5" />
          )}
        </button>
      </TooltipTrigger>
      <TooltipContent side="top">{label}</TooltipContent>
    </Tooltip>
  )
}

function ConfidenceBadge({ confidence }: { confidence: C2Address["confidence"] }) {
  const high = confidence === "high"
  return (
    <span
      className={cn(
        "inline-flex h-6 shrink-0 items-center rounded-sm border px-2 text-xs font-medium whitespace-nowrap",
        // Red is reserved for severe events: a ThreatFox-reported C2 qualifies, a sandbox contact does not.
        high ? "tint-severe border-sev-severe/30 text-sev-severe" : "border-border text-fg-muted",
      )}
    >
      {C2_CONFIDENCE_LABELS[confidence]}
    </span>
  )
}

function C2Row({ item }: { item: C2Address }) {
  const { masked } = useIpMask()
  const shown = masked ? maskDefanged(item.defanged) : item.defanged
  const refs = c2References(item)
  return (
    <div className="space-y-2 px-4 py-3 sm:px-5">
      <div className="flex items-center justify-between gap-3">
        <p className="min-w-0 truncate font-mono text-sm text-fg" title={shown}>
          {shown}
          {item.port !== null ? <span className="text-fg-muted">:{item.port}</span> : null}
        </p>
        <CopyAddress text={item.port !== null ? `${item.defanged}:${item.port}` : item.defanged} />
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs text-fg-muted">
        <ConfidenceBadge confidence={item.confidence} />
        {item.families.length > 0 ? (
          <span className="text-sm text-fg">{item.families.join(", ")}</span>
        ) : (
          <span className="text-fg-subtle">No family named</span>
        )}
        <span className="tabular-nums">
          {item.sessions > 0
            ? `${plural(item.sessions, "session")} dropped this malware`
            : "No session of ours dropped it"}
        </span>
        {refs.map((url) => (
          <a
            key={url}
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded-sm text-fg underline decoration-fg-subtle underline-offset-4 hover:decoration-fg"
          >
            {referenceLabel(url)}
            <ExternalLink aria-hidden className="size-3" />
            <span className="sr-only">(opens in a new tab)</span>
          </a>
        ))}
      </div>
      <details className="group/details">
        <summary className="inline-flex cursor-pointer list-none items-center gap-1 rounded-sm text-xs text-fg-muted hover:text-fg [&::-webkit-details-marker]:hidden">
          <ChevronRight
            aria-hidden
            className="size-3.5 transition-transform duration-150 group-open/details:rotate-90"
          />
          Technical details
        </summary>
        <dl className="mt-2 space-y-2 pl-4 text-xs">
          <div>
            <dt className="text-2xs font-medium tracking-wide text-fg-subtle uppercase">
              Files that contact it ({formatNumber(item.hash_count)})
            </dt>
            <dd className="mt-1 space-y-1">
              {item.hashes.map((h) => (
                <p key={h.sha256} className="font-mono break-all text-fg-muted">
                  {h.sha256}
                  {h.family ? <span className="font-sans text-fg"> · {h.family}</span> : null}
                </p>
              ))}
              {item.hash_count > item.hashes.length ? (
                <p className="text-fg-subtle">
                  and {formatNumber(item.hash_count - item.hashes.length)} more
                </p>
              ) : null}
            </dd>
          </div>
          <div className="flex flex-wrap gap-x-6 gap-y-1 text-fg-muted">
            <p>
              First seen{" "}
              <time dateTime={item.first_seen} className="text-fg tabular-nums">
                {formatAbsolute(item.first_seen)}
              </time>
            </p>
            <p>
              Last dropped here{" "}
              <time dateTime={item.last_seen} className="text-fg tabular-nums">
                {formatAbsolute(item.last_seen)}
              </time>{" "}
              (<RelativeTime iso={item.last_seen} className="text-xs" />)
            </p>
          </div>
        </dl>
      </details>
    </div>
  )
}

/** Addresses that malware dropped on the decoys is said to contact. Text only, never a link. */
export function C2Section({ className }: { className?: string }) {
  const query = useInfiniteQuery({
    queryKey: queryKeys.c2(),
    queryFn: ({ pageParam }) => api.c2(pageParam, PAGE_SIZE),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const rows = query.data?.pages.flatMap((p) => p.items) ?? []
  const sentence = query.isSuccess
    ? describeC2(rows, query.hasNextPage)
    : "Looking for control servers of the malware dropped here…"

  return (
    <section aria-labelledby="c2-heading" className={className}>
      <div className="mb-3 space-y-1">
        <h2 id="c2-heading" className="text-sm font-medium text-fg">
          Probable <Explain term="c2">C2</Explain>
        </h2>
        <p className="text-sm text-fg-muted">{sentence}</p>
      </div>
      <div className="overflow-hidden rounded-lg border bg-surface shadow-sm">
        {query.isPending ? (
          <SkeletonList rows={3} />
        ) : query.isError ? (
          <EmptyState
            variant="bare"
            icon={SearchX}
            title="Could not load the control servers"
            description={query.error.message}
            action={
              <Button variant="outline" size="sm" onClick={() => void query.refetch()}>
                Try again
              </Button>
            }
          />
        ) : rows.length === 0 ? (
          <EmptyState
            variant="bare"
            icon={Radio}
            title="No C2 address known yet"
            description="It appears once VirusTotal or ThreatFox has analysed a file dropped here."
          />
        ) : (
          <ul aria-label="Probable C2 addresses" className="divide-y">
            {rows.map((item) => (
              <li key={`${item.kind}:${item.address}`}>
                <C2Row item={item} />
              </li>
            ))}
          </ul>
        )}
      </div>
      <LoadMore
        hasNextPage={query.hasNextPage}
        isFetchingNextPage={query.isFetchingNextPage}
        fetchNextPage={query.fetchNextPage}
        label="Show more"
      />
    </section>
  )
}
