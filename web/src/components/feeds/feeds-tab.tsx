import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Ban, CircleCheck, Clock, Plus, Rss, type LucideIcon } from "lucide-react"
import { useState } from "react"
import { IPChip } from "@/components/ip-chip"
import { EmptyState } from "@/components/empty-state"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SkeletonText } from "@/components/skeletons"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  defendApi,
  defendKeys,
  describeDefendError,
  feedsSentence,
  kindsPhrase,
  revokeFeedToken,
  type FeedToken,
} from "@/lib/defend"
import { plural } from "@/lib/format"
import { CreateTokenDialog, type CreatedToken } from "./create-token-dialog"
import { TokenReveal } from "./token-reveal"

const STATE: Record<FeedToken["state"], { label: string; icon: LucideIcon }> = {
  active: { label: "Active", icon: CircleCheck },
  revoked: { label: "Revoked", icon: Ban },
  expired: { label: "Expired", icon: Clock },
}

const GRID =
  "md:grid md:grid-cols-[minmax(0,1.6fr)_minmax(0,1.3fr)_6.5rem_minmax(0,1fr)_minmax(0,1.2fr)_5rem] md:items-center md:gap-x-4"

function TokenRow({ token }: { token: FeedToken }) {
  const queryClient = useQueryClient()
  const revoke = useMutation({
    mutationFn: () => revokeFeedToken(token.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: defendKeys.tokens }),
  })
  const s = STATE[token.state]
  const Icon = s.icon
  const badge = (
    <Badge variant="outline" className="text-fg">
      <Icon aria-hidden />
      {s.label}
    </Badge>
  )
  return (
    <li className={`flex flex-col gap-2 px-4 py-3.5 sm:px-5 md:py-3 ${GRID}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 space-y-0.5">
          <p className="truncate text-sm font-medium text-fg">{token.name}</p>
          <p className="font-mono text-xs text-fg-muted">{token.hint}</p>
        </div>
        {/* On phones the state sits next to the name; from md it has its own column. */}
        <div className="md:hidden">{badge}</div>
      </div>
      <div className="min-w-0 text-xs text-fg-muted">
        <span className="block text-fg first-letter:uppercase">{kindsPhrase(token.kinds)}</span>
        score {token.min_score}+{token.include_benign ? " · with research scanners" : ""}
      </div>
      <div className="hidden md:block">{badge}</div>
      <div className="text-xs text-fg-muted">
        <span className="block">
          Created <RelativeTime iso={token.created_at} className="text-xs" />
        </span>
        <span className="block">
          {token.expires_at ? (
            <>
              {token.state === "expired" ? "Expired" : "Expires"}{" "}
              <RelativeTime iso={token.expires_at} className="text-xs" />
            </>
          ) : (
            "Never expires"
          )}
        </span>
      </div>
      <div className="min-w-0 text-xs text-fg-muted">
        {token.last_used_at ? (
          <>
            <span className="block">
              Used <RelativeTime iso={token.last_used_at} className="text-xs" />
            </span>
            <span className="flex flex-wrap items-center gap-x-1.5">
              {token.last_used_ip ? (
                <>
                  <IPChip ip={token.last_used_ip} variant="ghost" href={null} copyable={false} />
                  <span aria-hidden>·</span>
                </>
              ) : null}
              <span className="whitespace-nowrap">{plural(token.use_count, "pull")}</span>
            </span>
          </>
        ) : (
          "Never used"
        )}
      </div>
      <div className="md:justify-self-end">
        {token.state === "active" ? (
          <Button
            variant="outline"
            size="sm"
            disabled={revoke.isPending}
            onClick={() => revoke.mutate()}
            aria-label={`Revoke the token ${token.name}`}
          >
            Revoke
          </Button>
        ) : null}
      </div>
    </li>
  )
}

/** Settings > Feeds (administrators): the tokens that let a firewall pull the blocklists. */
export function FeedsTab() {
  const [creating, setCreating] = useState(false)
  const [created, setCreated] = useState<CreatedToken | null>(null)
  const q = useQuery({ queryKey: defendKeys.tokens, queryFn: defendApi.feedTokens })
  const list = q.data
  const enabled = list?.enabled === true

  return (
    <div className="grid grid-cols-1 gap-4">
      <FindingCard
        eyebrow="Feeds"
        finding={q.isError ? "Feeds could not be checked right now." : feedsSentence(list)}
        detail={
          <>
            A feed is a plain list your firewall or proxy downloads by itself. It is the only part
            of this app that can be read without the dashboard login, and only with a secret token.
            If the dashboard sits behind Cloudflare Access, give{" "}
            <code className="font-mono text-fg">/feeds/*</code> a bypass policy.
          </>
        }
        action={
          <Button size="sm" disabled={!enabled} onClick={() => setCreating(true)}>
            <Plus aria-hidden />
            Create token
          </Button>
        }
      >
        {q.isPending ? (
          <SkeletonText lines={2} />
        ) : q.isError ? (
          <p className="text-sm text-fg-muted">{describeDefendError(q.error)}</p>
        ) : !enabled ? (
          <div className="flex items-start gap-2.5 rounded-md border border-dashed px-4 py-3 text-sm text-fg-muted">
            <Rss aria-hidden className="mt-0.5 size-4 shrink-0" />
            <p>
              Off is the default. To turn feeds on, set{" "}
              <code className="font-mono text-fg">FEEDS_ENABLED=true</code> in{" "}
              <code className="font-mono text-fg">.env</code> and restart the stack. Until then no
              token works and the public feed address answers nothing.
            </p>
          </div>
        ) : (
          <p className="flex items-center gap-2 text-sm text-fg-muted">
            <CircleCheck aria-hidden className="size-4 text-status-ok" />
            <span>
              Feeds are <span className="font-medium text-fg">on</span>. A request without a valid
              token gets nothing.
            </span>
          </p>
        )}
      </FindingCard>

      {created ? <TokenReveal created={created} onDismiss={() => setCreated(null)} /> : null}

      {list && list.items.length > 0 ? (
        <FindingCard
          eyebrow="Tokens"
          finding="Each token reads only the lists and the score you gave it."
          bodyClassName="px-0 sm:px-0 pt-3 pb-0 sm:pb-0"
        >
          <div className={`hidden border-y px-5 py-2.5 type-column text-fg-subtle ${GRID}`}>
            <span>Name</span>
            <span>Covers</span>
            <span>State</span>
            <span>Dates</span>
            <span>Last used</span>
            <span className="sr-only">Actions</span>
          </div>
          <ul aria-label="Feed tokens" className="divide-y border-t md:border-t-0">
            {list.items.map((t) => (
              <TokenRow key={t.id} token={t} />
            ))}
          </ul>
        </FindingCard>
      ) : list && enabled ? (
        <EmptyState
          icon={Rss}
          title="No token yet"
          description="Create a token, then give your firewall the URL. It will pull the list once a day."
        />
      ) : null}

      <CreateTokenDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(c) => setCreated(c)}
      />
    </div>
  )
}
