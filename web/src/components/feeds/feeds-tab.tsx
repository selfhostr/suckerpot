import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Ban, CircleCheck, Clock, Plus, Rss, type LucideIcon } from "lucide-react"
import { useState } from "react"
import { IPChip } from "@/components/ip-chip"
import { t, tk } from "@/i18n"
import { tNodes } from "@/i18n/rich"
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
import { CreateTokenDialog, type CreatedToken } from "./create-token-dialog"
import { TokenReveal } from "./token-reveal"

const STATE: Record<FeedToken["state"], { labelKey: string; icon: LucideIcon }> = {
  active: { labelKey: tk("users_state_active"), icon: CircleCheck },
  revoked: { labelKey: tk("feeds_state_revoked"), icon: Ban },
  expired: { labelKey: tk("feeds_state_expired"), icon: Clock },
}

const GRID =
  "md:grid md:grid-cols-[minmax(0,1.6fr)_minmax(0,1.3fr)_minmax(6.5rem,auto)_minmax(0,1fr)_minmax(0,1.2fr)_minmax(5rem,auto)] md:items-center md:gap-x-4"

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
      {t(s.labelKey)}
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
        {t("feeds_token_score", {
          score: token.min_score,
          benign: token.include_benign ? "yes" : "no",
        })}
      </div>
      <div className="hidden md:block">{badge}</div>
      <div className="text-xs text-fg-muted">
        <span className="block">
          {tNodes(
            "feeds_token_created",
            {},
            { time: <RelativeTime iso={token.created_at} className="text-xs" /> },
          )}
        </span>
        <span className="block">
          {token.expires_at ? (
            token.state === "expired" ? (
              tNodes(
                "feeds_token_expired_at",
                {},
                { time: <RelativeTime iso={token.expires_at} className="text-xs" /> },
              )
            ) : (
              tNodes(
                "feeds_token_expires_at",
                {},
                { time: <RelativeTime iso={token.expires_at} className="text-xs" /> },
              )
            )
          ) : (
            t("feeds_token_never_expires")
          )}
        </span>
      </div>
      <div className="min-w-0 text-xs text-fg-muted">
        {token.last_used_at ? (
          <>
            <span className="block">
              {tNodes(
                "feeds_token_used",
                {},
                { time: <RelativeTime iso={token.last_used_at} className="text-xs" /> },
              )}
            </span>
            <span className="flex flex-wrap items-center gap-x-1.5">
              {token.last_used_ip ? (
                <>
                  <IPChip ip={token.last_used_ip} variant="ghost" href={null} copyable={false} />
                  <span aria-hidden>·</span>
                </>
              ) : null}
              <span className="whitespace-nowrap">
                {t("feeds_token_pulls", { count: token.use_count })}
              </span>
            </span>
          </>
        ) : (
          t("feeds_token_never_used")
        )}
      </div>
      <div className="md:justify-self-end">
        {token.state === "active" ? (
          <Button
            variant="outline"
            size="sm"
            disabled={revoke.isPending}
            onClick={() => revoke.mutate()}
            aria-label={t("feeds_token_revoke_label", { name: token.name })}
          >
            {t("feeds_token_revoke")}
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
        eyebrow={t("settings_tab_feeds")}
        finding={q.isError ? t("feeds_check_failed") : feedsSentence(list)}
        detail={tNodes(
          "feeds_detail",
          {},
          { path: <code className="font-mono text-fg">/feeds/*</code> },
        )}
        action={
          <Button size="sm" disabled={!enabled} onClick={() => setCreating(true)}>
            <Plus aria-hidden />
            {t("feeds_create")}
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
              {tNodes(
                "feeds_off",
                {},
                {
                  setting: <code className="font-mono text-fg">FEEDS_ENABLED=true</code>,
                  env: <code className="font-mono text-fg">.env</code>,
                },
              )}
            </p>
          </div>
        ) : (
          <p className="flex items-center gap-2 text-sm text-fg-muted">
            <CircleCheck aria-hidden className="size-4 text-status-ok" />
            <span>
              {tNodes(
                "feeds_on",
                {},
                { on: <span className="font-medium text-fg">{t("feeds_on_word")}</span> },
              )}
            </span>
          </p>
        )}
      </FindingCard>

      {created ? <TokenReveal created={created} onDismiss={() => setCreated(null)} /> : null}

      {list && list.items.length > 0 ? (
        <FindingCard
          eyebrow={t("feeds_tokens_title")}
          finding={t("feeds_tokens_finding")}
          bodyClassName="px-0 sm:px-0 pt-3 pb-0 sm:pb-0"
        >
          <div className={`hidden border-y px-5 py-2.5 type-column text-fg-subtle ${GRID}`}>
            <span>{t("channels_name")}</span>
            <span>{t("feeds_col_covers")}</span>
            <span>{t("feeds_col_state")}</span>
            <span>{t("feeds_col_dates")}</span>
            <span>{t("feeds_col_last_used")}</span>
            <span className="sr-only">{t("feeds_col_actions")}</span>
          </div>
          <ul aria-label={t("feeds_list_label")} className="divide-y border-t md:border-t-0">
            {list.items.map((item) => (
              <TokenRow key={item.id} token={item} />
            ))}
          </ul>
        </FindingCard>
      ) : list && enabled ? (
        <EmptyState
          icon={Rss}
          title={t("feeds_empty_title")}
          description={t("feeds_empty_description")}
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
