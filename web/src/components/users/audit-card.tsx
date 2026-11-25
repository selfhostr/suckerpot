import { useInfiniteQuery } from "@tanstack/react-query"
import { LoadMore } from "@/components/load-more"
import { useEffect, useMemo, useState } from "react"
import { FindingCard } from "@/components/finding-card"
import { IPChip } from "@/components/ip-chip"
import { t } from "@/i18n"
import { RelativeTime } from "@/components/relative-time"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonText } from "@/components/skeletons"
import { Input } from "@/components/ui/input"
import { useUrlParam } from "@/hooks/use-url-param"
import { queryKeys } from "@/lib/api"
import {
  AUDIT_GROUPS,
  auditActorLabel,
  describeAudit,
  isSystemActor,
  usersApi,
  type AuditEntry,
} from "@/lib/users"

const GROUP_VALUES = AUDIT_GROUPS.map((g) => g.value) as readonly string[]

function finding(entries: AuditEntry[] | undefined, filtered: boolean): string {
  if (!entries) return t("users_audit_checking")
  const first = entries[0]
  if (!first) return filtered ? t("users_audit_no_match") : t("users_audit_empty")
  return filtered
    ? t("users_audit_matching", {
        count: entries.length,
        more: entries.length >= 25 ? "yes" : "no",
        actor: auditActorLabel(first),
      })
    : t("users_audit_latest", { actor: auditActorLabel(first), description: describeAudit(first) })
}

/** Administrators only: who did what, newest first. Entries are kept for a year. */
export function AuditCard() {
  const [actorParam, setActorParam] = useUrlParam("audit_actor")
  const [groupParam, setGroupParam] = useUrlParam("audit_action")
  const group = groupParam !== null && GROUP_VALUES.includes(groupParam) ? groupParam : ""
  const actor = actorParam ?? ""
  const [typed, setTyped] = useState(actor)

  // The URL is the source of truth; the box keeps what is being typed and writes it after a pause.
  useEffect(() => {
    if (typed.trim() === actor) return
    const timer = setTimeout(() => setActorParam(typed.trim() || null), 350)
    return () => clearTimeout(timer)
  }, [typed, actor, setActorParam])

  const filters = useMemo(
    () => ({ actor: actor || undefined, action: group || undefined }),
    [actor, group],
  )
  const q = useInfiniteQuery({
    queryKey: queryKeys.audit(filters),
    queryFn: ({ pageParam }) => usersApi.audit(filters, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const entries = useMemo(() => q.data?.pages.flatMap((p) => p.items), [q.data])

  return (
    <FindingCard
      eyebrow={t("users_audit_title")}
      finding={q.isError ? t("users_audit_unavailable") : finding(entries, !!(actor || group))}
      detail={t("users_audit_detail")}
      bodyClassName="px-0 sm:px-0 pt-3 pb-1 sm:pb-1"
    >
      <div className="flex flex-wrap items-center gap-3 px-4 pb-3 sm:px-5">
        <SegmentedControl
          label={t("users_audit_kind")}
          value={group}
          onChange={(v) => setGroupParam(v || null)}
          options={AUDIT_GROUPS.map((g) => ({ value: g.value, label: g.label }))}
        />
        <Input
          aria-label={t("users_audit_filter_label")}
          placeholder={t("users_audit_filter_placeholder")}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          size="sm"
          className="w-44 font-mono placeholder:font-sans"
        />
      </div>
      {q.isPending ? (
        <div className="border-t px-4 py-3 sm:px-5">
          <SkeletonText lines={5} />
        </div>
      ) : entries ? (
        <>
          <ul aria-label={t("users_audit_title")} className="divide-y border-t">
            {entries.map((e) => (
              <li
                key={e.id}
                className="grid grid-cols-[1fr_auto] items-baseline gap-x-3 gap-y-1 px-4 py-2.5 sm:px-5 lg:grid-cols-[7rem_minmax(0,1fr)_11rem]"
              >
                <p className="col-span-2 text-sm text-fg lg:col-span-1 lg:col-start-2 lg:row-start-1">
                  {isSystemActor(e) ? (
                    <span className="font-medium" title={t("users_audit_system_title")}>
                      {t("users_audit_system")}
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setActorParam(e.actor)}
                      className="font-medium underline-offset-4 hover:underline"
                      title={t("users_audit_only_actor")}
                    >
                      {e.actor}
                    </button>
                  )}{" "}
                  <span className="text-fg-muted">{describeAudit(e)}</span>
                </p>
                <RelativeTime
                  iso={e.ts}
                  className="row-start-2 text-xs lg:col-start-1 lg:row-start-1"
                />
                <span className="row-start-2 justify-self-end lg:col-start-3 lg:row-start-1">
                  {e.ip ? (
                    // Right-aligned: the ghost chip's left pull would make it truncate here.
                    <IPChip
                      ip={e.ip}
                      href={null}
                      copyable={false}
                      variant="ghost"
                      className="-mr-1.5 ml-0 max-w-none"
                    />
                  ) : null}
                </span>
              </li>
            ))}
            {entries.length === 0 ? (
              <li className="px-4 py-6 text-center text-sm text-fg-muted sm:px-5">
                {t("users_audit_none")}
              </li>
            ) : null}
          </ul>
          <LoadMore
            hasNextPage={q.hasNextPage}
            isFetchingNextPage={q.isFetchingNextPage}
            fetchNextPage={q.fetchNextPage}
            label={t("users_audit_older")}
            className="border-t"
          />
        </>
      ) : null}
    </FindingCard>
  )
}
