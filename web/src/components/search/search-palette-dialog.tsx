import { keepPreviousData, useQuery } from "@tanstack/react-query"
import {
  Bug,
  Clock,
  Crosshair,
  Flag,
  Globe,
  SearchX,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { useNavigate } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import {
  Command,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command"
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog"
import { ScannerBadge } from "@/components/scanner-badge"
import { t } from "@/i18n"
import { tNodes } from "@/i18n/rich"
import { formatNumber, maskIpsInText } from "@/lib/format"
import {
  GROUP_LABEL,
  MIN_QUERY,
  cleanQuery,
  hitHref,
  loadRecent,
  orderedGroups,
  rememberSearch,
  searchApi,
  type SearchHit,
  type SearchKind,
} from "@/lib/search"
import { searchPlaceholder } from "./search-palette-constants"
import { cn } from "@/lib/utils"

/** One example per kind; a click fills the box. Documentation addresses only. */
const EXAMPLES = ["203.0.113.", "CVE-2026-109618", "mirai"] as const

const KIND_ICON: Record<SearchKind, LucideIcon> = {
  ip: Crosshair,
  campaign: Flag,
  cve: ShieldAlert,
  hash: Bug,
  domain: Globe,
}

function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), ms)
    return () => clearTimeout(timer)
  }, [value, ms])
  return debounced
}

function Hit({ hit, masked, onSelect }: { hit: SearchHit; masked: boolean; onSelect: () => void }) {
  const Icon = KIND_ICON[hit.kind]
  const mono = hit.kind !== "campaign"
  const label = masked ? maskIpsInText(hit.label) : hit.label
  return (
    <CommandItem
      value={`${hit.kind}:${hit.value}`}
      onSelect={onSelect}
      className="min-h-11 gap-3 py-2 sm:min-h-10"
    >
      <Icon aria-hidden className="size-4 text-fg-subtle" strokeWidth={1.85} />
      <span className="min-w-0 flex-1">
        <span className={cn("block truncate text-sm text-fg", mono && "font-mono text-xs")}>
          {label}
        </span>
        {hit.detail ? (
          <span className="block truncate text-xs text-fg-muted">
            {masked ? maskIpsInText(hit.detail) : hit.detail}
          </span>
        ) : null}
      </span>
      {hit.benign ? <ScannerBadge short /> : null}
      {hit.count != null ? (
        <span className="text-xs text-fg-muted tabular-nums">
          {hit.kind === "ip" || hit.kind === "campaign"
            ? t("search_session_count", { count: hit.count })
            : formatNumber(hit.count)}
        </span>
      ) : null}
    </CommandItem>
  )
}

export default function SearchPaletteDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const navigate = useNavigate()
  const { masked } = useIpMask()
  const [input, setInput] = useState("")
  const q = useDebounced(cleanQuery(input), 200)
  const ready = q.length >= MIN_QUERY

  // Read each time the palette opens: a search made a moment ago must show up.
  const recent = useMemo(() => (open ? loadRecent() : []), [open])
  const close = (next: boolean) => {
    if (!next) setInput("")
    onOpenChange(next)
  }

  const result = useQuery({
    queryKey: ["search", q],
    queryFn: () => searchApi.search(q),
    enabled: open && ready,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  })
  const groups = orderedGroups(ready ? result.data : undefined)
  const typing = cleanQuery(input) !== q
  const searching = ready && (result.isFetching || typing)

  const go = (hit: SearchHit) => {
    rememberSearch(q)
    close(false)
    void navigate(hitHref(hit))
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent
        showCloseButton={false}
        className="top-[4.5rem] translate-y-0 gap-0 overflow-hidden p-0 sm:top-[12vh] sm:max-w-xl"
      >
        <DialogTitle className="sr-only">{t("common_search")}</DialogTitle>
        <DialogDescription className="sr-only">
          {t("search_description")}
        </DialogDescription>
        <Command shouldFilter={false} label={t("common_search")} className="rounded-lg bg-popover">
          <CommandInput
            value={input}
            onValueChange={setInput}
            maxLength={128}
            placeholder={searchPlaceholder()}
            aria-label={t("common_search")}
          />
          <CommandList className="max-h-[min(24rem,60dvh)]">
            {!ready ? (
              <>
                {recent.length > 0 ? (
                  <CommandGroup heading={t("search_recent")}>
                    {recent.map((r) => (
                      <CommandItem
                        key={r}
                        value={`recent:${r}`}
                        onSelect={() => setInput(r)}
                        className="min-h-11 gap-3 sm:min-h-10"
                      >
                        <Clock aria-hidden className="size-4 text-fg-subtle" />
                        <span className="font-mono text-xs">{masked ? maskIpsInText(r) : r}</span>
                      </CommandItem>
                    ))}
                  </CommandGroup>
                ) : null}
                <div className="px-4 py-4">
                  <p className="text-sm text-fg-muted">
                    {t("search_hint_min")}
                  </p>
                  <div className="mt-3 flex flex-wrap items-center gap-1.5">
                    <span className="text-xs text-fg-subtle">{t("search_try")}</span>
                    {EXAMPLES.map((ex) => (
                      <button
                        key={ex}
                        type="button"
                        onClick={() => setInput(ex)}
                        className="inline-flex h-7 items-center rounded-sm border px-2 font-mono text-2xs text-fg-muted transition-colors duration-150 hover:border-border-strong hover:text-fg"
                      >
                        {ex}
                      </button>
                    ))}
                  </div>
                </div>
              </>
            ) : searching && groups.length === 0 ? (
              <p role="status" className="px-4 py-6 text-center text-sm text-fg-muted">
                {t("search_searching")}
              </p>
            ) : (
              <>
                {groups.length === 0 ? (
                  <div role="status" className="px-6 py-8 text-center text-sm text-fg-muted">
                    <SearchX aria-hidden className="mx-auto mb-2 size-5 text-fg-subtle" />
                    {t("search_no_match", { query: q })}
                  </div>
                ) : null}
                {groups.map((g) => (
                  <CommandGroup key={g.kind} heading={GROUP_LABEL[g.kind]}>
                    {g.hits.map((hit) => (
                      <Hit
                        key={`${hit.kind}:${hit.value}`}
                        hit={hit}
                        masked={masked}
                        onSelect={() => go(hit)}
                      />
                    ))}
                    {g.more ? (
                      <p className="px-2 py-1 text-xs text-fg-subtle">
                        {t("search_more")}
                      </p>
                    ) : null}
                  </CommandGroup>
                ))}
              </>
            )}
          </CommandList>
          <div className="flex items-center justify-between border-t px-3 py-2 text-2xs text-fg-subtle">
            <span className="hidden sm:inline">
              {tNodes(
                "search_hint_keys",
                {},
                {
                  up: <kbd className="font-sans">↑</kbd>,
                  down: <kbd className="font-sans">↓</kbd>,
                  enter: <kbd className="font-sans">Enter</kbd>,
                },
              )}
            </span>
            <span className="hidden sm:inline">
              {tNodes("search_hint_esc", {}, { esc: <kbd className="font-sans">Esc</kbd> })}
            </span>
            <button
              type="button"
              onClick={() => close(false)}
              className="-my-1 inline-flex h-8 items-center rounded-md px-2 text-xs text-fg-muted hover:text-fg sm:hidden"
            >
              {t("common_close")}
            </button>
          </div>
        </Command>
      </DialogContent>
    </Dialog>
  )
}
