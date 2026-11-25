import { useQuery } from "@tanstack/react-query"
import { ArrowDown, ArrowUp, Check, ChevronsUpDown, Search } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { useSearchParams } from "react-router"
import { CountryFlag } from "@/components/country-flag"
import { Button } from "@/components/ui/button"
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useUrlParam } from "@/hooks/use-url-param"
import { api, ASN_LIMIT, queryKeys } from "@/lib/api"
import { countryName } from "@/lib/format"
import {
  allCountries,
  cleanSearchValue,
  dayAfter,
  dayStart,
  parseAsn,
  parseCountry,
  parseTag,
  patchParams,
  PERIOD_PRESETS,
  presetSince,
  toDateInput,
} from "@/lib/list-filters"
import { STAGE_META, STAGES, windowLabel, parseInstant, type Stage } from "@/lib/story"
import { cn } from "@/lib/utils"

const nonEmpty = (v: string) => (v === "" ? undefined : v)

/** The button every filter popover opens from: a muted name, then the chosen value. */
function Trigger({
  label,
  value,
  active,
}: {
  label: string
  value: React.ReactNode
  active: boolean
}) {
  return (
    <PopoverTrigger asChild>
      <Button
        variant="outline"
        size="sm"
        className={cn(
          "h-8 max-w-full justify-between gap-2 px-2.5 text-xs font-medium",
          active && "border-border-strong",
        )}
      >
        <span className="inline-flex min-w-0 items-center gap-1.5">
          <span className="text-fg-muted">{label}</span>
          <span className="min-w-0 truncate text-fg">{value}</span>
        </span>
        <ChevronsUpDown aria-hidden className="size-3.5 text-fg-subtle" />
      </Button>
    </PopoverTrigger>
  )
}

export interface ChoiceOption {
  value: string
  label: string
  node?: React.ReactNode
  hint?: string
}

interface ChoiceFilterProps {
  /** Name shown on the button and in the chip, e.g. "Country". */
  label: string
  param: string
  /** The choices shown before typing. */
  options: readonly ChoiceOption[]
  /** More choices that match what was typed (e.g. every country). */
  search?: (query: string) => readonly ChoiceOption[]
  /** Turns typed text into a value the API accepts, or undefined when it is not one. */
  custom?: (query: string) => ChoiceOption | undefined
  /** How the current value reads on the button. */
  show?: (value: string) => React.ReactNode
  searchable?: boolean
  placeholder?: string
  /** What the button says when nothing is chosen. */
  any?: string
  emptyText?: string
  /** Other params removed when this one changes. */
  alsoRemove?: readonly string[]
}

/** One value out of many, from a short list or typed. Writes `?param=value`. */
export function ChoiceFilter({
  label,
  param,
  options,
  search,
  custom,
  show,
  searchable = true,
  placeholder = "Search…",
  any = "Any",
  emptyText = "Nothing matches.",
  alsoRemove = [],
}: ChoiceFilterProps) {
  const [params, setParams] = useSearchParams()
  const current = params.get(param)
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const q = query.trim()

  const choose = (value: string | null) => {
    setParams(
      (prev) =>
        patchParams(prev, {
          [param]: value,
          ...Object.fromEntries(alsoRemove.map((k) => [k, null])),
        }),
      {
        preventScrollReset: true,
      },
    )
    setOpen(false)
  }

  const typed = q && custom ? custom(q) : undefined
  const matches = q && search ? search(q) : options
  const list = [
    ...(typed && !matches.some((o) => o.value === typed.value) ? [typed] : []),
    ...matches,
  ]
  const known = current ? options.find((o) => o.value === current) : undefined

  return (
    <Popover
      open={open}
      onOpenChange={(o) => {
        setOpen(o)
        if (!o) setQuery("")
      }}
    >
      <Trigger
        label={label}
        active={Boolean(current)}
        value={current ? (show ? show(current) : (known?.label ?? current)) : any}
      />
      <PopoverContent
        align="start"
        className="w-[min(18rem,calc(100vw-2rem))] overflow-hidden p-0"
        onOpenAutoFocus={(e) => {
          e.preventDefault()
          ;(e.currentTarget as HTMLElement).querySelector("input")?.focus()
        }}
      >
        <Command loop shouldFilter={false} className="bg-surface-raised">
          {searchable ? (
            <CommandInput
              value={query}
              onValueChange={setQuery}
              placeholder={placeholder}
              aria-label={`Find a ${label.toLowerCase()}`}
            />
          ) : null}
          <CommandList label={label} className="max-h-[min(22rem,60dvh)]">
            <CommandEmpty className="py-6 text-center text-xs text-fg-muted">
              {emptyText}
            </CommandEmpty>
            <CommandGroup>
              {current ? (
                <CommandItem
                  value="__any"
                  onSelect={() => choose(null)}
                  className="h-8 text-xs text-fg-muted"
                >
                  {any}
                </CommandItem>
              ) : null}
              {list.slice(0, 60).map((o) => (
                <CommandItem
                  key={o.value}
                  value={o.value}
                  onSelect={() => choose(o.value)}
                  aria-checked={o.value === current}
                  className="h-8 gap-2.5 text-xs text-fg"
                >
                  <span className="flex min-w-0 flex-1 items-center gap-2">
                    {o.node ?? <span className="truncate">{o.label}</span>}
                  </span>
                  {o.hint ? (
                    <span className="font-mono text-2xs text-fg-subtle tabular-nums">{o.hint}</span>
                  ) : null}
                  {o.value === current ? <Check aria-hidden className="size-3.5 text-fg" /> : null}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

// --- Country, network, tag, outcome ---------------------------------------------------------

const flagOption = (code: string, hint?: string): ChoiceOption => ({
  value: code,
  label: countryName(code) ?? code,
  node: <CountryFlag code={code} showName className="text-fg" />,
  ...(hint ? { hint } : {}),
})

/** Countries seen in the last day first; typing searches every country by name or code. */
export function CountryFilter() {
  const top = useQuery({
    queryKey: queryKeys.top("country", {}),
    queryFn: () => api.top("country", {}, 30),
  })
  const seen = (top.data?.items ?? []).map((i) =>
    flagOption(i.value.toUpperCase(), String(i.count)),
  )
  return (
    <ChoiceFilter
      label="Country"
      param="country"
      options={seen}
      search={(q) => {
        const l = q.toLowerCase()
        return allCountries()
          .filter((c) => c.name.toLowerCase().includes(l) || c.code.toLowerCase() === l)
          .map((c) => flagOption(c.code))
      }}
      custom={(q) => {
        const code = parseCountry(q)
        return code ? flagOption(code) : undefined
      }}
      show={(v) => <CountryFlag code={v} showName className="text-fg" />}
      placeholder="Country name or code"
      any="Any country"
      emptyText="No country matches."
    />
  )
}

/** The busiest networks first; typing an AS number or a name narrows them. */
export function NetworkFilter() {
  const nets = useQuery({
    queryKey: queryKeys.asns("sessions"),
    queryFn: () => api.asns("sessions", ASN_LIMIT),
  })
  const items = nets.data?.items ?? []
  const toOption = (n: (typeof items)[number]): ChoiceOption => ({
    value: String(n.asn),
    label: `AS${n.asn} ${n.org ?? ""}`.trim(),
    node: (
      <>
        <span className="shrink-0 font-mono text-fg-muted">AS{n.asn}</span>
        <span className="truncate">{n.org ?? "Unknown network"}</span>
      </>
    ),
  })
  return (
    <ChoiceFilter
      label="Network"
      param="asn"
      options={items.slice(0, 30).map(toOption)}
      search={(q) => {
        const l = q.toLowerCase().replace(/^as\s*(?=\d)/, "")
        return items
          .filter((n) => String(n.asn).startsWith(l) || (n.org ?? "").toLowerCase().includes(l))
          .map(toOption)
      }}
      custom={(q) => {
        const asn = parseAsn(q)
        return asn
          ? { value: asn, label: `AS${asn}`, node: <span className="font-mono">AS{asn}</span> }
          : undefined
      }}
      show={(v) => <span className="font-mono">AS{v}</span>}
      placeholder="AS number or network name"
      any="Any network"
      emptyText="No network matches."
    />
  )
}

/** Tags seen in the last day; any other tag can be typed. */
export function TagFilter() {
  const top = useQuery({
    queryKey: queryKeys.top("tag", {}),
    queryFn: () => api.top("tag", {}, 30),
  })
  const toOption = (value: string, hint?: string): ChoiceOption => ({
    value,
    label: value,
    node: <span className="truncate font-mono">{value}</span>,
    ...(hint ? { hint } : {}),
  })
  const options = (top.data?.items ?? []).map((i) => toOption(i.value, String(i.count)))
  return (
    <ChoiceFilter
      label="Tag"
      param="tag"
      options={options}
      search={(q) => options.filter((o) => o.value.includes(q.toLowerCase()))}
      custom={(q) => {
        const tag = parseTag(q)
        return tag ? toOption(tag) : undefined
      }}
      show={(v) => <span className="font-mono">{v}</span>}
      placeholder="Tag, e.g. mirai"
      any="Any tag"
      emptyText="No tag matches."
    />
  )
}

/** How far a session got: the deepest step it reached. */
export function OutcomeFilter() {
  const options = (STAGES as readonly Stage[]).map<ChoiceOption>((s) => {
    const Icon = STAGE_META[s].icon
    return {
      value: s,
      label: STAGE_META[s].label,
      node: (
        <>
          <Icon aria-hidden className="size-3.5 shrink-0" style={{ color: STAGE_META[s].cssVar }} />
          <span className="truncate">{STAGE_META[s].label}</span>
        </>
      ),
    }
  })
  return (
    <ChoiceFilter
      label="Outcome"
      param="stage"
      options={options}
      searchable={false}
      any="Any outcome"
    />
  )
}

// --- Period ---------------------------------------------------------------------------------

/** A time window: quick presets, or a first and last day. `sinceOnly` hides the last day. */
export function PeriodFilter({ sinceOnly = false }: { sinceOnly?: boolean }) {
  const [params, setParams] = useSearchParams()
  const since = parseInstant(params.get("since"))
  const until = sinceOnly ? undefined : parseInstant(params.get("until"))
  const [open, setOpen] = useState(false)
  const write = (patch: Record<string, string | null>) =>
    setParams((prev) => patchParams(prev, patch), { preventScrollReset: true })
  const label = since || until ? windowLabel(since, until) : "Any time"
  const dateTitle = (iso: string | undefined) => (iso ? new Date(iso).toLocaleString() : "")

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <Trigger label="Period" active={since !== undefined || until !== undefined} value={label} />
      <PopoverContent align="start" className="w-[min(18rem,calc(100vw-2rem))] p-3">
        <div role="group" aria-label="Period presets" className="grid grid-cols-2 gap-1.5">
          {PERIOD_PRESETS.map((p) => (
            <Button
              key={p.id}
              variant="outline"
              size="sm"
              className="h-8 text-xs"
              onClick={() => {
                write({ since: presetSince(p.id) ?? null, until: null })
                setOpen(false)
              }}
            >
              {p.label}
            </Button>
          ))}
        </div>
        {sinceOnly ? null : (
          <div className="mt-3 grid grid-cols-2 gap-2">
            <label className="grid gap-1 text-xs text-fg-muted">
              From
              <Input
                type="date"
                value={toDateInput(since)}
                title={dateTitle(since)}
                max={nonEmpty(toDateInput(until, true))}
                onChange={(e) => write({ since: dayStart(e.target.value) ?? null })}
                className="h-8 px-2 text-xs md:text-xs"
              />
            </label>
            <label className="grid gap-1 text-xs text-fg-muted">
              To (included)
              <Input
                type="date"
                value={toDateInput(until, true)}
                min={nonEmpty(toDateInput(since))}
                onChange={(e) => write({ until: dayAfter(e.target.value) ?? null })}
                className="h-8 px-2 text-xs md:text-xs"
              />
            </label>
          </div>
        )}
        {since || until ? (
          <button
            type="button"
            onClick={() => {
              write({ since: null, until: null })
              setOpen(false)
            }}
            className="mt-3 text-xs font-medium text-fg-muted transition-colors hover:text-fg"
          >
            Any time
          </button>
        ) : null}
      </PopoverContent>
    </Popover>
  )
}

// --- Search ---------------------------------------------------------------------------------

export interface SearchField {
  param: string
  label: string
  placeholder: string
}

/**
 * Free-text search. With several fields, pick what to search in and press Enter: the search
 * becomes a chip. With one field the URL follows what is typed, after a short pause.
 */
export function SearchFilter({
  fields,
  clean = cleanSearchValue,
  className,
}: {
  fields: readonly SearchField[]
  clean?: (param: string, raw: string) => string | undefined
  className?: string
}) {
  const [, setParams] = useSearchParams()
  const [field, setField] = useState(fields[0]?.param ?? "")
  const meta = fields.find((f) => f.param === field) ?? fields[0]
  const [text, setText] = useState("")
  const [bad, setBad] = useState(false)
  const live = fields.length === 1
  const [urlValue] = useUrlParam(fields[0]?.param ?? "")
  const input = useRef<HTMLInputElement>(null)

  // One field: mirror the URL (Clear all, Back), unless the person is typing.
  useEffect(() => {
    if (!live || document.activeElement === input.current) return
    const id = setTimeout(() => setText(urlValue ?? ""), 0)
    return () => clearTimeout(id)
  }, [live, urlValue])

  const write = (param: string, value: string | null) =>
    setParams((prev) => patchParams(prev, { [param]: value }), { preventScrollReset: true })

  useEffect(() => {
    if (!live || !meta) return
    if (text.trim() === (urlValue ?? "")) return
    const id = setTimeout(() => {
      const v = clean(meta.param, text)
      setBad(Boolean(text.trim()) && !v)
      write(meta.param, v ?? null)
    }, 250)
    return () => clearTimeout(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text, live, urlValue])

  if (!meta) return null
  const commit = () => {
    const v = clean(meta.param, text)
    setBad(Boolean(text.trim()) && !v)
    if (!v) return
    write(meta.param, v)
    setText("")
  }

  return (
    <div className={cn("flex w-[85%] shrink-0 items-center gap-1.5 sm:w-auto", className)}>
      {live ? null : (
        <Select value={field} onValueChange={setField}>
          <SelectTrigger size="sm" aria-label="Search in" className="h-8 shrink-0 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {fields.map((f) => (
              <SelectItem key={f.param} value={f.param} className="text-xs">
                {f.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      <div className="relative min-w-0 flex-1 sm:w-64 sm:flex-none">
        <Search
          aria-hidden
          className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-fg-subtle"
        />
        <Input
          ref={input}
          value={text}
          onChange={(e) => {
            setText(e.target.value)
            setBad(false)
          }}
          onKeyDown={(e) => {
            if (!live && e.key === "Enter") commit()
          }}
          autoComplete="off"
          spellCheck={false}
          maxLength={256}
          placeholder={meta.placeholder}
          aria-label={live ? meta.label : `Search ${meta.label.toLowerCase()}`}
          aria-invalid={bad || undefined}
          className="h-8 pl-8 font-mono text-xs md:text-xs"
        />
      </div>
    </div>
  )
}

// --- Sort -----------------------------------------------------------------------------------

/** What to order by, and which way. Defaults stay out of the URL. */
export function SortFilter({
  options,
  defaultSort,
  directional = true,
}: {
  options: readonly { id: string; label: string }[]
  defaultSort: string
  /** False when the API only sorts one way. */
  directional?: boolean
}) {
  const [params, setParams] = useSearchParams()
  const sort = options.find((o) => o.id === params.get("sort"))?.id ?? defaultSort
  const asc = params.get("order") === "asc"
  const write = (patch: Record<string, string | null>) =>
    setParams((prev) => patchParams(prev, patch), { preventScrollReset: true })
  return (
    <div className="flex items-center gap-1.5">
      <span aria-hidden className="text-xs text-fg-muted">
        Sort by
      </span>
      <Select value={sort} onValueChange={(v) => write({ sort: v === defaultSort ? null : v })}>
        <SelectTrigger size="sm" aria-label="Sort by" className="h-8 text-xs">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map((o) => (
            <SelectItem key={o.id} value={o.id} className="text-xs">
              {o.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {directional ? (
        <Button
          variant="outline"
          size="icon"
          className="size-8"
          onClick={() => write({ order: asc ? null : "asc" })}
          aria-label={
            asc
              ? "Oldest or lowest first. Switch to highest first"
              : "Newest or highest first. Switch to lowest first"
          }
          title={asc ? "Lowest first" : "Highest first"}
        >
          {asc ? (
            <ArrowUp aria-hidden className="size-3.5" />
          ) : (
            <ArrowDown aria-hidden className="size-3.5" />
          )}
        </Button>
      ) : null}
    </div>
  )
}
