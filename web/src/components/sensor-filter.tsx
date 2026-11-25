import { Check, ChevronsUpDown, Minus } from "lucide-react"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { t } from "@/i18n"
import { useSensorFilter } from "@/hooks/use-sensor-filter"
import {
  FAMILY_META,
  SENSOR_FAMILIES,
  SENSOR_META,
  exactFamily,
  sensorSetLabel,
  type Sensor,
  type SensorFamily,
} from "@/lib/sensors"
import { cn } from "@/lib/utils"

type CheckState = boolean | "mixed"

/** A visual checkbox inside a listbox option (the option itself carries aria-checked). */
function CheckMark({ state }: { state: CheckState }) {
  return (
    <span
      aria-hidden
      className={cn(
        "flex size-4 shrink-0 items-center justify-center rounded-[4px] border transition-colors duration-150",
        state
          ? "border-primary bg-primary text-primary-foreground"
          : "border-border-strong bg-surface",
      )}
    >
      {state === "mixed" ? (
        <Minus className="size-3 text-primary-foreground" strokeWidth={3.5} />
      ) : state ? (
        <Check className="size-3 text-primary-foreground" strokeWidth={3.5} />
      ) : null}
    </span>
  )
}

function portLabel(s: Sensor) {
  const m = SENSOR_META[s]
  return m.transport === "udp" ? `${m.port}/udp` : String(m.port)
}

/** What the closed trigger shows: a few icons or a family swatch, then the selection's name. */
function TriggerValue({ sensors }: { sensors: readonly Sensor[] }) {
  if (sensors.length === 0) return <span className="text-fg">{t("common_all")}</span>
  const family = sensors.length > 1 ? exactFamily(sensors) : null
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5 text-fg">
      {family ? (
        <span
          aria-hidden
          className={cn("size-2 shrink-0 rounded-full", FAMILY_META[family].fill)}
        />
      ) : sensors.length <= 3 ? (
        <span aria-hidden className="inline-flex items-center gap-0.5">
          {sensors.map((s) => {
            const Icon = SENSOR_META[s].icon
            return <Icon key={s} className={cn("size-3.5", SENSOR_META[s].text)} />
          })}
        </span>
      ) : null}
      <span className="truncate">{sensorSetLabel(sensors)}</span>
    </span>
  )
}

interface SensorFilterProps {
  className?: string
  /** Popover alignment against the trigger. */
  align?: "start" | "end"
}

/**
 * Multi-select sensor filter, grouped by family, synced to `?sensor=a,b`.
 * Type to narrow, arrows to move, Enter or Space to toggle, Escape to close.
 * A family row toggles all of its sensors at once.
 */
export function SensorFilter({ className, align = "start" }: SensorFilterProps) {
  const [sensors, setSensors] = useSensorFilter()
  const [open, setOpen] = useState(false)
  // Filtered by hand (not by cmdk) so the family tree keeps its order while typing.
  const [query, setQuery] = useState("")
  const q = query.trim().toLowerCase()
  const hit = (...texts: string[]) => !q || texts.some((t) => t.toLowerCase().includes(q))
  const selected = new Set(sensors)

  const toggle = (s: Sensor) => {
    const next = new Set(selected)
    if (next.has(s)) next.delete(s)
    else next.add(s)
    setSensors([...next])
  }
  const familyState = (f: SensorFamily): CheckState => {
    const members = FAMILY_META[f].sensors
    const n = members.filter((s) => selected.has(s)).length
    return n === 0 ? false : n === members.length ? true : "mixed"
  }
  const toggleFamily = (f: SensorFamily) => {
    const members = FAMILY_META[f].sensors
    const next = new Set(selected)
    if (familyState(f) === true) members.forEach((s) => next.delete(s))
    else members.forEach((s) => next.add(s))
    setSensors([...next])
  }

  return (
    <Popover
      open={open}
      onOpenChange={(o) => {
        setOpen(o)
        if (!o) setQuery("")
      }}
    >
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className={cn("max-w-full justify-between gap-2 px-2.5", className)}
        >
          <span className="inline-flex min-w-0 items-center gap-1.5">
            <span className="text-fg-muted">{t("sensor_filter_label")}</span>
            <TriggerValue sensors={sensors} />
          </span>
          <ChevronsUpDown aria-hidden className="size-3.5 text-fg-subtle" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align={align}
        className="w-[min(18rem,calc(100vw-2rem))] overflow-hidden p-0"
        onOpenAutoFocus={(e) => {
          // Focus the search box, not the first option.
          e.preventDefault()
          ;(e.currentTarget as HTMLElement).querySelector("input")?.focus()
        }}
      >
        <Command loop shouldFilter={false} className="bg-surface-raised">
          <CommandInput
            value={query}
            onValueChange={setQuery}
            placeholder={t("sensor_filter_placeholder")}
            aria-label={t("sensor_filter_find")}
          />
          <CommandList
            label={t("sensor_filter_label")}
            aria-multiselectable="true"
            className="max-h-[min(26rem,60dvh)]"
          >
            <CommandEmpty className="py-6 text-center text-xs text-fg-muted">
              {t("sensor_filter_empty")}
            </CommandEmpty>
            {SENSOR_FAMILIES.map((f) => ({
              f,
              members: hit(FAMILY_META[f].label)
                ? FAMILY_META[f].sensors
                : FAMILY_META[f].sensors.filter((s) => {
                    const m = SENSOR_META[s]
                    return hit(m.label, m.noun, String(m.port))
                  }),
            }))
              .filter((x) => x.members.length > 0)
              .map(({ f, members }, i) => {
                const fam = FAMILY_META[f]
                const state = familyState(f)
                return (
                  <div key={f}>
                    {i > 0 ? <CommandSeparator /> : null}
                    <CommandGroup>
                      <CommandItem
                        value={`family-${f}`}
                        keywords={[fam.label, ...fam.sensors.map((s) => SENSOR_META[s].label)]}
                        onSelect={() => toggleFamily(f)}
                        aria-checked={state}
                        className="h-8 gap-2.5 text-xs font-medium text-fg data-[selected=true]:bg-surface-hover"
                      >
                        <CheckMark state={state} />
                        <span
                          aria-hidden
                          className={cn("size-2 shrink-0 rounded-full", fam.fill)}
                        />
                        <span className="flex-1">{fam.label}</span>
                      </CommandItem>
                      {members.map((s) => {
                        const m = SENSOR_META[s]
                        const on = selected.has(s)
                        return (
                          <CommandItem
                            key={s}
                            value={s}
                            keywords={[m.label, m.noun, String(m.port)]}
                            onSelect={() => toggle(s)}
                            aria-checked={on}
                            className="h-8 gap-2.5 pl-6 text-xs text-fg-muted data-[selected=true]:bg-surface-hover data-[selected=true]:text-fg"
                          >
                            <CheckMark state={on} />
                            <m.icon
                              aria-hidden
                              className={cn("size-3.5", m.text)}
                              strokeWidth={2}
                            />
                            <span className={cn("flex-1", on && "text-fg")}>{m.label}</span>
                            <span className="font-mono text-2xs text-fg-subtle">
                              {portLabel(s)}
                            </span>
                          </CommandItem>
                        )
                      })}
                    </CommandGroup>
                  </div>
                )
              })}
          </CommandList>
          <div className="flex items-center justify-between gap-2 border-t px-3 py-2 text-xs">
            <span className="text-fg-subtle" aria-live="polite">
              {sensors.length
                ? t("sensor_filter_selected", { count: sensors.length })
                : t("sensor_filter_every")}
            </span>
            {sensors.length ? (
              <button
                type="button"
                onClick={() => setSensors([])}
                className="rounded-sm font-medium text-fg-muted transition-colors hover:text-fg"
              >
                {t("sensor_filter_show_all")}
              </button>
            ) : null}
          </div>
        </Command>
      </PopoverContent>
    </Popover>
  )
}
