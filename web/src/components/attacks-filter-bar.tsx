import { CampaignName } from "@/components/campaigns/campaign-name"
import { CountryFlag } from "@/components/country-flag"
import { FilterBar, SensorFilter, type FilterChipDef } from "@/components/filter-bar"
import { FloodFilter } from "@/components/flood-filter"
import {
  CountryFilter,
  NetworkFilter,
  OutcomeFilter,
  PeriodFilter,
  SearchFilter,
  SortFilter,
  TagFilter,
} from "@/components/list-filters"
import { useSearchParams } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { ATTACKER_SORTS } from "@/lib/api"
import { maskIp } from "@/lib/format"
import {
  ASN_SORTS,
  ATTACKER_PARAMS,
  ATTACKER_SORT_LABELS,
  NETWORK_PARAMS,
  SESSION_PARAMS,
  SESSION_SEARCH_FIELDS,
} from "@/lib/list-filters"
import { STAGE_META, parseInstant, parseStage, windowLabel } from "@/lib/story"

/** What the Attacks lists group by: one row per session, per address or per network. */
export type AttacksGroup = "sessions" | "attackers" | "networks"

const IP_SORTS = ATTACKER_SORTS.map((id) => ({ id, label: ATTACKER_SORT_LABELS[id] }))
const mono = (v: string) => <span className="font-mono">{v}</span>
const country = (v: string) => <CountryFlag code={v.toUpperCase()} showName className="text-fg" />

/**
 * The one filter bar of Sessions, Attackers and Networks. The three lists are the same attacks
 * grouped three ways, so the bar is the same: each filter a grouping can apply shows, and the
 * page switch carries the shared ones (sensor, country, network, tag, period) across the tabs.
 */
export function AttacksFilterBar({ group }: { group: AttacksGroup }) {
  const { masked } = useIpMask()
  const [params] = useSearchParams()
  const period: FilterChipDef[] =
    group === "networks"
      ? [
          {
            param: "since",
            label: "Period",
            render: (v) => <span>{windowLabel(parseInstant(v), undefined)}</span>,
          },
        ]
      : [
          {
            param: "since",
            label: "Period",
            alsoRemove: ["until"],
            render: (v) => (
              <span>{windowLabel(parseInstant(v), parseInstant(params.get("until")))}</span>
            ),
          },
          ...(params.get("since")
            ? []
            : [
                {
                  param: "until",
                  label: "Period",
                  render: (v: string) => <span>{windowLabel(undefined, parseInstant(v))}</span>,
                },
              ]),
        ]
  const countryChip: FilterChipDef = { param: "country", label: "Country", render: country }
  const networkChip: FilterChipDef = {
    param: "asn",
    label: "Network",
    render: (v) => <span className="font-mono">AS{v}</span>,
  }
  const tagChip: FilterChipDef = { param: "tag", label: "Tag", render: mono }

  if (group === "networks") {
    return (
      <FilterBar
        alsoClears={[...NETWORK_PARAMS]}
        trailing={<SortFilter options={ASN_SORTS} defaultSort="sessions" directional={false} />}
        chips={[{ param: "q", label: "Search", render: (v) => <span>{v}</span> }, countryChip, ...period]}
      >
        <SearchFilter
          fields={[{ param: "q", label: "Network", placeholder: "AS number, network or country" }]}
          clean={(_, raw) => raw.trim().slice(0, 64) || undefined}
        />
        <PeriodFilter sinceOnly />
        <CountryFilter />
      </FilterBar>
    )
  }

  if (group === "attackers") {
    return (
      <FilterBar
        alsoClears={[...ATTACKER_PARAMS]}
        trailing={<SortFilter options={IP_SORTS} defaultSort="last_seen" />}
        chips={[{ param: "q", label: "IP prefix", render: mono }, countryChip, networkChip, tagChip]}
      >
        <SearchFilter
          fields={[{ param: "q", label: "IP prefix", placeholder: "IP prefix, e.g. 203.0.113" }]}
          clean={(_, raw) => (/^[0-9a-fA-F.:]{1,45}$/.test(raw.trim()) ? raw.trim() : undefined)}
        />
        <SensorFilter />
        <CountryFilter />
        <NetworkFilter />
        <TagFilter />
      </FilterBar>
    )
  }

  return (
    <FilterBar
      alsoClears={[...SESSION_PARAMS]}
      chips={[
        {
          param: "src_ip",
          label: "IP address",
          render: (v) => <span className="font-mono">{masked ? maskIp(v) : v}</span>,
        },
        { param: "username", label: "Username", render: mono },
        { param: "command", label: "Command", render: mono },
        {
          param: "url",
          label: "Download URL",
          render: (v) => <span className="font-mono break-all">{v}</span>,
        },
        ...period,
        {
          param: "stage",
          label: "Outcome",
          render: (v) => {
            const stage = parseStage(v)
            return <span>{stage ? STAGE_META[stage].label : v}</span>
          },
        },
        tagChip,
        countryChip,
        networkChip,
        { param: "technique", label: "Technique", render: mono },
        { param: "campaign_id", label: "Campaign", render: (v) => <CampaignName id={v} /> },
      ]}
    >
      <SearchFilter fields={SESSION_SEARCH_FIELDS} />
      <SensorFilter />
      <PeriodFilter />
      <CountryFilter />
      <NetworkFilter />
      <TagFilter />
      <OutcomeFilter />
      <FloodFilter />
    </FilterBar>
  )
}
