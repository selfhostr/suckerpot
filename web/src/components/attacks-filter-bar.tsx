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
import { t } from "@/i18n"
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

const ipSorts = () => ATTACKER_SORTS.map((id) => ({ id, label: ATTACKER_SORT_LABELS[id] }))
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
            label: t("filters_period_label"),
            render: (v) => <span>{windowLabel(parseInstant(v), undefined)}</span>,
          },
        ]
      : [
          {
            param: "since",
            label: t("filters_period_label"),
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
                  label: t("filters_period_label"),
                  render: (v: string) => <span>{windowLabel(undefined, parseInstant(v))}</span>,
                },
              ]),
        ]
  const countryChip: FilterChipDef = {
    param: "country",
    label: t("filters_country_label"),
    render: country,
  }
  const networkChip: FilterChipDef = {
    param: "asn",
    label: t("filters_network_label"),
    render: (v) => <span className="font-mono">AS{v}</span>,
  }
  const tagChip: FilterChipDef = { param: "tag", label: t("filters_tag_label"), render: mono }

  if (group === "networks") {
    return (
      <FilterBar
        alsoClears={[...NETWORK_PARAMS]}
        trailing={<SortFilter options={ASN_SORTS} defaultSort="sessions" directional={false} />}
        chips={[
          { param: "q", label: t("filters_chip_search"), render: (v) => <span>{v}</span> },
          countryChip,
          ...period,
        ]}
      >
        <SearchFilter
          fields={[
            {
              param: "q",
              label: t("filters_network_label"),
              placeholder: t("filters_network_search_placeholder"),
            },
          ]}
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
        trailing={<SortFilter options={ipSorts()} defaultSort="last_seen" />}
        chips={[
          { param: "q", label: t("filters_chip_ip_prefix"), render: mono },
          countryChip,
          networkChip,
          tagChip,
        ]}
      >
        <SearchFilter
          fields={[
            {
              param: "q",
              label: t("filters_chip_ip_prefix"),
              placeholder: t("filters_ip_prefix_placeholder"),
            },
          ]}
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
          label: t("filters_search_src_ip_label"),
          render: (v) => <span className="font-mono">{masked ? maskIp(v) : v}</span>,
        },
        { param: "username", label: t("filters_search_username_label"), render: mono },
        { param: "command", label: t("filters_search_command_label"), render: mono },
        {
          param: "url",
          label: t("filters_search_url_label"),
          render: (v) => <span className="font-mono break-all">{v}</span>,
        },
        ...period,
        {
          param: "stage",
          label: t("filters_outcome_label"),
          render: (v) => {
            const stage = parseStage(v)
            return <span>{stage ? STAGE_META[stage].label : v}</span>
          },
        },
        tagChip,
        countryChip,
        networkChip,
        { param: "technique", label: t("filters_technique_label"), render: mono },
        { param: "campaign_id", label: t("filters_campaign_label"), render: (v) => <CampaignName id={v} /> },
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
