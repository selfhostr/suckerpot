/* eslint-disable react-refresh/only-export-components -- a styleguide section exports its registry entry next to its component. */
import { useState } from "react"
import { ScannerBadge } from "@/components/scanner-badge"
import { ScannerToggle } from "@/components/scanner-toggle"
import { SearchTrigger } from "@/components/search/search-palette"
import { Term } from "@/components/term"
import { HourlyActivity } from "@/components/charts/hourly-activity"
import { TodoList } from "@/components/today/todo-list"
import { Button } from "@/components/ui/button"
import { TERM_IDS } from "@/lib/glossary"
import type { TimelineBucket } from "@/lib/story"
import type { TodayCardData } from "@/lib/today"
import { Section, Specimen } from "./parts"
import type { FeatureSection } from "./registry"

const TODO: TodayCardData[] = [
  {
    id: "forms",
    sentence: "1 report to submit by web form, for 1 provider.",
    items: [],
    action: { label: "Open the form queue", to: "/abuse?status=forms" },
    empty: false,
  },
  {
    id: "act",
    sentence: "2 servers handed out malware today. Block them before a real machine fetches it.",
    items: [],
    action: { label: "Open the blocklists", to: "/defend/blocklists" },
    empty: false,
  },
  {
    id: "exposure",
    sentence: "No service inventory yet, so there is no exposure to report.",
    items: [],
    action: { label: "Open your exposure", to: "/defend/exposure" },
    empty: true,
  },
]

const QUIET: TodayCardData[] = [
  {
    id: "act",
    sentence: "Nothing urgent today: no malware downloads and no exploit payloads.",
    items: [],
    action: { label: "Open the blocklists", to: "/defend/blocklists" },
    empty: true,
  },
  {
    id: "campaigns",
    sentence: "No new campaign in the last 24 hours.",
    items: [],
    action: { label: "See all campaigns", to: "/campaigns" },
    empty: true,
  },
]

/** A fixed day: a calm night, a busy evening and one spike, on four doors. */
const HOUR = 3_600_000
const DAY: TimelineBucket[] = Array.from({ length: 24 }, (_, i) => {
  const sessions = Math.round(
    120 + 90 * Math.sin((i / 24) * Math.PI * 2 - 1) + (i === 19 ? 260 : 0),
  )
  const ssh = Math.round(sessions * 0.5)
  const web = Math.round(sessions * 0.2)
  const redis = Math.round(sessions * 0.12)
  return {
    start: new Date(Date.UTC(2026, 0, 1) + i * HOUR).toISOString(),
    sessions,
    by_door: { ssh, web, redis, rdp: sessions - ssh - web - redis },
    by_stage: {},
    severe: 0,
  }
})

function Motion() {
  const [run, setRun] = useState(0)
  return (
    <Specimen label="animate-card-in · motion-stagger · animate-page-in" className="lg:col-span-2">
      <div className="flex w-full flex-col gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="outline" size="sm" onClick={() => setRun((n) => n + 1)}>
            Replay
          </Button>
          <p className="text-xs text-fg-muted">
            320 ms, 8 px of travel, 60 ms between cards. Pages fade in over 200 ms with 4 px. Off
            under reduced motion, with <code>?motion=off</code>, and in screenshots.
          </p>
        </div>
        <div key={run} className="grid grid-cols-3 gap-3">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              style={{ "--motion-i": i } as React.CSSProperties}
              className="motion-stagger animate-card-in rounded-lg border bg-surface p-4 text-xs text-fg-muted"
            >
              Card {i + 1}
            </div>
          ))}
        </div>
      </div>
    </Specimen>
  )
}

function TodayStyleguide() {
  return (
    <Section
      id="today"
      title="Today, search and glossary"
      description="The to-do card and the hourly chart of the home page, the header search, glossary terms, the research-scanner switch and the entrance motion."
    >
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Specimen label="TodoList · the three most pressing items, then a quiet day">
          <div className="grid w-full gap-4 sm:grid-cols-2">
            <TodoList cards={TODO} />
            <TodoList cards={QUIET} />
          </div>
        </Specimen>

        <Specimen label="HourlyActivity · visits per hour, stacked by family">
          <HourlyActivity timeline={DAY} className="w-full" plotClassName="h-36 flex-none" />
        </Specimen>

        <Specimen label="Term: hover, tap, or press Enter">
          <p className="text-base text-fg">
            A <Term id="campaign">campaign</Term> reuses one script; its <Term id="indicator" />s
            can go on a <Term id="blocklist" />. Check the <Term id="asn" /> before you block a
            whole network.
          </p>
        </Specimen>

        <Specimen label="Every glossary term">
          <ul className="flex flex-wrap gap-x-4 gap-y-2 text-sm">
            {TERM_IDS.map((id) => (
              <li key={id}>
                <Term id={id} />
              </li>
            ))}
          </ul>
        </Specimen>

        <Specimen label="ScannerBadge">
          <ScannerBadge name="Atlas Census" />
          <ScannerBadge short />
        </Specimen>

        <Specimen label="ScannerToggle · inline (desktop header) and stacked (phone drawer)">
          <ScannerToggle inline />
          <ScannerToggle className="w-60" />
        </Specimen>

        <Specimen label="SearchTrigger (header) · Ctrl K or Cmd K opens the palette">
          <SearchTrigger className="max-w-md" />
          <SearchTrigger compact />
        </Specimen>

        <Motion />
      </div>
    </Section>
  )
}

export const section: FeatureSection = {
  id: "today",
  label: "Today",
  order: 20,
  Component: TodayStyleguide,
}
