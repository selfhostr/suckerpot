import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router"
import { describe, expect, it, vi } from "vitest"
import { IpMaskProvider } from "@/app/ip-mask"
import { CampaignName } from "@/components/campaigns/campaign-name"
import { CampaignChip } from "@/components/campaigns/campaign-chip"
import { CampaignRow } from "@/components/campaigns/campaign-row"
import { ExcerptBlock } from "@/components/campaigns/excerpt-block"
import { StageTrail } from "@/components/campaigns/stage-trail"
import { TechniqueChips } from "@/components/campaigns/technique-chips"
import { TechniqueTable } from "@/components/techniques/technique-table"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { Campaign, Matrix, StoryStage } from "@/lib/campaigns"

const campaign: Campaign = {
  id: 3,
  name: "Mirai-style loader over Telnet #3",
  status: "active",
  merged_into: null,
  first_seen: "2026-10-20T10:00:00Z",
  last_seen: "2026-10-24T10:00:00Z",
  sessions: 87,
  sources: 23,
  countries: ["FR", "DE"],
  asns: [64496, 64497],
  sensors: ["telnet", "ssh"],
  techniques: ["T1110", "T1105"],
  stages: ["access", "tool_transfer"],
  tags: ["mirai"],
  families: ["mirai"],
  severity: "severe",
  rep_session_id: "s1",
  demo: false,
}

function wrap(ui: React.ReactNode, client = new QueryClient()) {
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <IpMaskProvider>
          <TooltipProvider>{ui}</TooltipProvider>
        </IpMaskProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe("StageTrail", () => {
  it("says which stages were seen, without relying on colour", () => {
    wrap(<StageTrail stages={["access", "tool_transfer"]} />)
    const list = screen.getByRole("list", { name: /Stages: Getting in → Bringing tools/ })
    expect(list).toBeInTheDocument()
    expect(screen.getByText("Getting in (seen)")).toBeInTheDocument()
    expect(screen.getByText("Looking around (not seen)")).toBeInTheDocument()
  })
})

describe("CampaignRow", () => {
  it("opens the campaign and tells it in one line", () => {
    wrap(<CampaignRow campaign={campaign} />)
    const link = screen.getByRole("link", {
      name: "Mirai-style loader over Telnet #3: 87 sessions from 23 addresses in 2 countries",
    })
    expect(link).toHaveAttribute("href", "/campaigns/3")
    expect(screen.getByText("Active")).toBeInTheDocument()
    expect(screen.getByText("Telnet")).toBeInTheDocument()
  })

  it("shows a quiet campaign as quiet", () => {
    wrap(<CampaignRow campaign={{ ...campaign, status: "quiet" }} />)
    expect(screen.getByText("Quiet")).toBeInTheDocument()
  })
})

const stages: StoryStage[] = [
  {
    stage: "access",
    label: "Getting in",
    summary: "They guessed passwords.",
    techniques: [
      {
        id: "T1110",
        name: "Brute Force",
        url: "https://attack.example/T1110/",
        plain: "guessed passwords",
      },
    ],
  },
  {
    stage: "tool_transfer",
    label: "Bringing tools",
    summary: "They downloaded a tool onto the machine.",
    techniques: [
      {
        id: "T1105",
        name: "Ingress Tool Transfer",
        url: "https://attack.example/T1105/",
        plain: "downloaded a tool",
      },
    ],
  },
]

describe("TechniqueChips", () => {
  it("links a technique to this campaign's sessions and to ATT&CK in a new tab", () => {
    wrap(<TechniqueChips stages={stages} campaignId={3} />)
    expect(screen.getByRole("link", { name: /^Brute Force, T1110/ })).toHaveAttribute(
      "href",
      "/attacks?campaign_id=3&technique=T1110",
    )
    const external = screen.getByRole("link", { name: /Read about T1110 .*\(opens in a new tab\)/ })
    expect(external).toHaveAttribute("target", "_blank")
    expect(external).toHaveAttribute("rel", expect.stringContaining("noopener"))
  })
})

describe("ExcerptBlock", () => {
  it("renders attacker text as text, never as markup or links", () => {
    wrap(
      <ExcerptBlock
        excerpt={{
          session_id: "s1",
          sensor: "ssh",
          lines: [
            { kind: "command", text: "<img src=x onerror=alert(1)>" },
            { kind: "download", text: "http://203.0.113.66/x86" },
          ],
        }}
      />,
    )
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument()
    expect(document.querySelector("img")).toBeNull()
    expect(screen.queryAllByRole("link")).toHaveLength(0)
    expect(screen.getByText("http://203.0.113.66/x86")).toBeInTheDocument()
  })
})

const matrix: Matrix = {
  since: "2026-10-22",
  until: "2026-10-24",
  days: ["2026-10-22", "2026-10-23", "2026-10-24"],
  stages: [],
  rows: [
    {
      id: "T1110",
      name: "Brute Force",
      tactic: "credential-access",
      stage: "access",
      url: "https://attack.example/T1110/",
      plain: "guessed passwords",
      total_sessions: 15,
      total_events: 60,
      counts: [4, 6, 5],
    },
    {
      id: "T1105",
      name: "Ingress Tool Transfer",
      tactic: "command-and-control",
      stage: "tool_transfer",
      url: "https://attack.example/T1105/",
      plain: "downloaded a tool",
      total_sessions: 3,
      total_events: 12,
      counts: [0, 1, 2],
    },
  ],
}

describe("TechniqueTable", () => {
  it("lists techniques with the most sessions first and links each to its sessions", () => {
    wrap(<TechniqueTable matrix={matrix} linkSuffix="&sensor=ssh" />)
    const link = screen.getByRole("link", { name: /Brute Force/ })
    expect(link).toHaveAttribute("href", "/attacks?technique=T1110&sensor=ssh")
    const names = screen.getAllByRole("listitem").map((li) => li.textContent ?? "")
    expect(names.findIndex((t) => t.includes("Brute Force"))).toBeLessThan(
      names.findIndex((t) => t.includes("Ingress Tool Transfer")),
    )
  })
})

describe("CampaignChip", () => {
  it("shows the campaign a session is part of and links to it", async () => {
    const client = new QueryClient()
    client.setQueryData(["campaigns", "detail", 3], campaign)
    wrap(<CampaignChip id={3} />, client)
    const link = await screen.findByRole("link", { name: /Part of campaign/ })
    expect(link).toHaveAttribute("href", "/campaigns/3")
    expect(link).toHaveTextContent("Mirai-style loader over Telnet #3")
  })

  it("follows a merged campaign to the one that absorbed it", async () => {
    const client = new QueryClient()
    client.setQueryData(["campaigns", "detail", 11], {
      ...campaign,
      id: 11,
      status: "merged",
      merged_into: 3,
    })
    client.setQueryData(["campaigns", "detail", 3], campaign)
    wrap(<CampaignChip id={11} />, client)
    const link = await screen.findByRole("link", { name: /Part of campaign/ })
    expect(link).toHaveAttribute("href", "/campaigns/3")
  })

  it("stays out of the way when the campaign cannot be read", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(JSON.stringify({ detail: "campaign not found" }), { status: 404 }),
      )
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    wrap(<CampaignChip id={999} />, client)
    await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalled())
    await vi.waitFor(() => expect(screen.queryByRole("link")).toBeNull())
    fetchSpy.mockRestore()
  })
})

describe("CampaignName", () => {
  it("shows the campaign name in a filter chip, the id until it is known", async () => {
    const client = new QueryClient()
    wrap(<CampaignName id="3" />, client)
    expect(screen.getByText("#3")).toBeInTheDocument()
    client.setQueryData(["campaigns", "detail", 3], campaign)
    expect(await screen.findByText("Mirai-style loader over Telnet #3")).toBeInTheDocument()
  })

  it("never fetches for something that is not an id", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch")
    wrap(<CampaignName id="abc" />)
    expect(screen.getByText("#abc")).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })
})
