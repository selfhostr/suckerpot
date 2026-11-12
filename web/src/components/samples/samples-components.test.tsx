import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"
import { describe, expect, it } from "vitest"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { SampleItem } from "@/lib/samples"
import { SampleRow } from "./sample-row"
import { FetchStatusChip } from "./fetch-status-chip"
import { ChainSteps } from "./chain-steps"
import { StringsList } from "./strings-list"

describe("FetchStatusChip", () => {
  it("shows a word, not just a colour", () => {
    render(<FetchStatusChip status="refused" />)
    expect(screen.getByText("Refused")).toBeInTheDocument()
  })
  it("names TFTP", () => {
    render(<FetchStatusChip status="unsupported" url="tftp://192.0.2.4/a" />)
    expect(screen.getByText("Not fetched (TFTP)")).toBeInTheDocument()
  })
})

describe("ChainSteps", () => {
  it("links the steps to their views and marks the current file", () => {
    const sha = "b".repeat(64)
    render(
      <MemoryRouter>
        <ChainSteps
          current={sha}
          chain={{
            nodes: [
              { id: "s", kind: "session", label: "S1", session_id: "S1" },
              { id: "f", kind: "sample", label: "bbbb", sha256: sha },
            ],
            edges: [{ from: "s", to: "f" }],
          }}
        />
      </MemoryRouter>,
    )
    expect(screen.getByRole("link", { name: "S1" })).toHaveAttribute("href", "/attacks/S1")
    expect(screen.getByText(/this file/)).toBeInTheDocument()
  })
})

describe("ChainSteps web content", () => {
  it("names a web page instead of showing the raw kind", () => {
    const sha = "d".repeat(64)
    render(
      <MemoryRouter>
        <ChainSteps
          current={sha}
          chain={{
            nodes: [{ id: "f", kind: "sample", label: "dddd", sha256: sha, family: "html" }],
            edges: [],
          }}
        />
      </MemoryRouter>,
    )
    expect(screen.getByText("Web page")).toBeInTheDocument()
    expect(screen.queryByText("html")).not.toBeInTheDocument()
  })
})

describe("StringsList", () => {
  it("is a focusable list", async () => {
    render(
      <TooltipProvider>
        <StringsList strings={["/bin/sh", "wget"]} />
      </TooltipProvider>,
    )
    const list = screen.getByRole("list", { name: "Strings found in the file" })
    await userEvent.tab()
    expect(list).toHaveFocus()
  })
})

describe("SampleRow origin badge", () => {
  const base: SampleItem = {
    sha256: "c".repeat(64),
    kind: "ELF",
    arch: "x86_64",
    bits: 64,
    family: null,
    severity: "notice",
    size: 1024,
    sources: 1,
    sessions: 0,
    first_seen: "2026-11-01T10:00:00Z",
    last_seen: "2026-11-01T10:00:00Z",
    yara: [],
    stored: true,
    analysis_status: "done",
    origin: "local",
  }
  const renderRow = (origin: SampleItem["origin"]) =>
    render(
      <TooltipProvider>
        <MemoryRouter>
          <SampleRow item={{ ...base, origin }} />
        </MemoryRouter>
      </TooltipProvider>,
    )
  it("flags a network check with a plain-English explanation", () => {
    renderRow("network_verify")
    expect(screen.getByText(/Network check · not seen here/)).toBeInTheDocument()
    expect(screen.getByText(/did not attack this node/)).toBeInTheDocument()
  })
  it("shows nothing for a local sample", () => {
    renderRow("local")
    expect(screen.queryByText(/Network check/)).not.toBeInTheDocument()
  })
})

describe("SampleRow web content", () => {
  const web: SampleItem = {
    sha256: "e".repeat(64),
    kind: "html",
    arch: null,
    bits: null,
    family: null,
    severity: "info",
    size: 2048,
    sources: 1,
    sessions: 0,
    first_seen: "2026-11-01T10:00:00Z",
    last_seen: "2026-11-01T10:00:00Z",
    yara: [],
    stored: true,
    analysis_status: "done",
    origin: "local",
  }
  const renderRow = (item: SampleItem) =>
    render(
      <TooltipProvider>
        <MemoryRouter>
          <SampleRow item={item} />
        </MemoryRouter>
      </TooltipProvider>,
    )
  it("names a plain web page once, not Unknown and the raw kind", () => {
    renderRow(web)
    expect(screen.getAllByText("Web page")).toHaveLength(1)
    expect(screen.queryByText("Unknown")).not.toBeInTheDocument()
    expect(screen.queryByText("html")).not.toBeInTheDocument()
    expect(
      screen.getByRole("link", { name: /^Web page, 2 KB, hash eeeeeeeeeeee/ }),
    ).toBeInTheDocument()
  })
  it("keeps the family and adds the kind when a rule matched the page", () => {
    renderRow({ ...web, family: "shell-dropper", severity: "severe" })
    expect(screen.getByRole("link", { name: "shell-dropper" })).toBeInTheDocument()
    expect(screen.getByText("Web page")).toBeInTheDocument()
  })
  it("shows the label of a stylesheet, an image and a script", () => {
    for (const [kind, label] of [
      ["css", "Stylesheet"],
      ["svg", "Image (SVG)"],
      ["javascript", "Script (web)"],
    ] as const) {
      const { unmount } = renderRow({ ...web, kind })
      expect(screen.getByText(label)).toBeInTheDocument()
      unmount()
    }
  })
})
