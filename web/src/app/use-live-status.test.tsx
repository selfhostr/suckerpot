import { act, render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import type { LiveClient, LiveFeedState } from "@/lib/live-client"
import { LiveFeedContext } from "./use-live-feed"
import { useLiveStatus } from "./use-live-status"

function fakeClient(initial: LiveFeedState) {
  let state = initial
  const listeners = new Set<() => void>()
  const client = {
    subscribe: (l: () => void) => {
      listeners.add(l)
      return () => listeners.delete(l)
    },
    getSnapshot: () => state,
  } as unknown as LiveClient
  return {
    client,
    set(patch: Partial<LiveFeedState>) {
      state = { ...state, ...patch }
      listeners.forEach((l) => l())
    },
  }
}

const BASE: LiveFeedState = {
  status: "live",
  transport: "websocket",
  events: [],
  stats: null,
  dropped: 0,
}

describe("useLiveStatus", () => {
  it("re-renders on status and transport changes only, not on every event", () => {
    const feed = fakeClient(BASE)
    let renders = 0
    function Probe() {
      renders++
      const { status, detail } = useLiveStatus()
      return <p>{`${status}:${detail ?? "-"}`}</p>
    }
    render(
      <LiveFeedContext value={feed.client}>
        <Probe />
      </LiveFeedContext>,
    )
    expect(screen.getByText("live:-")).toBeInTheDocument()
    const first = renders

    act(() => feed.set({ events: [{ id: 1 } as never], dropped: 2 }))
    act(() => feed.set({ events: [{ id: 2 } as never, { id: 1 } as never] }))
    expect(renders).toBe(first)

    act(() => feed.set({ transport: "polling" }))
    expect(screen.getByText("live:Polling")).toBeInTheDocument()
    act(() => feed.set({ status: "offline" }))
    expect(screen.getByText("offline:-")).toBeInTheDocument()
  })
})
