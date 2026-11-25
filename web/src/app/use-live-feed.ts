import { createContext, use, useSyncExternalStore } from "react"
import type { LiveClient, LiveFeedState } from "@/lib/live-client"

export const LiveFeedContext = createContext<LiveClient | null>(null)

/** The shared live client, for hooks that subscribe to one slice of its state. */
export function useLiveClient(): LiveClient {
  const client = use(LiveFeedContext)
  if (!client) throw new Error("useLiveFeed needs <LiveFeedProvider>")
  return client
}

/** Status, events (newest first), stats and transport of the shared live feed. */
export function useLiveFeed(): LiveFeedState {
  const client = useLiveClient()
  return useSyncExternalStore(client.subscribe, client.getSnapshot, client.getSnapshot)
}
