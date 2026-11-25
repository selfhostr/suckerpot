import { useSyncExternalStore } from "react"
import type { LiveStatus } from "@/components/live-indicator"
import { useLiveClient } from "./use-live-feed"

/**
 * Connection status for the shell. It reads only the status and the transport of the shared live
 * feed, so the shell does not re-render for every event that arrives.
 */
export function useLiveStatus(): { status: LiveStatus; detail: string | undefined } {
  const client = useLiveClient()
  const status = useSyncExternalStore(
    client.subscribe,
    () => client.getSnapshot().status,
    () => client.getSnapshot().status,
  )
  const polling = useSyncExternalStore(
    client.subscribe,
    () => client.getSnapshot().transport === "polling",
    () => client.getSnapshot().transport === "polling",
  )
  return { status, detail: status === "live" && polling ? "Polling" : undefined }
}
