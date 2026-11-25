import { useQuery } from "@tanstack/react-query"
import { API_BASE } from "@/lib/api"

/** Public, country-level home position served by `GET /settings/site`. */
export interface SiteHome {
  lat: number
  lon: number
  /** Country name served by the API; absent when the operator set none. */
  label?: string | undefined
}

async function fetchSite(): Promise<SiteHome> {
  const res = await fetch(`${API_BASE}/settings/site`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
  if (!res.ok) throw new Error(`site settings: ${res.status}`)
  const body = (await res.json()) as { home?: Partial<SiteHome> }
  const { lat, lon, label } = body.home ?? {}
  if (typeof lat !== "number" || typeof lon !== "number") throw new Error("site settings: bad home")
  return { lat, lon, label: typeof label === "string" && label ? label : undefined }
}

/** Where the arcs land. Never refetched: it only changes with the server configuration. */
export function useSiteHome() {
  return useQuery({
    queryKey: ["settings", "site"],
    queryFn: fetchSite,
    staleTime: Infinity,
    retry: 1,
  })
}
