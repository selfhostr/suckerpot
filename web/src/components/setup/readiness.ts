import { useQuery } from "@tanstack/react-query"
import { alertKeys, alertsApi } from "@/lib/alerts"
import { abuseApi, abuseKeys } from "@/lib/abuse"
import { networkApi, networkKeys } from "@/lib/network"
import { vpnApi, vpnKeys } from "@/lib/vpn"

/**
 * Which optional steps are already satisfied by what the server knows. They read the same
 * queries as the step bodies, so nothing is fetched twice. Unknown (still loading) counts as not
 * done, which only means the button says "Skip for now" a moment longer.
 */
export function useStepReadiness(): Record<string, boolean> {
  const vpn = useQuery({ queryKey: vpnKeys.status, queryFn: vpnApi.status })
  const terms = useQuery({ queryKey: abuseKeys.terms(false), queryFn: () => abuseApi.terms(false) })
  const settings = useQuery({ queryKey: abuseKeys.settings, queryFn: abuseApi.settings })
  const channels = useQuery({ queryKey: alertKeys.channels, queryFn: alertsApi.channels })
  const network = useQuery({
    queryKey: networkKeys.status,
    queryFn: networkApi.status,
    retry: false,
  })
  return {
    vpn: vpn.data?.gate.state === "open",
    self: (terms.data ?? []).some((t) => t.confirmed),
    // A contact that blocks every report does not count as set up.
    reporting:
      !!settings.data?.reply_contact?.trim() &&
      Object.keys(settings.data.field_issues ?? {}).length === 0,
    alerts: (channels.data ?? []).length > 0,
    network: network.data?.state === "member" || network.data?.state === "enrolling",
  }
}
